package object

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"flowstore/internal/crypto"
	"flowstore/internal/erasure"
	"lukechampine.com/blake3"
)

const (
	DefaultChunkSize = 64 * 1024 * 1024 // 64 MiB
)

var (
	ErrHashMismatch = errors.New("reconstructed object failed overall BLAKE3 hash check")
)

// Pipeline encapsulates chunking, encryption, and erasure coding.
type Pipeline struct {
	keyring   *crypto.Keyring
	erasure   *erasure.Engine
	chunkSize uint32
	epoch     uint32
}

// NewPipeline creates a new ingestion and reconstruction pipeline.
func NewPipeline(keyring *crypto.Keyring, chunkSize uint32, epoch uint32) (*Pipeline, error) {
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}
	engine, err := erasure.DefaultEngine()
	if err != nil {
		return nil, err
	}
	return &Pipeline{
		keyring:   keyring,
		erasure:   engine,
		chunkSize: chunkSize,
		epoch:     epoch,
	}, nil
}

// EncodedChunk contains all 10 erasure shards and metadata for a single chunk.
type EncodedChunk struct {
	Ref    ChunkRef
	Shards []erasure.Shard
}

// Ingest processes an input reader into encrypted, erasure-coded chunks and
// collects every encoded chunk in memory. Use IngestStream for large objects.
func (p *Pipeline) Ingest(r io.Reader, logicalPath string) (*Manifest, []EncodedChunk, error) {
	var encodedChunks []EncodedChunk
	manifest, err := p.IngestStream(r, logicalPath, func(chunk EncodedChunk) error {
		encodedChunks = append(encodedChunks, chunk)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return manifest, encodedChunks, nil
}

// IngestStream processes an input reader one chunk at a time and hands each
// encoded chunk to sink before reading the next one. The caller should persist
// the returned manifest only after this method returns successfully. Encoded
// payload memory is bounded by the configured chunk size and the sink's own
// buffers; the returned per-chunk manifest metadata still grows with chunk count.
func (p *Pipeline) IngestStream(r io.Reader, logicalPath string, sink func(EncodedChunk) error) (*Manifest, error) {
	if sink == nil {
		return nil, errors.New("chunk sink is required")
	}
	// Generate random 16-byte object ID
	objIDBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, objIDBytes); err != nil {
		return nil, fmt.Errorf("failed to generate object ID: %w", err)
	}
	objectID := hex.EncodeToString(objIDBytes)

	manifest := &Manifest{
		ObjectID:  objectID,
		Path:      logicalPath,
		CreatedAt: time.Now().UTC(),
		ChunkSize: p.chunkSize,
	}

	overallHasher := blake3.New(32, nil)
	teeReader := io.TeeReader(r, overallHasher)

	chunkBuf := make([]byte, p.chunkSize)
	var chunkIndex uint32
	var totalBytes uint64

	for {
		n, err := io.ReadFull(teeReader, chunkBuf)
		if n > 0 {
			totalBytes += uint64(n)
			chunkPlaintext := chunkBuf[:n]

			// 1. Generate chunk key
			var chunkKey [32]byte
			if _, err := io.ReadFull(rand.Reader, chunkKey[:]); err != nil {
				return nil, fmt.Errorf("failed to generate chunk key: %w", err)
			}

			// 2. Encrypt with XChaCha20-Poly1305
			aad := []byte(fmt.Sprintf("%s:%d", objectID, chunkIndex))
			encryptedChunk, err := crypto.Encrypt(chunkPlaintext, chunkKey[:], aad)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt chunk %d: %w", chunkIndex, err)
			}

			// 3. Erasure-code into 6 data + 4 parity = 10 shards
			shards, err := p.erasure.Encode(encryptedChunk)
			if err != nil {
				return nil, fmt.Errorf("failed to erasure-code chunk %d: %w", chunkIndex, err)
			}

			// 4. Derive oblivious routing ID for each shard
			var shardRefs []ShardRef
			for i := range shards {
				routingID := crypto.DeriveRoutingID(
					p.keyring.RoutingKey[:],
					objIDBytes,
					chunkIndex,
					shards[i].Index,
					p.epoch,
				)
				shardRefs = append(shardRefs, ShardRef{
					ShardIndex: shards[i].Index,
					RoutingID:  routingID,
					Checksum:   shards[i].Checksum,
					Size:       uint32(len(shards[i].Data)),
				})
			}

			chunkRef := ChunkRef{
				Index:        chunkIndex,
				ChunkKey:     chunkKey,
				CipherSize:   uint64(len(encryptedChunk)),
				OriginalSize: uint64(n),
				Shards:       shardRefs,
			}

			encodedChunk := EncodedChunk{
				Ref:    chunkRef,
				Shards: shards,
			}
			if sink != nil {
				if err := sink(encodedChunk); err != nil {
					return nil, fmt.Errorf("failed storing chunk %d: %w", chunkIndex, err)
				}
			}
			manifest.Chunks = append(manifest.Chunks, chunkRef)

			chunkIndex++
		}

		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return nil, fmt.Errorf("error reading stream: %w", err)
		}
	}

	manifest.TotalSize = totalBytes
	copy(manifest.PlainHash[:], overallHasher.Sum(nil))

	return manifest, nil
}

// ShardGetter is a callback function that retrieves a shard by its routing ID.
type ShardGetter func(routingID string) (*erasure.Shard, error)

// Reconstruct retrieves shards, reconstructs missing shards via Reed-Solomon,
// decrypts via XChaCha20-Poly1305, and writes the byte-perfect plaintext to w.
func (p *Pipeline) Reconstruct(w io.Writer, manifest *Manifest, getter ShardGetter) error {
	if _, err := hex.DecodeString(manifest.ObjectID); err != nil {
		return fmt.Errorf("invalid object ID: %w", err)
	}

	overallHasher := blake3.New(32, nil)
	multiWriter := io.MultiWriter(w, overallHasher)

	for _, chunkRef := range manifest.Chunks {
		if err := p.reconstructOneChunk(multiWriter, manifest.ObjectID, chunkRef, getter); err != nil {
			return err
		}
	}

	// Verify whole-file hash
	actualHash := overallHasher.Sum(nil)
	var expectedHash [32]byte
	copy(expectedHash[:], actualHash)
	if expectedHash != manifest.PlainHash {
		return ErrHashMismatch
	}

	return nil
}

func (p *Pipeline) reconstructOneChunk(w io.Writer, objectID string, chunkRef ChunkRef, getter ShardGetter) error {
	// Collect available shards from getter
	var available []erasure.Shard
	for _, sRef := range chunkRef.Shards {
		shard, err := getter(sRef.RoutingID)
		if err == nil && shard != nil {
			available = append(available, *shard)
		}
	}

	if len(available) < p.erasure.DataShards() {
		return fmt.Errorf("chunk %d: %w (got %d, need %d)",
			chunkRef.Index, erasure.ErrInsufficientShards, len(available), p.erasure.DataShards())
	}

	// Reconstruct encrypted chunk
	encryptedChunk, err := p.erasure.Decode(available)
	if err != nil {
		return fmt.Errorf("failed to reconstruct chunk %d: %w", chunkRef.Index, err)
	}

	// Decrypt chunk with XChaCha20-Poly1305
	aad := []byte(fmt.Sprintf("%s:%d", objectID, chunkRef.Index))
	decrypted, err := crypto.Decrypt(encryptedChunk, chunkRef.ChunkKey[:], aad)
	if err != nil {
		return fmt.Errorf("failed to decrypt chunk %d: %w", chunkRef.Index, err)
	}

	if _, err := w.Write(decrypted); err != nil {
		return fmt.Errorf("failed to write decrypted chunk %d: %w", chunkRef.Index, err)
	}
	return nil
}
