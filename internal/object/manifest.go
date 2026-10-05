package object

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"flowstore/internal/crypto"
)

// ShardRef records the lookup reference for a specific shard.
type ShardRef struct {
	ShardIndex uint8    `json:"shard_index"`
	RoutingID  string   `json:"routing_id"` // Oblivious DHT lookup key
	Checksum   [32]byte `json:"checksum"`   // BLAKE3 checksum
	Size       uint32   `json:"size"`
}

// ChunkRef records metadata for a 64 MiB (or test-sized) encrypted chunk.
type ChunkRef struct {
	Index        uint32     `json:"index"`
	ChunkKey     [32]byte   `json:"chunk_key"`     // Per-chunk symmetric key
	CipherSize   uint64     `json:"cipher_size"`   // Length of encrypted chunk payload
	OriginalSize uint64     `json:"original_size"` // Length of plaintext chunk
	Shards       []ShardRef `json:"shards"`        // Exactly 10 shards (6 data + 4 parity)
}

// Manifest represents the private metadata structure of an ingested file or object.
type Manifest struct {
	ObjectID  string     `json:"object_id"`
	Path      string     `json:"path"`
	TotalSize uint64     `json:"total_size"`
	PlainHash [32]byte   `json:"plain_hash"` // BLAKE3 hash of complete original file
	CreatedAt time.Time  `json:"created_at"`
	ChunkSize uint32     `json:"chunk_size"`
	Chunks    []ChunkRef `json:"chunks"`
}

const encryptedManifestFormatVersion = 1

// EncryptedManifestFile is the on-disk envelope for an encrypted manifest.
// ObjectID is public routing metadata required to reconstruct the AEAD AAD;
// paths and per-chunk keys remain inside Ciphertext.
type EncryptedManifestFile struct {
	FormatVersion uint8  `json:"format_version"`
	ObjectID      string `json:"object_id"`
	Ciphertext    []byte `json:"ciphertext"`
}

// Encrypt serializes and encrypts the manifest using the user's CatalogKey.
func (m *Manifest) Encrypt(catalogKey []byte) ([]byte, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest: %w", err)
	}

	aad := []byte("flowstore-manifest-v1:" + m.ObjectID)
	return crypto.Encrypt(data, catalogKey, aad)
}

// MarshalEncryptedManifest serializes a manifest into an encrypted JSON
// envelope suitable for atomic local persistence.
func MarshalEncryptedManifest(m *Manifest, catalogKey []byte) ([]byte, error) {
	ciphertext, err := m.Encrypt(catalogKey)
	if err != nil {
		return nil, err
	}
	envelope := EncryptedManifestFile{
		FormatVersion: encryptedManifestFormatVersion,
		ObjectID:      m.ObjectID,
		Ciphertext:    ciphertext,
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encrypted manifest envelope: %w", err)
	}
	return data, nil
}

// UnmarshalManifest reads a new encrypted envelope or a legacy plaintext
// manifest. The bool result is true only for the legacy plaintext format.
func UnmarshalManifest(data, catalogKey []byte) (*Manifest, bool, error) {
	var envelope EncryptedManifestFile
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.FormatVersion != 0 {
		if envelope.FormatVersion != encryptedManifestFormatVersion {
			return nil, false, fmt.Errorf("unsupported encrypted manifest format version %d", envelope.FormatVersion)
		}
		if envelope.ObjectID == "" || len(envelope.Ciphertext) == 0 {
			return nil, false, errors.New("encrypted manifest envelope is missing object ID or ciphertext")
		}
		manifest, err := DecryptManifest(envelope.Ciphertext, catalogKey, envelope.ObjectID)
		if err != nil {
			return nil, false, err
		}
		if manifest.ObjectID != envelope.ObjectID {
			return nil, false, errors.New("encrypted manifest object ID does not match its envelope")
		}
		return manifest, false, nil
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, false, fmt.Errorf("failed to parse manifest file: %w", err)
	}
	if manifest.ObjectID == "" {
		return nil, false, errors.New("manifest is missing object ID")
	}
	return &manifest, true, nil
}

// DecryptManifest decrypts and parses an encrypted manifest using the user's CatalogKey.
func DecryptManifest(ciphertext []byte, catalogKey []byte, objectID string) (*Manifest, error) {
	aad := []byte("flowstore-manifest-v1:" + objectID)
	plaintext, err := crypto.Decrypt(ciphertext, catalogKey, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt manifest: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(plaintext, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest json: %w", err)
	}

	return &m, nil
}
