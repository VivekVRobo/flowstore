package object

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"flowstore/internal/crypto"
	"lukechampine.com/blake3"
)

// DefaultManifestPageSize bounds per-page ChunkRef metadata. 256 chunks at
// 64 MiB cover 16 GiB per page; multi-TB objects span many pages.
const DefaultManifestPageSize = 256

// MaxManifestPageSize keeps user-selected manifest metadata pages bounded.
const MaxManifestPageSize = 4096

const encryptedManifestPageFormatVersion = 1

// ManifestPage holds a bounded slice of ChunkRefs for one object.
type ManifestPage struct {
	ObjectID  string     `json:"object_id"`
	PageIndex uint32     `json:"page_index"`
	PageCount uint32     `json:"page_count"`
	ChunkSize uint32     `json:"chunk_size"`
	Chunks    []ChunkRef `json:"chunks"`
}

// PagedManifestHeader describes a multi-page object without holding all refs.
type PagedManifestHeader struct {
	ObjectID   string    `json:"object_id"`
	Path       string    `json:"path"`
	TotalSize  uint64    `json:"total_size"`
	PlainHash  [32]byte  `json:"plain_hash"`
	CreatedAt  time.Time `json:"created_at"`
	ChunkSize  uint32    `json:"chunk_size"`
	ChunkCount uint32    `json:"chunk_count"`
	PageSize   uint32    `json:"page_size"`
	PageCount  uint32    `json:"page_count"`
}

// PagedManifest is the compact object descriptor stored in local manifests
// and catalog entries. Each page's encrypted bytes are themselves stored as a
// regular FlowStore object; only their small manifests are kept here.
type PagedManifest struct {
	Header        PagedManifestHeader `json:"header"`
	PageManifests []*Manifest         `json:"page_manifests"`
}

const (
	pagedManifestKind         = "flowstore-paged-manifest"
	encryptedPagedManifestVer = 1
)

// EncryptedPagedManifestFile protects the paged descriptor at rest. Kind
// distinguishes this envelope from the legacy inline manifest envelope.
type EncryptedPagedManifestFile struct {
	Kind          string `json:"kind"`
	FormatVersion uint8  `json:"format_version"`
	ObjectID      string `json:"object_id"`
	Ciphertext    []byte `json:"ciphertext"`
}

func pagedManifestAAD(objectID string) []byte {
	return []byte("flowstore-paged-manifest-v1:" + objectID)
}

// IsPagedManifestEnvelope reports whether data uses the paged descriptor
// envelope. It allows callers to retain compatibility with inline manifests.
func IsPagedManifestEnvelope(data []byte) bool {
	var marker struct {
		Kind string `json:"kind"`
	}
	return json.Unmarshal(data, &marker) == nil && marker.Kind == pagedManifestKind
}

// ValidatePagedManifest checks the descriptor shape before it is persisted or
// used for recovery.
func ValidatePagedManifest(manifest *PagedManifest) error {
	if manifest == nil {
		return errors.New("paged manifest is nil")
	}
	h := manifest.Header
	if h.ObjectID == "" || h.ChunkSize == 0 || h.PageSize == 0 || h.PageCount == 0 {
		return errors.New("paged manifest header is incomplete")
	}
	if h.PageSize > MaxManifestPageSize {
		return fmt.Errorf("paged manifest page size %d exceeds maximum %d", h.PageSize, MaxManifestPageSize)
	}
	wantPages := uint32((uint64(h.ChunkCount) + uint64(h.PageSize) - 1) / uint64(h.PageSize))
	if wantPages == 0 {
		wantPages = 1
	}
	if h.PageCount != wantPages {
		return fmt.Errorf("paged manifest header declares %d pages, expected %d", h.PageCount, wantPages)
	}
	if uint32(len(manifest.PageManifests)) != h.PageCount {
		return fmt.Errorf("paged manifest has %d page manifests, expected %d", len(manifest.PageManifests), h.PageCount)
	}
	for i, pageManifest := range manifest.PageManifests {
		if pageManifest == nil || pageManifest.ObjectID == "" || pageManifest.ChunkSize == 0 || len(pageManifest.Chunks) == 0 {
			return fmt.Errorf("paged manifest page %d has an incomplete storage manifest", i)
		}
	}
	return nil
}

// MarshalEncryptedPagedManifest encrypts a paged object descriptor using the
// user's CatalogKey. The header and storage references are confidential.
func MarshalEncryptedPagedManifest(manifest *PagedManifest, catalogKey []byte) ([]byte, error) {
	if err := ValidatePagedManifest(manifest); err != nil {
		return nil, err
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal paged manifest: %w", err)
	}
	ciphertext, err := crypto.Encrypt(data, catalogKey, pagedManifestAAD(manifest.Header.ObjectID))
	if err != nil {
		return nil, err
	}
	envelope := EncryptedPagedManifestFile{
		Kind:          pagedManifestKind,
		FormatVersion: encryptedPagedManifestVer,
		ObjectID:      manifest.Header.ObjectID,
		Ciphertext:    ciphertext,
	}
	return json.MarshalIndent(envelope, "", "  ")
}

// UnmarshalEncryptedPagedManifest decrypts and validates a paged descriptor.
func UnmarshalEncryptedPagedManifest(data, catalogKey []byte) (*PagedManifest, error) {
	var envelope EncryptedPagedManifestFile
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse paged manifest envelope: %w", err)
	}
	if envelope.Kind != pagedManifestKind {
		return nil, errors.New("file is not a paged manifest envelope")
	}
	if envelope.FormatVersion != encryptedPagedManifestVer {
		return nil, fmt.Errorf("unsupported paged manifest format version %d", envelope.FormatVersion)
	}
	if envelope.ObjectID == "" || len(envelope.Ciphertext) == 0 {
		return nil, errors.New("paged manifest envelope is incomplete")
	}
	plaintext, err := crypto.Decrypt(envelope.Ciphertext, catalogKey, pagedManifestAAD(envelope.ObjectID))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt paged manifest: %w", err)
	}
	var manifest PagedManifest
	if err := json.Unmarshal(plaintext, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal paged manifest: %w", err)
	}
	if manifest.Header.ObjectID != envelope.ObjectID {
		return nil, errors.New("paged manifest object ID does not match its envelope")
	}
	if err := ValidatePagedManifest(&manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// EncryptedManifestPageFile is the on-disk envelope for one page.
type EncryptedManifestPageFile struct {
	FormatVersion uint8  `json:"format_version"`
	ObjectID      string `json:"object_id"`
	PageIndex     uint32 `json:"page_index"`
	PageCount     uint32 `json:"page_count"`
	Ciphertext    []byte `json:"ciphertext"`
}

func pageAAD(objectID string, pageIndex uint32) []byte {
	return []byte(fmt.Sprintf("flowstore-manifest-page-v1:%s:%d", objectID, pageIndex))
}

// MarshalEncryptedPage encrypts one page with the CatalogKey.
func MarshalEncryptedPage(page *ManifestPage, catalogKey []byte) ([]byte, error) {
	data, err := json.Marshal(page)
	if err != nil {
		return nil, err
	}
	ciphertext, err := crypto.Encrypt(data, catalogKey, pageAAD(page.ObjectID, page.PageIndex))
	if err != nil {
		return nil, err
	}
	envelope := EncryptedManifestPageFile{
		FormatVersion: encryptedManifestPageFormatVersion,
		ObjectID:      page.ObjectID,
		PageIndex:     page.PageIndex,
		PageCount:     page.PageCount,
		Ciphertext:    ciphertext,
	}
	return json.MarshalIndent(envelope, "", "  ")
}

// UnmarshalEncryptedPage decrypts one page envelope.
func UnmarshalEncryptedPage(data, catalogKey []byte) (*ManifestPage, error) {
	var envelope EncryptedManifestPageFile
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	if envelope.FormatVersion != encryptedManifestPageFormatVersion {
		return nil, fmt.Errorf("unsupported manifest page version %d", envelope.FormatVersion)
	}
	plaintext, err := crypto.Decrypt(envelope.Ciphertext, catalogKey, pageAAD(envelope.ObjectID, envelope.PageIndex))
	if err != nil {
		return nil, err
	}
	var page ManifestPage
	if err := json.Unmarshal(plaintext, &page); err != nil {
		return nil, err
	}
	if page.ObjectID != envelope.ObjectID || page.PageIndex != envelope.PageIndex {
		return nil, errors.New("manifest page envelope mismatch")
	}
	return &page, nil
}

// SplitManifest divides a complete manifest into bounded pages plus a header.
func SplitManifest(m *Manifest, pageSize uint32) (*PagedManifestHeader, []*ManifestPage) {
	if pageSize == 0 {
		pageSize = DefaultManifestPageSize
	}
	if pageSize > MaxManifestPageSize {
		pageSize = MaxManifestPageSize
	}
	chunkCount := uint32(len(m.Chunks))
	pageCount := (chunkCount + pageSize - 1) / pageSize
	if pageCount == 0 {
		pageCount = 1
	}
	header := &PagedManifestHeader{
		ObjectID:   m.ObjectID,
		Path:       m.Path,
		TotalSize:  m.TotalSize,
		PlainHash:  m.PlainHash,
		CreatedAt:  m.CreatedAt,
		ChunkSize:  m.ChunkSize,
		ChunkCount: chunkCount,
		PageSize:   pageSize,
		PageCount:  pageCount,
	}
	var pages []*ManifestPage
	for i := uint32(0); i < pageCount; i++ {
		start := i * pageSize
		end := start + pageSize
		if end > chunkCount {
			end = chunkCount
		}
		var chunks []ChunkRef
		if start < chunkCount {
			chunks = append([]ChunkRef(nil), m.Chunks[start:end]...)
		}
		pages = append(pages, &ManifestPage{
			ObjectID:  m.ObjectID,
			PageIndex: i,
			PageCount: pageCount,
			ChunkSize: m.ChunkSize,
			Chunks:    chunks,
		})
	}
	return header, pages
}

// JoinPages reassembles a complete manifest from pages (for small-object compat).
func JoinPages(header *PagedManifestHeader, pages []*ManifestPage) (*Manifest, error) {
	if uint32(len(pages)) != header.PageCount {
		return nil, fmt.Errorf("expected %d pages, got %d", header.PageCount, len(pages))
	}
	var chunks []ChunkRef
	for i, p := range pages {
		if p == nil || p.PageIndex != uint32(i) || p.ObjectID != header.ObjectID {
			return nil, fmt.Errorf("page %d mismatch", i)
		}
		chunks = append(chunks, p.Chunks...)
	}
	if uint32(len(chunks)) != header.ChunkCount {
		return nil, fmt.Errorf("chunk count mismatch: header %d, pages %d", header.ChunkCount, len(chunks))
	}
	return &Manifest{
		ObjectID:  header.ObjectID,
		Path:      header.Path,
		TotalSize: header.TotalSize,
		PlainHash: header.PlainHash,
		CreatedAt: header.CreatedAt,
		ChunkSize: header.ChunkSize,
		Chunks:    chunks,
	}, nil
}

// IngestStreamPaged streams chunks like IngestStream but bounds ChunkRef memory
// to pageSize by encrypting each full page and handing it to pageSink.
// Chunk payloads still go to chunkSink one by one. Pages carry PageIndex and
// ObjectID; the header carries the true PageCount/ChunkCount, so intermediate
// pages are encrypted without knowing the total (PageCount=0 provisional).
func (p *Pipeline) IngestStreamPaged(r io.Reader, logicalPath string, pageSize uint32, chunkSink func(EncodedChunk) error, pageSink func(pageIndex uint32, encryptedPage []byte) error) (*PagedManifestHeader, error) {
	if chunkSink == nil {
		return nil, errors.New("chunk sink is required")
	}
	if pageSize == 0 {
		pageSize = DefaultManifestPageSize
	}
	if pageSize > MaxManifestPageSize {
		return nil, fmt.Errorf("manifest page size %d exceeds maximum %d", pageSize, MaxManifestPageSize)
	}
	objIDBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, objIDBytes); err != nil {
		return nil, fmt.Errorf("failed to generate object ID: %w", err)
	}
	objectID := hex.EncodeToString(objIDBytes)
	createdAt := time.Now().UTC()

	overallHasher := blake3.New(32, nil)
	teeReader := io.TeeReader(r, overallHasher)
	chunkBuf := make([]byte, p.chunkSize)

	var (
		chunkIndex uint32
		totalBytes uint64
		pageChunks []ChunkRef
		pageIndex  uint32
		chunkCount uint32
	)
	flushPage := func() error {
		if pageSink == nil {
			pageChunks = pageChunks[:0]
			pageIndex++
			return nil
		}
		page := &ManifestPage{
			ObjectID:  objectID,
			PageIndex: pageIndex,
			ChunkSize: p.chunkSize,
			Chunks:    append([]ChunkRef(nil), pageChunks...),
		}
		enc, err := p.encryptPage(page)
		if err != nil {
			return err
		}
		if err := pageSink(pageIndex, enc); err != nil {
			return fmt.Errorf("failed storing manifest page %d: %w", pageIndex, err)
		}
		pageChunks = pageChunks[:0]
		pageIndex++
		return nil
	}

	// Manual loop to keep page buffering explicit and bounded.
	for {
		n, err := io.ReadFull(teeReader, chunkBuf)
		if n > 0 {
			totalBytes += uint64(n)
			chunkPlaintext := append([]byte(nil), chunkBuf[:n]...)

			var chunkKey [32]byte
			if _, err := io.ReadFull(rand.Reader, chunkKey[:]); err != nil {
				return nil, fmt.Errorf("failed to generate chunk key: %w", err)
			}
			aad := []byte(fmt.Sprintf("%s:%d", objectID, chunkIndex))
			encryptedChunk, err := crypto.Encrypt(chunkPlaintext, chunkKey[:], aad)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt chunk %d: %w", chunkIndex, err)
			}
			shards, err := p.erasure.Encode(encryptedChunk)
			if err != nil {
				return nil, fmt.Errorf("failed to erasure-code chunk %d: %w", chunkIndex, err)
			}
			var shardRefs []ShardRef
			for i := range shards {
				routingID := crypto.DeriveRoutingID(p.keyring.RoutingKey[:], objIDBytes, chunkIndex, shards[i].Index, p.epoch)
				shardRefs = append(shardRefs, ShardRef{ShardIndex: shards[i].Index, RoutingID: routingID, Checksum: shards[i].Checksum, Size: uint32(len(shards[i].Data))})
			}
			chunkRef := ChunkRef{Index: chunkIndex, ChunkKey: chunkKey, CipherSize: uint64(len(encryptedChunk)), OriginalSize: uint64(n), Shards: shardRefs}
			if err := chunkSink(EncodedChunk{Ref: chunkRef, Shards: shards}); err != nil {
				return nil, fmt.Errorf("failed storing chunk %d: %w", chunkIndex, err)
			}
			pageChunks = append(pageChunks, chunkRef)
			chunkIndex++
			chunkCount++
			if uint32(len(pageChunks)) >= pageSize {
				if err := flushPage(); err != nil {
					return nil, err
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return nil, fmt.Errorf("error reading stream: %w", err)
		}
	}
	if len(pageChunks) > 0 || pageIndex == 0 {
		if err := flushPage(); err != nil {
			return nil, err
		}
	}
	pageCount := pageIndex
	var plainHash [32]byte
	copy(plainHash[:], overallHasher.Sum(nil))
	header := &PagedManifestHeader{
		ObjectID: objectID, Path: logicalPath, TotalSize: totalBytes,
		PlainHash: plainHash, CreatedAt: createdAt,
		ChunkSize: p.chunkSize, ChunkCount: chunkCount,
		PageSize: pageSize, PageCount: pageCount,
	}
	return header, nil
}

func (p *Pipeline) encryptPage(page *ManifestPage) ([]byte, error) {
	data, err := json.Marshal(page)
	if err != nil {
		return nil, err
	}
	ciphertext, err := crypto.Encrypt(data, p.keyring.CatalogKey[:], pageAAD(page.ObjectID, page.PageIndex))
	if err != nil {
		return nil, err
	}
	envelope := EncryptedManifestPageFile{
		FormatVersion: encryptedManifestPageFormatVersion,
		ObjectID:      page.ObjectID,
		PageIndex:     page.PageIndex,
		PageCount:     page.PageCount,
		Ciphertext:    ciphertext,
	}
	return json.MarshalIndent(envelope, "", "  ")
}

// PageLoader loads one decrypted page by index.
type PageLoader func(pageIndex uint32) (*ManifestPage, error)

// ReconstructPaged rebuilds plaintext by streaming pages, bounding ChunkRef
// memory to one page at a time.
func (p *Pipeline) ReconstructPaged(w io.Writer, header *PagedManifestHeader, loader PageLoader, getter ShardGetter) error {
	if header == nil || loader == nil || header.ObjectID == "" || header.PageCount == 0 || header.PageSize == 0 {
		return errors.New("paged reconstruction header or loader is incomplete")
	}
	if header.PageSize > MaxManifestPageSize {
		return fmt.Errorf("paged reconstruction page size %d exceeds maximum %d", header.PageSize, MaxManifestPageSize)
	}
	expectedPages := uint32((uint64(header.ChunkCount) + uint64(header.PageSize) - 1) / uint64(header.PageSize))
	if expectedPages == 0 {
		expectedPages = 1
	}
	if header.PageCount != expectedPages {
		return fmt.Errorf("paged reconstruction header declares %d pages, expected %d", header.PageCount, expectedPages)
	}
	overallHasher := blake3.New(32, nil)
	multiWriter := io.MultiWriter(w, overallHasher)
	var reconstructedChunks uint32
	for i := uint32(0); i < header.PageCount; i++ {
		page, err := loader(i)
		if err != nil {
			return fmt.Errorf("failed loading manifest page %d: %w", i, err)
		}
		if page.ObjectID != header.ObjectID {
			return fmt.Errorf("page %d object mismatch", i)
		}
		if page.PageIndex != i {
			return fmt.Errorf("page %d contains index %d", i, page.PageIndex)
		}
		if page.ChunkSize != header.ChunkSize {
			return fmt.Errorf("page %d has chunk size %d, expected %d", i, page.ChunkSize, header.ChunkSize)
		}
		if page.PageCount != 0 && page.PageCount != header.PageCount {
			return fmt.Errorf("page %d declares %d pages, expected %d", i, page.PageCount, header.PageCount)
		}
		if uint32(len(page.Chunks)) > header.PageSize {
			return fmt.Errorf("page %d exceeds declared page size", i)
		}
		for _, chunkRef := range page.Chunks {
			if chunkRef.Index != reconstructedChunks {
				return fmt.Errorf("page %d contains out-of-order chunk index %d, expected %d", i, chunkRef.Index, reconstructedChunks)
			}
			if err := p.reconstructOneChunk(multiWriter, header.ObjectID, chunkRef, getter); err != nil {
				return fmt.Errorf("failed reconstructing chunk %d: %w", chunkRef.Index, err)
			}
			reconstructedChunks++
		}
	}
	if reconstructedChunks != header.ChunkCount {
		return fmt.Errorf("paged reconstruction restored %d chunks, expected %d", reconstructedChunks, header.ChunkCount)
	}
	if actual := overallHasher.Sum(nil); !equalHash(actual, header.PlainHash[:]) {
		return ErrHashMismatch
	}
	return nil
}

// LoadManifestPage reconstructs and decrypts one metadata page from its stored
// FlowStore object. Only one page's refs are materialized at a time.
func (p *Pipeline) LoadManifestPage(manifest *PagedManifest, pageIndex uint32, getter ShardGetter) (*ManifestPage, error) {
	if manifest == nil || manifest.Header.ObjectID == "" || manifest.Header.PageCount == 0 || manifest.Header.PageSize == 0 {
		return nil, errors.New("paged manifest header is incomplete")
	}
	if uint32(len(manifest.PageManifests)) != manifest.Header.PageCount {
		return nil, fmt.Errorf("paged manifest has %d page manifests, expected %d", len(manifest.PageManifests), manifest.Header.PageCount)
	}
	if pageIndex >= manifest.Header.PageCount {
		return nil, fmt.Errorf("manifest page index %d is out of range", pageIndex)
	}
	pageManifest := manifest.PageManifests[pageIndex]
	if pageManifest == nil || pageManifest.ObjectID == "" || pageManifest.ChunkSize == 0 || len(pageManifest.Chunks) == 0 {
		return nil, fmt.Errorf("paged manifest page %d has an incomplete storage manifest", pageIndex)
	}
	pagePipeline, err := NewPipeline(p.keyring, pageManifest.ChunkSize, 0)
	if err != nil {
		return nil, fmt.Errorf("create page reconstruction pipeline: %w", err)
	}
	var encryptedPage bytes.Buffer
	if err := pagePipeline.Reconstruct(&encryptedPage, pageManifest, getter); err != nil {
		return nil, fmt.Errorf("reconstruct stored manifest page %d: %w", pageIndex, err)
	}
	page, err := UnmarshalEncryptedPage(encryptedPage.Bytes(), p.keyring.CatalogKey[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt manifest page %d: %w", pageIndex, err)
	}
	if page.ObjectID != manifest.Header.ObjectID || page.PageIndex != pageIndex {
		return nil, fmt.Errorf("stored manifest page %d does not match its descriptor", pageIndex)
	}
	return page, nil
}

// ReconstructPagedManifest rebuilds an object from its encrypted metadata pages
// while keeping ChunkRef memory bounded to one page.
func (p *Pipeline) ReconstructPagedManifest(w io.Writer, manifest *PagedManifest, getter ShardGetter) error {
	if err := ValidatePagedManifest(manifest); err != nil {
		return err
	}
	loader := func(pageIndex uint32) (*ManifestPage, error) {
		return p.LoadManifestPage(manifest, pageIndex, getter)
	}
	return p.ReconstructPaged(w, &manifest.Header, loader, getter)
}

// VisitPagedManifestChunks visits a paged object's chunk refs in order without
// collecting the full manifest in memory.
func (p *Pipeline) VisitPagedManifestChunks(manifest *PagedManifest, getter ShardGetter, visit func(ChunkRef) error) error {
	if err := ValidatePagedManifest(manifest); err != nil {
		return err
	}
	if visit == nil {
		return errors.New("chunk visitor is required")
	}
	var visited uint32
	for pageIndex := uint32(0); pageIndex < manifest.Header.PageCount; pageIndex++ {
		page, err := p.LoadManifestPage(manifest, pageIndex, getter)
		if err != nil {
			return err
		}
		if page.ChunkSize != manifest.Header.ChunkSize {
			return fmt.Errorf("page %d has chunk size %d, expected %d", pageIndex, page.ChunkSize, manifest.Header.ChunkSize)
		}
		if page.PageCount != 0 && page.PageCount != manifest.Header.PageCount {
			return fmt.Errorf("page %d declares %d pages, expected %d", pageIndex, page.PageCount, manifest.Header.PageCount)
		}
		if uint32(len(page.Chunks)) > manifest.Header.PageSize {
			return fmt.Errorf("page %d exceeds declared page size", pageIndex)
		}
		for _, chunkRef := range page.Chunks {
			if chunkRef.Index != visited {
				return fmt.Errorf("page %d contains out-of-order chunk index %d, expected %d", pageIndex, chunkRef.Index, visited)
			}
			if err := visit(chunkRef); err != nil {
				return err
			}
			visited++
		}
	}
	if visited != manifest.Header.ChunkCount {
		return fmt.Errorf("paged manifest contains %d chunks, expected %d", visited, manifest.Header.ChunkCount)
	}
	return nil
}

func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
