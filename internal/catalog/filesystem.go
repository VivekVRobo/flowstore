package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"flowstore/internal/crypto"
	"flowstore/internal/object"
)

var (
	ErrFileNotFound = errors.New("file not found in catalog")
)

// FileEntry represents a file in the private encrypted catalog.
type FileEntry struct {
	Path          string                `json:"path"`
	Size          uint64                `json:"size"`
	PlainHash     [32]byte              `json:"plain_hash"`
	CreatedAt     time.Time             `json:"created_at"`
	Manifest      *object.Manifest      `json:"manifest,omitempty"`
	PagedManifest *object.PagedManifest `json:"paged_manifest,omitempty"`
}

// Catalog represents the private virtual filesystem structure.
type Catalog struct {
	OwnerID   string               `json:"owner_id"`
	Version   uint64               `json:"version"`
	UpdatedAt time.Time            `json:"updated_at"`
	Files     map[string]FileEntry `json:"files"`
}

const encryptedCatalogFormatVersion = 1

// EncryptedCatalogFile is the local encrypted catalog envelope. The owner ID
// and catalog version are authenticated as part of the ciphertext AAD.
type EncryptedCatalogFile struct {
	FormatVersion  uint8  `json:"format_version"`
	OwnerID        string `json:"owner_id"`
	CatalogVersion uint64 `json:"catalog_version"`
	Ciphertext     []byte `json:"ciphertext"`
}

// NewCatalog creates an empty virtual filesystem catalog.
func NewCatalog(ownerID string) *Catalog {
	return &Catalog{
		OwnerID:   ownerID,
		Version:   1,
		UpdatedAt: time.Now().UTC(),
		Files:     make(map[string]FileEntry),
	}
}

// AddFile registers an ingested file manifest in the catalog.
func (c *Catalog) AddFile(m *object.Manifest) {
	c.Files[m.Path] = FileEntry{
		Path:      m.Path,
		Size:      m.TotalSize,
		PlainHash: m.PlainHash,
		CreatedAt: m.CreatedAt,
		Manifest:  m,
	}
	c.Version++
	c.UpdatedAt = time.Now().UTC()
}

// AddPagedFile registers an ingested file with a page-bounded chunk manifest.
func (c *Catalog) AddPagedFile(m *object.PagedManifest) error {
	if err := object.ValidatePagedManifest(m); err != nil {
		return err
	}
	h := m.Header
	c.Files[h.Path] = FileEntry{
		Path:          h.Path,
		Size:          h.TotalSize,
		PlainHash:     h.PlainHash,
		CreatedAt:     h.CreatedAt,
		PagedManifest: m,
	}
	c.Version++
	c.UpdatedAt = time.Now().UTC()
	return nil
}

// GetFile retrieves a file entry by its logical path.
func (c *Catalog) GetFile(path string) (*FileEntry, error) {
	entry, ok := c.Files[path]
	if !ok {
		return nil, ErrFileNotFound
	}
	return &entry, nil
}

// ListFiles returns sorted list of all file paths in the catalog.
func (c *Catalog) ListFiles() []string {
	var paths []string
	for p := range c.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// Encrypt serializes and encrypts the catalog using the 256-bit CatalogKey.
func (c *Catalog) Encrypt(catalogKey []byte) ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal catalog: %w", err)
	}

	aad := []byte(fmt.Sprintf("flowstore:catalog:v%d:%s", c.Version, c.OwnerID))
	return crypto.Encrypt(data, catalogKey, aad)
}

// MarshalEncryptedCatalog encodes a catalog for protected local persistence.
func MarshalEncryptedCatalog(c *Catalog, catalogKey []byte) ([]byte, error) {
	ciphertext, err := c.Encrypt(catalogKey)
	if err != nil {
		return nil, err
	}
	envelope := EncryptedCatalogFile{
		FormatVersion:  encryptedCatalogFormatVersion,
		OwnerID:        c.OwnerID,
		CatalogVersion: c.Version,
		Ciphertext:     ciphertext,
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encrypted catalog envelope: %w", err)
	}
	return data, nil
}

// UnmarshalCatalog reads an encrypted catalog envelope or a legacy plaintext
// catalog. The bool result is true only for the legacy plaintext format.
func UnmarshalCatalog(data, catalogKey []byte) (*Catalog, bool, error) {
	var envelope EncryptedCatalogFile
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.FormatVersion != 0 {
		if envelope.FormatVersion != encryptedCatalogFormatVersion {
			return nil, false, fmt.Errorf("unsupported encrypted catalog format version %d", envelope.FormatVersion)
		}
		if envelope.OwnerID == "" || envelope.CatalogVersion == 0 || len(envelope.Ciphertext) == 0 {
			return nil, false, errors.New("encrypted catalog envelope is incomplete")
		}
		catalog, err := DecryptCatalog(envelope.Ciphertext, catalogKey, envelope.OwnerID, envelope.CatalogVersion)
		if err != nil {
			return nil, false, err
		}
		if catalog.OwnerID != envelope.OwnerID || catalog.Version != envelope.CatalogVersion {
			return nil, false, errors.New("decrypted catalog metadata does not match its envelope")
		}
		return catalog, false, nil
	}

	var legacy Catalog
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, false, fmt.Errorf("failed to parse local catalog: %w", err)
	}
	if legacy.OwnerID == "" || legacy.Version == 0 {
		return nil, false, errors.New("legacy catalog is missing owner ID or version")
	}
	if legacy.Files == nil {
		legacy.Files = make(map[string]FileEntry)
	}
	return &legacy, true, nil
}

// DecryptCatalog decrypts and parses an encrypted catalog using CatalogKey.
func DecryptCatalog(ciphertext []byte, catalogKey []byte, ownerID string, version uint64) (*Catalog, error) {
	aad := []byte(fmt.Sprintf("flowstore:catalog:v%d:%s", version, ownerID))
	plaintext, err := crypto.Decrypt(ciphertext, catalogKey, aad)
	if err != nil {
		// Fallback without version in AAD for version-agnostic lookup
		fallbackAAD := []byte(fmt.Sprintf("flowstore:catalog:%s", ownerID))
		plaintext, err = crypto.Decrypt(ciphertext, catalogKey, fallbackAAD)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt catalog: %w", err)
		}
	}

	var cat Catalog
	if err := json.Unmarshal(plaintext, &cat); err != nil {
		return nil, fmt.Errorf("failed to unmarshal catalog json: %w", err)
	}
	return &cat, nil
}
