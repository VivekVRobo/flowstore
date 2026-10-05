package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
	"lukechampine.com/blake3"
)

const (
	MasterSecretSize = 32 // 256 bits
	KeySize          = 32 // 256 bits for symmetric AEAD keys
)

// Keyring holds all derived operational keys for a FlowStore identity.
type Keyring struct {
	MasterSecret []byte
	IdentityPriv ed25519.PrivateKey
	IdentityPub  ed25519.PublicKey
	CatalogKey   [KeySize]byte
	RoutingKey   [KeySize]byte
	MetadataKey  [KeySize]byte
	WrappingKey  [KeySize]byte
}

// GenerateMasterSecret creates a new cryptographically secure 256-bit secret.
func GenerateMasterSecret() ([]byte, error) {
	secret := make([]byte, MasterSecretSize)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return nil, fmt.Errorf("failed to generate random secret: %w", err)
	}
	return secret, nil
}

// FormatRecoveryCode converts a 32-byte secret into a human-friendly format:
// FLOW-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
func FormatRecoveryCode(secret []byte) string {
	h := strings.ToUpper(hex.EncodeToString(secret))
	var parts []string
	parts = append(parts, "FLOW")
	for i := 0; i < len(h); i += 8 {
		end := i + 8
		if end > len(h) {
			end = len(h)
		}
		parts = append(parts, h[i:end])
	}
	return strings.Join(parts, "-")
}

// ParseRecoveryCode parses a recovery code string back into 32-byte secret.
func ParseRecoveryCode(code string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.TrimSpace(code))
	cleaned = strings.TrimPrefix(cleaned, "FLOW-")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")

	secret, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid hexadecimal characters: %w", err)
	}
	if len(secret) != MasterSecretSize {
		return nil, fmt.Errorf("invalid recovery code length: expected %d bytes, got %d", MasterSecretSize, len(secret))
	}
	return secret, nil
}

// DeriveKeyring deterministically expands a 256-bit master secret into all operational keys using HKDF-SHA256.
func DeriveKeyring(masterSecret []byte) (*Keyring, error) {
	if len(masterSecret) != MasterSecretSize {
		return nil, errors.New("master secret must be exactly 32 bytes (256 bits)")
	}

	kr := &Keyring{
		MasterSecret: append([]byte(nil), masterSecret...),
	}

	salt := []byte("flowstore-v1-hkdf-salt")

	// 1. Identity Key Seed (32 bytes)
	idSeed := make([]byte, 32)
	idReader := hkdf.New(sha256.New, masterSecret, salt, []byte("flowstore-identity-seed-v1"))
	if _, err := io.ReadFull(idReader, idSeed); err != nil {
		return nil, fmt.Errorf("failed to derive identity seed: %w", err)
	}
	kr.IdentityPriv = ed25519.NewKeyFromSeed(idSeed)
	kr.IdentityPub = kr.IdentityPriv.Public().(ed25519.PublicKey)

	// 2. Catalog Key (32 bytes)
	catReader := hkdf.New(sha256.New, masterSecret, salt, []byte("flowstore-catalog-key-v1"))
	if _, err := io.ReadFull(catReader, kr.CatalogKey[:]); err != nil {
		return nil, fmt.Errorf("failed to derive catalog key: %w", err)
	}

	// 3. Routing Key (32 bytes)
	routeReader := hkdf.New(sha256.New, masterSecret, salt, []byte("flowstore-routing-key-v1"))
	if _, err := io.ReadFull(routeReader, kr.RoutingKey[:]); err != nil {
		return nil, fmt.Errorf("failed to derive routing key: %w", err)
	}

	// 4. Metadata Key (32 bytes)
	metaReader := hkdf.New(sha256.New, masterSecret, salt, []byte("flowstore-metadata-key-v1"))
	if _, err := io.ReadFull(metaReader, kr.MetadataKey[:]); err != nil {
		return nil, fmt.Errorf("failed to derive metadata key: %w", err)
	}

	// 5. Wrapping Key (32 bytes)
	wrapReader := hkdf.New(sha256.New, masterSecret, salt, []byte("flowstore-wrapping-key-v1"))
	if _, err := io.ReadFull(wrapReader, kr.WrappingKey[:]); err != nil {
		return nil, fmt.Errorf("failed to derive wrapping key: %w", err)
	}

	return kr, nil
}

// DeriveRoutingID computes an oblivious lookup token for a specific shard.
// RoutingID = BLAKE3-KeyedHash(routingKey, objectID || chunkIndex || shardIndex || epoch)
// Returns 64-character lowercase hex string.
func DeriveRoutingID(routingKey []byte, objectID []byte, chunkIndex uint32, shardIndex uint8, epoch uint32) string {
	hasher := blake3.New(32, routingKey)

	// Context buffer: objectID (typically 32 bytes) + 4-byte chunk + 1-byte shard + 4-byte epoch
	buf := make([]byte, len(objectID)+9)
	copy(buf, objectID)
	offset := len(objectID)

	binary.BigEndian.PutUint32(buf[offset:offset+4], chunkIndex)
	buf[offset+4] = shardIndex
	binary.BigEndian.PutUint32(buf[offset+5:offset+9], epoch)

	hasher.Write(buf)
	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum)
}
