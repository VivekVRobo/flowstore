package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrCiphertextTooShort = errors.New("ciphertext too short: must be at least nonce size + overhead")
	ErrDecryptionFailed   = errors.New("decryption failed: authentication tag mismatch or corrupted data")
)

// Encrypt encrypts plaintext using XChaCha20-Poly1305 with a freshly generated 24-byte nonce.
// Returns: nonce (24 bytes) || ciphertext || tag (16 bytes).
func Encrypt(plaintext []byte, key []byte, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: got %d, expected %d", len(key), chacha20poly1305.KeySize)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	// aead.Seal appends the encrypted ciphertext and 16-byte tag to the prefix buffer (here, nonce).
	ciphertext := aead.Seal(nonce, nonce, plaintext, aad)
	return ciphertext, nil
}

// Decrypt verifies and decrypts ciphertext that begins with a 24-byte nonce.
func Decrypt(ciphertext []byte, key []byte, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: got %d, expected %d", len(key), chacha20poly1305.KeySize)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize+aead.Overhead() {
		return nil, ErrCiphertextTooShort
	}

	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, actualCiphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}
