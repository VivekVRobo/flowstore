package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
)

// Identity represents a cryptographically verified FlowStore node or client identity.
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// NewIdentityFromPrivateKey constructs an Identity from an Ed25519 private key.
func NewIdentityFromPrivateKey(priv ed25519.PrivateKey) *Identity {
	return &Identity{
		PrivateKey: priv,
		PublicKey:  priv.Public().(ed25519.PublicKey),
	}
}

// NodeID returns a deterministic hex-encoded identifier for this identity.
func (id *Identity) NodeID() string {
	return hex.EncodeToString(id.PublicKey)
}

// Sign generates an Ed25519 cryptographic signature over data.
func (id *Identity) Sign(data []byte) []byte {
	return ed25519.Sign(id.PrivateKey, data)
}

// VerifySignature verifies an Ed25519 signature against a public key.
func VerifySignature(pubKey ed25519.PublicKey, data []byte, sig []byte) bool {
	if len(pubKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubKey, data, sig)
}

// ParsePublicKey parses a 32-byte hex string into an Ed25519 public key.
func ParsePublicKey(hexStr string) (ed25519.PublicKey, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	if len(bytes) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key length: expected 32 bytes")
	}
	return ed25519.PublicKey(bytes), nil
}
