package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestMasterSecretGenerationAndParsing(t *testing.T) {
	secret, err := GenerateMasterSecret()
	if err != nil {
		t.Fatalf("GenerateMasterSecret failed: %v", err)
	}
	if len(secret) != MasterSecretSize {
		t.Fatalf("expected secret size %d, got %d", MasterSecretSize, len(secret))
	}

	code := FormatRecoveryCode(secret)
	parsedSecret, err := ParseRecoveryCode(code)
	if err != nil {
		t.Fatalf("ParseRecoveryCode failed: %v", err)
	}

	if !bytes.Equal(secret, parsedSecret) {
		t.Fatalf("parsed secret does not match original: %x != %x", parsedSecret, secret)
	}
}

func TestKeyringDerivationDeterminism(t *testing.T) {
	secret, _ := GenerateMasterSecret()

	kr1, err := DeriveKeyring(secret)
	if err != nil {
		t.Fatalf("DeriveKeyring 1 failed: %v", err)
	}

	kr2, err := DeriveKeyring(secret)
	if err != nil {
		t.Fatalf("DeriveKeyring 2 failed: %v", err)
	}

	if !bytes.Equal(kr1.CatalogKey[:], kr2.CatalogKey[:]) {
		t.Error("CatalogKey derivation not deterministic")
	}
	if !bytes.Equal(kr1.RoutingKey[:], kr2.RoutingKey[:]) {
		t.Error("RoutingKey derivation not deterministic")
	}
	if !bytes.Equal(kr1.MetadataKey[:], kr2.MetadataKey[:]) {
		t.Error("MetadataKey derivation not deterministic")
	}
	if !bytes.Equal(kr1.WrappingKey[:], kr2.WrappingKey[:]) {
		t.Error("WrappingKey derivation not deterministic")
	}
	if !bytes.Equal(kr1.IdentityPub, kr2.IdentityPub) {
		t.Error("IdentityPub derivation not deterministic")
	}
}

func TestXChaCha20Poly1305Roundtrip(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("The swarming information follows no permanent server home.")
	aad := []byte("chunk-0001-context")

	ciphertext, err := Encrypt(plaintext, key, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, key, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted does not match plaintext: got %s, want %s", string(decrypted), string(plaintext))
	}
}

func TestTamperDetection(t *testing.T) {
	key := make([]byte, KeySize)
	io.ReadFull(rand.Reader, key)

	plaintext := []byte("Sensitive payload to be protected against tampering")
	aad := []byte("object-12345")

	ciphertext, err := Encrypt(plaintext, key, aad)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Bit flip in ciphertext body
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-5] ^= 0x01 // flip a bit in tag/payload
	_, err = Decrypt(tampered, key, aad)
	if err == nil {
		t.Error("expected decryption failure on tampered ciphertext, but succeeded")
	}

	// 2. Tampered AAD
	wrongAAD := []byte("object-99999")
	_, err = Decrypt(ciphertext, key, wrongAAD)
	if err == nil {
		t.Error("expected decryption failure with wrong AAD, but succeeded")
	}

	// 3. Truncated ciphertext
	_, err = Decrypt(ciphertext[:10], key, aad)
	if err == nil {
		t.Error("expected error on truncated ciphertext, but succeeded")
	}
}

func TestRoutingIDUnlinkability(t *testing.T) {
	routingKey := make([]byte, 32)
	io.ReadFull(rand.Reader, routingKey)

	objectID := []byte("object-alpha")
	r1 := DeriveRoutingID(routingKey, objectID, 0, 1, 0)
	r2 := DeriveRoutingID(routingKey, objectID, 0, 2, 0) // different shard index
	r3 := DeriveRoutingID(routingKey, objectID, 1, 1, 0) // different chunk index
	r4 := DeriveRoutingID(routingKey, objectID, 0, 1, 1) // different epoch

	if r1 == r2 || r1 == r3 || r1 == r4 || r2 == r3 || r2 == r4 || r3 == r4 {
		t.Fatalf("routing IDs collided or failed to differentiate indices: %s, %s, %s, %s", r1, r2, r3, r4)
	}
	if len(r1) != 64 {
		t.Fatalf("expected 64-hex char routing ID, got %d chars", len(r1))
	}
}

func TestIdentitySignAndVerify(t *testing.T) {
	secret, _ := GenerateMasterSecret()
	kr, _ := DeriveKeyring(secret)

	id := NewIdentityFromPrivateKey(kr.IdentityPriv)
	message := []byte("Challenge response for peer proof")

	sig := id.Sign(message)
	if !VerifySignature(id.PublicKey, message, sig) {
		t.Fatal("valid signature failed verification")
	}

	// Invalid message
	if VerifySignature(id.PublicKey, []byte("Altered challenge"), sig) {
		t.Fatal("signature verified against altered message")
	}
}
