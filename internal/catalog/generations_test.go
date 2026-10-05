package catalog

import (
	"context"
	"testing"
	"time"

	"flowstore/internal/crypto"
	"flowstore/internal/network"
)

func TestCatalogGenerationsAtomicRoot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pcHost, err := network.NewHost(ctx, network.Config{
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pcHost.Close()

	// Minimal in-memory peer IDs are not needed; test locator + pointer math
	// plus a two-publish flow against real nodes happens in recovery tests.
	// Here verify root pointer encrypt/decrypt and locator stability.
	secret, _ := crypto.GenerateMasterSecret()
	kr, _ := crypto.DeriveKeyring(secret)
	id := crypto.NewIdentityFromPrivateKey(kr.IdentityPriv)
	cat := NewCatalog(id.NodeID())
	if cat.Version != 1 {
		t.Fatalf("expected version 1, got %d", cat.Version)
	}
	epoch1 := uint32(cat.Version)
	locA := DeriveCatalogShardLocator(kr.CatalogKey[:], 0, epoch1)
	locB := DeriveCatalogShardLocator(kr.CatalogKey[:], 0, epoch1)
	if locA != locB {
		t.Fatal("generation locator not deterministic")
	}
	rootA := DeriveCatalogRootLocator(kr.CatalogKey[:], 0)
	rootB := DeriveCatalogRootLocator(kr.CatalogKey[:], 0)
	if rootA == locA {
		t.Fatal("root namespace collides with generation namespace")
	}
	if rootA != rootB {
		t.Fatal("root locator not deterministic")
	}
	ptr := &CatalogRootPointer{FormatVersion: 1, OwnerID: cat.OwnerID, CatalogVersion: cat.Version, CatalogEpoch: epoch1}
	enc, err := encryptRootPointer(ptr, kr.CatalogKey[:])
	if err != nil {
		t.Fatal(err)
	}
	dec, err := decryptRootPointer(enc, kr.CatalogKey[:], cat.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	if dec.CatalogVersion != 1 || dec.CatalogEpoch != epoch1 {
		t.Fatalf("bad pointer roundtrip: %+v", dec)
	}
	// Wrong owner must fail.
	if _, err := decryptRootPointer(enc, kr.CatalogKey[:], "other"); err == nil {
		t.Fatal("expected owner mismatch to fail")
	}
}
