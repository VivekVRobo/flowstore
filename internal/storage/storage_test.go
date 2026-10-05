package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"flowstore/internal/erasure"
	"lukechampine.com/blake3"
)

func TestFileShardStoreRoundtrip(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "flowstore_shardstore_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFileShardStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileShardStore failed: %v", err)
	}
	defer store.Close()

	payload := []byte("Opaque shard payload stored on an autonomous peer machine.")
	checksum := blake3.Sum256(payload)

	shard := erasure.Shard{
		Index:        3,
		Data:         payload,
		Checksum:     checksum,
		OriginalSize: 1024,
	}

	routingID := "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"

	// Put
	if err := store.Put(routingID, shard); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Has
	if !store.Has(routingID) {
		t.Fatal("expected store.Has to return true")
	}

	// Get
	retrieved, err := store.Get(routingID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.Index != shard.Index {
		t.Fatalf("index mismatch: %d != %d", retrieved.Index, shard.Index)
	}
	if !bytes.Equal(retrieved.Data, shard.Data) {
		t.Fatal("retrieved shard data mismatch")
	}
	if retrieved.Checksum != shard.Checksum {
		t.Fatal("checksum mismatch")
	}

	// List
	list, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(list) != 1 || list[0] != routingID {
		t.Fatalf("unexpected list output: %v", list)
	}

	// Delete
	if err := store.Delete(routingID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if store.Has(routingID) {
		t.Fatal("shard still exists after delete")
	}
}

func TestNodeDBOperations(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "flowstore_nodedb_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "node.db")
	db, err := OpenNodeDB(dbPath)
	if err != nil {
		t.Fatalf("OpenNodeDB failed: %v", err)
	}
	defer db.Close()

	routingID := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	if err := db.RecordShard(routingID, 65536, "checksum-blake3", 24*time.Hour); err != nil {
		t.Fatalf("RecordShard failed: %v", err)
	}

	meta, err := db.GetShardMeta(routingID)
	if err != nil {
		t.Fatalf("GetShardMeta failed: %v", err)
	}

	if meta.Size != 65536 {
		t.Fatalf("expected size 65536, got %d", meta.Size)
	}
	if meta.Checksum != "checksum-blake3" {
		t.Fatalf("expected checksum 'checksum-blake3', got %s", meta.Checksum)
	}

	usage, count, err := db.TotalUsage()
	if err != nil {
		t.Fatalf("TotalUsage failed: %v", err)
	}
	if usage != 65536 || count != 1 {
		t.Fatalf("unexpected usage: %d bytes, %d count", usage, count)
	}

	if err := db.DeleteShard(routingID); err != nil {
		t.Fatalf("DeleteShard failed: %v", err)
	}

	_, err = db.GetShardMeta(routingID)
	if err == nil {
		t.Fatal("expected error getting deleted shard, got nil")
	}
}
