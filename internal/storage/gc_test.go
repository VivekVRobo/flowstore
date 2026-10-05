package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"flowstore/internal/erasure"
	"lukechampine.com/blake3"
)

func putTestShard(t *testing.T, store *FileShardStore, routingID string, payload string) {
	t.Helper()
	data := []byte(payload)
	shard := erasure.Shard{
		Index:        0,
		Data:         data,
		Checksum:     blake3.Sum256(data),
		OriginalSize: uint64(len(data)),
	}
	if err := store.Put(routingID, shard); err != nil {
		t.Fatalf("Put %s failed: %v", routingID, err)
	}
}

func TestExpireLeasesAndReconcile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "flowstore_gc_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFileShardStore(filepath.Join(tempDir, "shards"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	db, err := OpenNodeDB(filepath.Join(tempDir, "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC()
	expiredID := "1111111111111111111111111111111111111111111111111111111111111111"
	liveID := "2222222222222222222222222222222222222222222222222222222222222222"
	putTestShard(t, store, expiredID, "expired-payload")
	putTestShard(t, store, liveID, "live-payload")

	if err := db.RecordShard(expiredID, 16, "expired", -time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordShard(liveID, 12, "live", time.Hour); err != nil {
		t.Fatal(err)
	}
	// Make the expired lease actually past relative to now.
	expiredMeta, err := db.GetShardMeta(expiredID)
	if err != nil {
		t.Fatal(err)
	}
	if !expiredMeta.LeaseExpiresAt.Before(now.Add(time.Minute)) {
		t.Fatalf("expected expired lease, got %+v", expiredMeta)
	}

	stats, err := CollectGarbage(store, db, now)
	if err != nil {
		t.Fatalf("CollectGarbage failed: %v", err)
	}
	if stats.ExpiredRemoved != 1 {
		t.Fatalf("expected 1 expired removed, got %+v", stats)
	}
	if store.Has(expiredID) {
		t.Fatal("expired shard file still present")
	}
	if _, err := db.GetShardMeta(expiredID); err == nil {
		t.Fatal("expired shard record still present")
	}
	if !store.Has(liveID) {
		t.Fatal("live shard was incorrectly collected")
	}

	// Orphan file (no DB record) and orphan record (no file) are reconciled.
	orphanFileID := "3333333333333333333333333333333333333333333333333333333333333333"
	putTestShard(t, store, orphanFileID, "orphan-file")
	orphanRecordID := "4444444444444444444444444444444444444444444444444444444444444444"
	if err := db.RecordShard(orphanRecordID, 10, "orphan", time.Hour); err != nil {
		t.Fatal(err)
	}
	stats, err = CollectGarbage(store, db, now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.OrphanFilesRemoved != 1 || stats.OrphanRecordsRemoved != 1 {
		t.Fatalf("expected 1 orphan file + 1 orphan record, got %+v", stats)
	}
	if store.Has(orphanFileID) {
		t.Fatal("orphan file still present")
	}
	if _, err := db.GetShardMeta(orphanRecordID); err == nil {
		t.Fatal("orphan record still present")
	}

	used, quota := store.UsageBytes()
	_ = quota
	if used <= 0 {
		t.Fatal("expected positive usage for surviving live shard")
	}
	_, count, err := db.TotalUsage()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 surviving record, got %d", count)
	}
}
