package storage

import (
	"time"
)

// GCStats reports what a collection pass reclaimed.
type GCStats struct {
	LeaseRenewed         int
	LeaseRenewSkipped    int
	ExpiredRemoved       int
	OrphanFilesRemoved   int
	OrphanRecordsRemoved int
}

// ExpireLeases deletes files and index records whose lease has passed.
// It returns the number of expired shards reclaimed.
func ExpireLeases(store ShardStore, db *NodeDB, now time.Time) (int, error) {
	if db == nil {
		return 0, nil
	}
	expired, err := db.ListExpired(now)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, meta := range expired {
		_ = store.Delete(meta.RoutingID)
		if err := db.DeleteShard(meta.RoutingID); err == nil {
			removed++
		}
	}
	return removed, nil
}

// Reconcile removes orphan files (no index record) and orphan index
// records (no file) so quota and List() reflect reality.
// It returns orphan file and record counts removed.
func Reconcile(store ShardStore, db *NodeDB) (orphanFiles, orphanRecords int, err error) {
	files, err := store.List()
	if err != nil {
		return 0, 0, err
	}
	if db == nil {
		return 0, 0, nil
	}
	records, err := db.ListAll()
	if err != nil {
		return 0, 0, err
	}
	recordSet := make(map[string]struct{}, len(records))
	for _, r := range records {
		recordSet[r.RoutingID] = struct{}{}
	}
	fileSet := make(map[string]struct{}, len(files))
	for _, f := range files {
		fileSet[f] = struct{}{}
	}
	for _, f := range files {
		if _, ok := recordSet[f]; !ok {
			_ = store.Delete(f)
			orphanFiles++
		}
	}
	for _, r := range records {
		if _, ok := fileSet[r.RoutingID]; !ok {
			_ = db.DeleteShard(r.RoutingID)
			orphanRecords++
		}
	}
	return orphanFiles, orphanRecords, nil
}

// CollectGarbage expires leases then reconciles index and disk.
func CollectGarbage(store ShardStore, db *NodeDB, now time.Time) (GCStats, error) {
	var stats GCStats
	expired, err := ExpireLeases(store, db, now)
	if err != nil {
		return stats, err
	}
	stats.ExpiredRemoved = expired
	orphanFiles, orphanRecords, err := Reconcile(store, db)
	if err != nil {
		return stats, err
	}
	stats.OrphanFilesRemoved = orphanFiles
	stats.OrphanRecordsRemoved = orphanRecords
	return stats, nil
}
