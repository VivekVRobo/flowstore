package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// ShardMeta holds index records for a stored shard.
type ShardMeta struct {
	RoutingID      string
	Size           int64
	Checksum       string
	CreatedAt      time.Time
	LeaseExpiresAt time.Time
	LeaseDuration  time.Duration
}

// NodeDB manages local SQLite index records for a node.
type NodeDB struct {
	db *sql.DB
}

// OpenNodeDB opens or creates the SQLite index database for a node.
func OpenNodeDB(dbPath string) (*NodeDB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Enable WAL mode for high concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to configure sqlite pragma: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS shards (
		routing_id TEXT PRIMARY KEY,
		size INTEGER NOT NULL,
		checksum TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		lease_expires_at INTEGER NOT NULL,
		lease_duration_seconds INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_lease_expires ON shards(lease_expires_at);
	`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}
	if err := migrateLeaseDuration(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate lease duration schema: %w", err)
	}

	return &NodeDB{db: db}, nil
}

// migrateLeaseDuration adds the renewal term to node databases created before
// persistent lease renewal was introduced. Old rows did not retain the
// requested term, so migration conservatively seeds it from the remaining
// validity at upgrade time instead of guessing from the original write date.
func migrateLeaseDuration(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(shards)`)
	if err != nil {
		return err
	}
	hasDuration := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == "lease_duration_seconds" {
			hasDuration = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if !hasDuration {
		if _, err := db.Exec(`ALTER TABLE shards ADD COLUMN lease_duration_seconds INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	_, err = db.Exec(`UPDATE shards
		SET lease_duration_seconds = MAX(1, lease_expires_at - ?)
		WHERE lease_duration_seconds <= 0`, time.Now().UTC().Unix())
	return err
}

// RecordShard adds or updates a shard record with lease expiration.
func (n *NodeDB) RecordShard(routingID string, size int64, checksum string, leaseDuration time.Duration) error {
	now := time.Now().UTC()
	expires := now.Add(leaseDuration)
	durationSeconds := int64(leaseDuration / time.Second)

	query := `
	INSERT INTO shards (routing_id, size, checksum, created_at, lease_expires_at, lease_duration_seconds)
	VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT(routing_id) DO UPDATE SET
		size = excluded.size,
		checksum = excluded.checksum,
		lease_expires_at = excluded.lease_expires_at,
		lease_duration_seconds = excluded.lease_duration_seconds;
	`
	_, err := n.db.Exec(query, routingID, size, checksum, now.Unix(), expires.Unix(), durationSeconds)
	return err
}

// GetShardMeta retrieves metadata for a shard.
func (n *NodeDB) GetShardMeta(routingID string) (*ShardMeta, error) {
	row := n.db.QueryRow(`SELECT routing_id, size, checksum, created_at, lease_expires_at, lease_duration_seconds FROM shards WHERE routing_id = ?`, routingID)

	var meta ShardMeta
	var createdUnix, expiresUnix, leaseSeconds int64
	if err := row.Scan(&meta.RoutingID, &meta.Size, &meta.Checksum, &createdUnix, &expiresUnix, &leaseSeconds); err != nil {
		return nil, err
	}

	meta.CreatedAt = time.Unix(createdUnix, 0).UTC()
	meta.LeaseExpiresAt = time.Unix(expiresUnix, 0).UTC()
	meta.LeaseDuration = time.Duration(leaseSeconds) * time.Second
	return &meta, nil
}

// ListExpiring returns live leases due to expire by cutoff. The limit bounds
// maintenance memory even when a node holds a large shard catalog.
func (n *NodeDB) ListExpiring(now, cutoff time.Time, limit int) ([]ShardMeta, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("lease query limit must be positive")
	}
	rows, err := n.db.Query(`SELECT routing_id, size, checksum, created_at, lease_expires_at, lease_duration_seconds
		FROM shards WHERE lease_expires_at > ? AND lease_expires_at <= ? AND lease_duration_seconds > 0
		ORDER BY lease_expires_at, routing_id LIMIT ?`, now.Unix(), cutoff.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanShardMetas(rows)
}

// RenewLease extends a still-live lease by its original duration. The prior
// checksum and expiry make the update conditional on the row remaining the
// same record that the caller inspected.
func (n *NodeDB) RenewLease(meta ShardMeta, now time.Time) (bool, error) {
	if meta.RoutingID == "" || meta.LeaseDuration <= 0 || !meta.LeaseExpiresAt.After(now) {
		return false, nil
	}
	result, err := n.db.Exec(`UPDATE shards
		SET lease_expires_at = ? + lease_duration_seconds
		WHERE routing_id = ? AND checksum = ? AND lease_expires_at = ?
		AND lease_expires_at > ? AND lease_duration_seconds > 0`,
		now.Unix(), meta.RoutingID, meta.Checksum, meta.LeaseExpiresAt.Unix(), now.Unix())
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	return changed > 0, err
}

// DeleteShard removes a shard record.
func (n *NodeDB) DeleteShard(routingID string) error {
	_, err := n.db.Exec(`DELETE FROM shards WHERE routing_id = ?`, routingID)
	return err
}

// ListAll returns every shard index record.
func (n *NodeDB) ListAll() ([]ShardMeta, error) {
	rows, err := n.db.Query(`SELECT routing_id, size, checksum, created_at, lease_expires_at, lease_duration_seconds FROM shards`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanShardMetas(rows)
}

// ListExpired returns records whose lease has passed as of now.
func (n *NodeDB) ListExpired(now time.Time) ([]ShardMeta, error) {
	rows, err := n.db.Query(`SELECT routing_id, size, checksum, created_at, lease_expires_at, lease_duration_seconds FROM shards WHERE lease_expires_at <= ?`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanShardMetas(rows)
}

func scanShardMetas(rows *sql.Rows) ([]ShardMeta, error) {
	var out []ShardMeta
	for rows.Next() {
		var meta ShardMeta
		var createdUnix, expiresUnix, leaseSeconds int64
		if err := rows.Scan(&meta.RoutingID, &meta.Size, &meta.Checksum, &createdUnix, &expiresUnix, &leaseSeconds); err != nil {
			return nil, err
		}
		meta.CreatedAt = time.Unix(createdUnix, 0).UTC()
		meta.LeaseExpiresAt = time.Unix(expiresUnix, 0).UTC()
		meta.LeaseDuration = time.Duration(leaseSeconds) * time.Second
		out = append(out, meta)
	}
	return out, rows.Err()
}

// TotalUsage returns the sum of shard sizes and count in this node.
func (n *NodeDB) TotalUsage() (totalBytes int64, count int, err error) {
	row := n.db.QueryRow(`SELECT COALESCE(SUM(size), 0), COUNT(*) FROM shards`)
	err = row.Scan(&totalBytes, &count)
	return
}

// Close closes the database handle.
func (n *NodeDB) Close() error {
	return n.db.Close()
}
