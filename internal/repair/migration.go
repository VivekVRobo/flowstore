package repair

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"flowstore/internal/network"
	"flowstore/internal/object"
	"flowstore/internal/placement"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// FlowMode defines the operational migration cadence.
type FlowMode string

const (
	FlowOff        FlowMode = "OFF"        // Static storage (no proactive movement)
	FlowSlow       FlowMode = "SLOW"       // ~5% shards migrated per month
	FlowAggressive FlowMode = "AGGRESSIVE" // ~10% shards migrated per day
	FlowContinuous FlowMode = "CONTINUOUS" // Immediate/test cadence for research monitoring
)

// MigrationEngine moves healthy shards continually between consented peers
// to eliminate any permanent physical home of the data.
type MigrationEngine struct {
	host      host.Host
	scheduler *placement.Scheduler
	dht       *network.ShardRouting
	mode      FlowMode
}

// NewMigrationEngine creates a new Flow migration controller.
func NewMigrationEngine(h host.Host, sched *placement.Scheduler, dht *network.ShardRouting, mode FlowMode) *MigrationEngine {
	if mode == "" {
		mode = FlowOff
	}
	return &MigrationEngine{
		host:      h,
		scheduler: sched,
		dht:       dht,
		mode:      mode,
	}
}

// Mode returns current flow configuration.
func (me *MigrationEngine) Mode() FlowMode {
	return me.mode
}

// SetMode updates the migration policy at runtime.
func (me *MigrationEngine) SetMode(mode FlowMode) {
	me.mode = mode
}

// MigrationEvent records an audit record of a successful shard movement.
type MigrationEvent struct {
	ShardIndex uint8
	RoutingID  string
	FromPeer   peer.ID
	ToPeer     peer.ID
	Timestamp  time.Time
}

// MigrateShard executes the copy-then-verify-then-retire migration protocol for a single shard.
func (me *MigrationEngine) MigrateShard(
	ctx context.Context,
	sRef object.ShardRef,
	sourcePeer peer.ID,
	chunkPeerMap map[uint8]peer.ID,
) (*MigrationEvent, error) {
	if me.mode == FlowOff {
		return nil, errors.New("migration engine is currently OFF")
	}

	// 1. Pick destination peer that does NOT already host any shard of this chunk,
	// preferring a new failure domain.
	excluded := make(map[peer.ID]bool)
	for _, pID := range chunkPeerMap {
		excluded[pID] = true
	}
	excluded[sourcePeer] = true

	candidates, _, err := me.scheduler.SelectDiversePeers(1, excluded)
	if err != nil {
		candidates, err = me.scheduler.SelectDistinctPeers(1, excluded)
		if err != nil {
			return nil, fmt.Errorf("failed to select new destination peer for migration: %w", err)
		}
	}
	destPeer := candidates[0]

	// 2. Fetch encrypted shard from source peer
	fetchCtx, cancelFetch := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFetch()

	shard, err := network.FetchShard(fetchCtx, me.host, sourcePeer, sRef.RoutingID)
	if err != nil {
		return nil, fmt.Errorf("migration read from source peer %s failed: %w", sourcePeer, err)
	}

	// 3. Cryptographic integrity verification before copying
	if shard.Checksum != sRef.Checksum {
		return nil, fmt.Errorf("shard read from %s is corrupt (expected %x, got %x)", sourcePeer, sRef.Checksum, shard.Checksum)
	}

	// 4. Copy encrypted shard to destination peer
	storeCtx, cancelStore := context.WithTimeout(ctx, 10*time.Second)
	defer cancelStore()

	if err := network.SendStoreShard(storeCtx, me.host, destPeer, sRef.RoutingID, *shard, 30*24*3600); err != nil {
		return nil, fmt.Errorf("migration store to destination peer %s failed: %w", destPeer, err)
	}

	// 5. Verification: Probe destination peer for cryptographic proof of possession
	var nonce [32]byte
	_, _ = io.ReadFull(rand.Reader, nonce[:])

	probeCtx, cancelProbe := context.WithTimeout(ctx, 5*time.Second)
	defer cancelProbe()

	hasProof, err := network.ProbeShard(probeCtx, me.host, destPeer, sRef.RoutingID, nonce, sRef.Checksum)
	if err != nil || !hasProof {
		return nil, fmt.Errorf("destination peer failed proof-of-possession after migration copy: %w", err)
	}

	// 6. Update DHT provider routing to announce new location
	if me.dht != nil {
		_ = me.dht.Provide(ctx, sRef.RoutingID)
	}

	event := &MigrationEvent{
		ShardIndex: sRef.ShardIndex,
		RoutingID:  sRef.RoutingID,
		FromPeer:   sourcePeer,
		ToPeer:     destPeer,
		Timestamp:  time.Now().UTC(),
	}

	return event, nil
}
