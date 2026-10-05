package repair

import (
	"context"
	"fmt"
	"time"

	"flowstore/internal/erasure"
	"flowstore/internal/network"
	"flowstore/internal/object"
	"flowstore/internal/placement"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// RepairEngine coordinates autonomous reconstruction of degraded shards.
type RepairEngine struct {
	host      host.Host
	erasure   *erasure.Engine
	scheduler *placement.Scheduler
	dht       *network.ShardRouting
}

// NewRepairEngine creates a new autonomous repair controller.
func NewRepairEngine(h host.Host, sched *placement.Scheduler, dht *network.ShardRouting) (*RepairEngine, error) {
	engine, err := erasure.DefaultEngine()
	if err != nil {
		return nil, err
	}
	return &RepairEngine{
		host:      h,
		erasure:   engine,
		scheduler: sched,
		dht:       dht,
	}, nil
}

// RepairResult records the outcome of a chunk repair operation.
type RepairResult struct {
	ChunkIndex       uint32
	RepairedCount    int
	NewLocations     map[uint8]peer.ID
	RestoredToHealth bool
	Error            error
}

// RepairChunk recovers missing shards for a degraded chunk and redistributes them across fresh peers.
func (re *RepairEngine) RepairChunk(ctx context.Context, chunkRef object.ChunkRef, health ChunkHealth, currentLocations map[uint8]peer.ID) RepairResult {
	result := RepairResult{
		ChunkIndex:   chunkRef.Index,
		NewLocations: make(map[uint8]peer.ID),
	}

	// Copy existing surviving locations
	for idx, p := range health.SurvivingPeers {
		result.NewLocations[idx] = p
	}

	if health.HealthyShards < re.erasure.DataShards() {
		result.Error = fmt.Errorf("chunk %d has only %d shards, cannot reconstruct (need at least %d)",
			chunkRef.Index, health.HealthyShards, re.erasure.DataShards())
		return result
	}

	if len(health.MissingIndices) == 0 {
		result.RestoredToHealth = true
		return result
	}

	// 1. Fetch at least 6 surviving shards from surviving peers
	var survivingShards []erasure.Shard
	for sIdx, pID := range health.SurvivingPeers {
		sRef := chunkRef.Shards[sIdx]
		fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		shard, err := network.FetchShard(fetchCtx, re.host, pID, sRef.RoutingID)
		cancel()

		if err == nil && shard != nil {
			survivingShards = append(survivingShards, *shard)
			if len(survivingShards) == re.erasure.DataShards() {
				break // 6 surviving shards are mathematically sufficient!
			}
		}
	}

	if len(survivingShards) < re.erasure.DataShards() {
		result.Error = fmt.Errorf("failed to fetch 6 surviving shards: only obtained %d", len(survivingShards))
		return result
	}

	// 2. Synthesize missing shards using Reed-Solomon without original file
	reconstructed, err := re.erasure.ReconstructMissing(survivingShards)
	if err != nil {
		result.Error = fmt.Errorf("reconstruct missing shards failed: %w", err)
		return result
	}

	// Filter down to only shards that are actually missing in the swarm
	var missingShards []erasure.Shard
	for _, s := range reconstructed {
		if _, exists := health.SurvivingPeers[s.Index]; !exists {
			missingShards = append(missingShards, s)
		}
	}

	// 3. Find eligible replacement peers (must NOT already hold any shard of this chunk).
	// Prefer failure-domain spread; fall back to distinct peers on single-host tests.
	excluded := make(map[peer.ID]bool)
	for _, pID := range health.SurvivingPeers {
		excluded[pID] = true
	}

	replacementPeers, _, err := re.scheduler.SelectDiversePeers(len(missingShards), excluded)
	if err != nil {
		replacementPeers, err = re.scheduler.SelectDistinctPeers(len(missingShards), excluded)
		if err != nil {
			result.Error = fmt.Errorf("failed to find replacement peers: %w", err)
			return result
		}
	}

	// 4. Dispatch reconstructed shards to new volunteer peers
	for i, missing := range missingShards {
		targetPeer := replacementPeers[i]
		sRef := chunkRef.Shards[missing.Index]

		storeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := network.SendStoreShard(storeCtx, re.host, targetPeer, sRef.RoutingID, missing, 30*24*3600)
		cancel()

		if err != nil {
			result.Error = fmt.Errorf("failed to store repaired shard %d on peer %s: %w", missing.Index, targetPeer, err)
			return result
		}

		// 5. Announce on DHT if available
		if re.dht != nil {
			_ = re.dht.Provide(ctx, sRef.RoutingID)
		}

		result.NewLocations[missing.Index] = targetPeer
		result.RepairedCount++
	}

	result.RestoredToHealth = (len(result.NewLocations) == re.erasure.TotalShards())
	return result
}
