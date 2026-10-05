package repair_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"flowstore/internal/crypto"
	"flowstore/internal/erasure"
	"flowstore/internal/network"
	"flowstore/internal/object"
	"flowstore/internal/placement"
	"flowstore/internal/repair"
	"github.com/libp2p/go-libp2p/core/peer"
	"lukechampine.com/blake3"
)

func TestSwarmHealthAuditRepairAndFlowMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tempBase, err := os.MkdirTemp("", "flowstore_repair_flow_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempBase)

	// 1. Client Identity & Pipeline Setup
	masterSecret, _ := crypto.GenerateMasterSecret()
	keyring, _ := crypto.DeriveKeyring(masterSecret)

	clientHost, err := network.NewHost(ctx, network.Config{
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatalf("failed to create client host: %v", err)
	}
	defer clientHost.Close()

	scheduler := placement.NewScheduler()

	// 2. Spawn 14 independent P2P storage peer nodes
	// Peers 0..9 will hold the initial 10 shards.
	// Peers 10..12 will serve as repair replacement candidates.
	// Peer 13 will serve as the flow migration destination.
	numPeers := 14
	peerNodes := make([]*network.NodeService, numPeers)
	for i := 0; i < numPeers; i++ {
		pDir := filepath.Join(tempBase, fmt.Sprintf("node_%02d", i))
		node, err := network.NewNodeService(ctx, network.NodeConfig{
			DataDir:     pDir,
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		})
		if err != nil {
			t.Fatalf("failed to create peer node %d: %v", i, err)
		}
		defer node.Close()
		peerNodes[i] = node

		// Connect client to peer
		if err := clientHost.Connect(ctx, node.AddrInfo()); err != nil {
			t.Fatalf("failed to connect client to peer %d: %v", i, err)
		}

		// Register peer in scheduler
		scheduler.RegisterPeer(node.Host.ID(), 100*1024*1024, node.Multiaddrs())
	}

	// Connect peers to each other for full inter-peer mesh
	for i := 0; i < numPeers; i++ {
		for j := i + 1; j < numPeers; j++ {
			_ = peerNodes[i].Host.Connect(ctx, peerNodes[j].AddrInfo())
		}
	}

	// 3. Ingest a test dataset
	chunkSize := uint32(128 * 1024) // 128 KiB chunk
	payload := make([]byte, 128*1024)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatal(err)
	}
	originalHash := blake3.Sum256(payload)

	pipeline, err := object.NewPipeline(keyring, chunkSize, 0)
	if err != nil {
		t.Fatalf("NewPipeline failed: %v", err)
	}

	manifest, encodedChunks, err := pipeline.Ingest(bytes.NewReader(payload), "robotics/telemetry.bin")
	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}

	chunk := encodedChunks[0]

	// 4. Distribute 10 shards across the first 10 peers (Peers 0..9)
	locations := make(map[uint8]peer.ID)
	for _, shard := range chunk.Shards {
		targetPeer := peerNodes[shard.Index]
		sRef := chunk.Ref.Shards[shard.Index]

		if err := network.SendStoreShard(ctx, clientHost, targetPeer.Host.ID(), sRef.RoutingID, shard, 86400); err != nil {
			t.Fatalf("failed to store shard %d on peer %d: %v", shard.Index, shard.Index, err)
		}
		locations[shard.Index] = targetPeer.Host.ID()
	}
	t.Logf("Initial placement: 10 shards distributed across Peers 0..9.")

	// 5. Gate G6: Autonomous Health Audit
	auditor := repair.NewAuditor(clientHost)
	health := auditor.AuditChunk(ctx, chunk.Ref, locations)
	if health.State != repair.StateHealthy || health.HealthyShards != 10 {
		t.Fatalf("expected HEALTHY (10/10), got %s (%d/10)", health.State, health.HealthyShards)
	}
	t.Log("SUCCESS (Gate G6): Initial audit confirms 100% HEALTHY (10/10 shards valid).")

	// 6. Simulate Peer Churn: Kill 3 nodes (Peers 2, 5, 8)
	t.Log("Simulating peer departures: shutting down Peers 2, 5, 8...")
	peerNodes[2].Close()
	peerNodes[5].Close()
	peerNodes[8].Close()
	scheduler.MarkInactive(peerNodes[2].Host.ID())
	scheduler.MarkInactive(peerNodes[5].Host.ID())
	scheduler.MarkInactive(peerNodes[8].Host.ID())

	// Re-audit degraded chunk
	degradedHealth := auditor.AuditChunk(ctx, chunk.Ref, locations)
	if degradedHealth.State != repair.StateDegraded || degradedHealth.HealthyShards != 7 {
		t.Fatalf("expected DEGRADED with 7 shards, got %s with %d shards", degradedHealth.State, degradedHealth.HealthyShards)
	}
	t.Logf("SUCCESS (Gate G6): Auditor accurately detected DEGRADED state (7/10 surviving: missing indices %v).", degradedHealth.MissingIndices)

	// 7. Gate G7: Autonomous Self-Repair
	t.Log("Executing Autonomous Repair Engine: reconstructing 3 missing shards from 7 survivors...")
	repairEngine, err := repair.NewRepairEngine(clientHost, scheduler, nil)
	if err != nil {
		t.Fatalf("NewRepairEngine failed: %v", err)
	}

	repairRes := repairEngine.RepairChunk(ctx, chunk.Ref, degradedHealth, locations)
	if repairRes.Error != nil {
		t.Fatalf("RepairChunk failed: %v", repairRes.Error)
	}
	if !repairRes.RestoredToHealth || repairRes.RepairedCount != 3 {
		t.Fatalf("expected 3 repaired shards and restored health, got count=%d, restored=%v", repairRes.RepairedCount, repairRes.RestoredToHealth)
	}

	// Update location map with repaired peers
	locations = repairRes.NewLocations

	// Audit after repair
	postRepairHealth := auditor.AuditChunk(ctx, chunk.Ref, locations)
	if postRepairHealth.State != repair.StateHealthy || postRepairHealth.HealthyShards != 10 {
		t.Fatalf("expected swarm to return to HEALTHY (10/10), got %s (%d/10)", postRepairHealth.State, postRepairHealth.HealthyShards)
	}
	t.Log("SUCCESS (Gate G7): Swarm self-repair completed! Health restored back to 10/10 without original file.")

	// 8. Gate G8: The FLOW Migration Engine
	t.Log("Executing Gate G8 (Flow Migration): Migrating Shard 0 from Peer 0 to brand-new volunteer Peer 13...")
	flowEngine := repair.NewMigrationEngine(clientHost, scheduler, nil, repair.FlowContinuous)

	shard0Ref := chunk.Ref.Shards[0]
	sourcePeer0 := locations[0]
	event, err := flowEngine.MigrateShard(ctx, shard0Ref, sourcePeer0, locations)
	if err != nil {
		t.Fatalf("MigrateShard failed: %v", err)
	}

	t.Logf("Migration verified: Shard 0 moved from %s to %s.", event.FromPeer, event.ToPeer)
	locations[0] = event.ToPeer

	// Shut down original source Peer 0 to prove it no longer possesses or provides Shard 0
	peerNodes[0].Close()
	scheduler.MarkInactive(sourcePeer0)

	// Final verification: Retrieve the file from the swarm and verify byte-perfect reconstruction
	getter := func(routingID string) (*erasure.Shard, error) {
		for sIdx, pID := range locations {
			if chunk.Ref.Shards[sIdx].RoutingID == routingID {
				fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				s, err := network.FetchShard(fetchCtx, clientHost, pID, routingID)
				cancel()
				return s, err
			}
		}
		return nil, fmt.Errorf("shard %s not found", routingID)
	}

	var reconstructedBuf bytes.Buffer
	if err := pipeline.Reconstruct(&reconstructedBuf, manifest, getter); err != nil {
		t.Fatalf("Reconstruction failed after self-repair and flow migration: %v", err)
	}

	if !bytes.Equal(payload, reconstructedBuf.Bytes()) {
		t.Fatal("reconstructed payload does not match original file after repair and migration")
	}
	reconstructedHash := blake3.Sum256(reconstructedBuf.Bytes())
	if reconstructedHash != originalHash {
		t.Fatal("BLAKE3 hash mismatch on reconstructed file")
	}

	t.Log("SUCCESS (Gate G8): Byte-perfect retrieval verified after Autonomous Self-Repair and Flow Migration!")
}
