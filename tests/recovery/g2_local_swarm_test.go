package recovery_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"flowstore/internal/crypto"
	"flowstore/internal/erasure"
	"flowstore/internal/object"
	"flowstore/internal/storage"
	"lukechampine.com/blake3"
)

// SimulatedNode represents an independent peer node holding a local disk store.
type SimulatedNode struct {
	ID    int
	Dir   string
	Store *storage.FileShardStore
	Alive bool
}

func NewSimulatedNode(id int, baseDir string) (*SimulatedNode, error) {
	nodeDir := filepath.Join(baseDir, fmt.Sprintf("node_%02d", id))
	store, err := storage.NewFileShardStore(nodeDir)
	if err != nil {
		return nil, err
	}
	return &SimulatedNode{
		ID:    id,
		Dir:   nodeDir,
		Store: store,
		Alive: true,
	}, nil
}

func (n *SimulatedNode) Destroy() {
	n.Alive = false
	os.RemoveAll(n.Dir)
}

func TestG2LocalSwarmCatastrophicLossAndSelfHealing(t *testing.T) {
	tempBase, err := os.MkdirTemp("", "flowstore_g2_swarm_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempBase)

	// 1. Identity & Keyring
	masterSecret, err := crypto.GenerateMasterSecret()
	if err != nil {
		t.Fatalf("crypto.GenerateMasterSecret failed: %v", err)
	}
	keyring, err := crypto.DeriveKeyring(masterSecret)
	if err != nil {
		t.Fatalf("crypto.DeriveKeyring failed: %v", err)
	}

	recoveryCode := crypto.FormatRecoveryCode(masterSecret)
	t.Logf("Generated Recovery Secret: %s", recoveryCode)

	// 2. Initialize 10 initial nodes (Node 0 .. Node 9)
	numInitialNodes := 10
	nodes := make([]*SimulatedNode, numInitialNodes)
	for i := 0; i < numInitialNodes; i++ {
		node, err := NewSimulatedNode(i, tempBase)
		if err != nil {
			t.Fatalf("failed to create node %d: %v", i, err)
		}
		nodes[i] = node
	}

	// 3. Prepare a multi-chunk test file (e.g., 2 MiB with 256 KiB chunks -> 8 chunks, 80 shards)
	chunkSize := uint32(256 * 1024) // 256 KiB chunks for thorough multi-chunk testing
	totalFileSize := 2 * 1024 * 1024 // 2 MiB
	originalPayload := make([]byte, totalFileSize)
	if _, err := io.ReadFull(rand.Reader, originalPayload); err != nil {
		t.Fatal(err)
	}
	originalHash := blake3.Sum256(originalPayload)

	// 4. Ingestion Pipeline
	pipeline, err := object.NewPipeline(keyring, chunkSize, 0)
	if err != nil {
		t.Fatalf("NewPipeline failed: %v", err)
	}

	manifest, encodedChunks, err := pipeline.Ingest(bytes.NewReader(originalPayload), "robotics/arm-design.step")
	if err != nil {
		t.Fatalf("pipeline.Ingest failed: %v", err)
	}

	expectedChunks := (totalFileSize + int(chunkSize) - 1) / int(chunkSize)
	if len(manifest.Chunks) != expectedChunks {
		t.Fatalf("expected %d chunks, got %d", expectedChunks, len(manifest.Chunks))
	}

	// 5. Shard Placement:
	// Distribute shard i to Node i (ensures failure-domain isolation)
	routingToNode := make(map[string]*SimulatedNode)
	for _, chunk := range encodedChunks {
		for _, shard := range chunk.Shards {
			targetNode := nodes[shard.Index]
			sRef := chunk.Ref.Shards[shard.Index]
			if err := targetNode.Store.Put(sRef.RoutingID, shard); err != nil {
				t.Fatalf("failed to store shard on node %d: %v", targetNode.ID, err)
			}
			routingToNode[sRef.RoutingID] = targetNode
		}
	}
	t.Logf("Distributed %d chunks (%d shards total) across %d nodes.", len(encodedChunks), len(encodedChunks)*10, numInitialNodes)

	// Helper getter that queries surviving nodes
	makeGetter := func(currentNodes []*SimulatedNode) object.ShardGetter {
		return func(routingID string) (*erasure.Shard, error) {
			for _, node := range currentNodes {
				if node.Alive && node.Store.Has(routingID) {
					return node.Store.Get(routingID)
				}
			}
			return nil, storage.ErrShardNotFound
		}
	}

	// 6. Catastrophic Failure #1: Deliberately destroy 4 nodes (40% of swarm disappears)
	destroyedIDs := []int{1, 4, 7, 9}
	t.Logf("Simulating catastrophic failure: destroying nodes %v...", destroyedIDs)
	for _, id := range destroyedIDs {
		nodes[id].Destroy()
	}

	// Count surviving alive nodes
	aliveCount := 0
	for _, n := range nodes {
		if n.Alive {
			aliveCount++
		}
	}
	if aliveCount != 6 {
		t.Fatalf("expected 6 alive nodes, got %d", aliveCount)
	}

	// 7. Reconstruction under catastrophic 40% loss
	var recoveredBuffer bytes.Buffer
	getter := makeGetter(nodes)
	if err := pipeline.Reconstruct(&recoveredBuffer, manifest, getter); err != nil {
		t.Fatalf("Reconstruction failed with 4 nodes dead: %v", err)
	}

	if !bytes.Equal(originalPayload, recoveredBuffer.Bytes()) {
		t.Fatal("recovered payload does not match original after 4 dead nodes")
	}
	recoveredHash := blake3.Sum256(recoveredBuffer.Bytes())
	if recoveredHash != originalHash {
		t.Fatal("BLAKE3 hash mismatch on recovered data")
	}
	t.Log("SUCCESS: Byte-perfect reconstruction verified with 4/10 nodes destroyed!")

	// 8. Self-Healing & Swarm Repair Engine:
	// Bring 4 new replacement nodes online (Node 10, Node 11, Node 12, Node 13)
	t.Log("Executing Swarm Self-Healing: reconstructing missing shards from surviving 6 nodes...")
	var newNodes []*SimulatedNode
	for i := 10; i < 14; i++ {
		newNode, err := NewSimulatedNode(i, tempBase)
		if err != nil {
			t.Fatalf("failed to create replacement node %d: %v", i, err)
		}
		newNodes = append(newNodes, newNode)
	}

	erasureEngine, _ := erasure.DefaultEngine()
	// For each chunk, find missing shards, reconstruct, and place onto new nodes
	for _, chunkRef := range manifest.Chunks {
		var survivingShards []erasure.Shard
		for _, sRef := range chunkRef.Shards {
			s, err := getter(sRef.RoutingID)
			if err == nil && s != nil {
				survivingShards = append(survivingShards, *s)
			}
		}

		missingShards, err := erasureEngine.ReconstructMissing(survivingShards)
		if err != nil {
			t.Fatalf("ReconstructMissing failed for chunk %d: %v", chunkRef.Index, err)
		}

		if len(missingShards) != 4 {
			t.Fatalf("expected 4 missing shards for chunk %d, got %d", chunkRef.Index, len(missingShards))
		}

		// Place reconstructed shards onto the replacement nodes
		for idx, missing := range missingShards {
			targetReplacement := newNodes[idx]
			sRef := chunkRef.Shards[missing.Index]
			if err := targetReplacement.Store.Put(sRef.RoutingID, missing); err != nil {
				t.Fatalf("failed to store repaired shard on replacement node: %v", err)
			}
		}
	}

	// Active pool is now original surviving (6) + new replacements (4) = 10 nodes
	var activeSwarm []*SimulatedNode
	for _, n := range nodes {
		if n.Alive {
			activeSwarm = append(activeSwarm, n)
		}
	}
	activeSwarm = append(activeSwarm, newNodes...)

	if len(activeSwarm) != 10 {
		t.Fatalf("expected active swarm to be back to 10 nodes, got %d", len(activeSwarm))
	}
	t.Log("SUCCESS: Swarm self-healing completed! Health restored back to 10/10.")

	// 9. Catastrophic Wave #2: Kill a DIFFERENT 4 nodes from the active swarm
	t.Log("Simulating Catastrophic Wave #2: destroying 4 different nodes from the repaired swarm...")
	secondWaveKills := []*SimulatedNode{activeSwarm[0], activeSwarm[2], activeSwarm[5], activeSwarm[7]}
	for _, n := range secondWaveKills {
		n.Destroy()
	}

	var wave2Buffer bytes.Buffer
	wave2Getter := makeGetter(activeSwarm)
	if err := pipeline.Reconstruct(&wave2Buffer, manifest, wave2Getter); err != nil {
		t.Fatalf("Wave 2 reconstruction failed: %v", err)
	}

	if !bytes.Equal(originalPayload, wave2Buffer.Bytes()) {
		t.Fatal("Wave 2 recovered payload does not match original")
	}
	t.Log("SUCCESS: Byte-perfect reconstruction verified after second wave of node destructions!")
}
