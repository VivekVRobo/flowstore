package network_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"flowstore/internal/crypto"
	"flowstore/internal/erasure"
	"flowstore/internal/network"
	"flowstore/internal/object"
	"lukechampine.com/blake3"
)

func TestWANTransferAndClientSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tempBase, err := os.MkdirTemp("", "flowstore_wan_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempBase)

	// 1. Start Node 1 (Simulated WAN Node 1)
	dir1 := filepath.Join(tempBase, "node_wan_1")
	node1, err := network.NewNodeService(ctx, network.NodeConfig{
		DataDir: dir1,
		ListenAddrs: []string{
			"/ip4/127.0.0.1/tcp/0",
			"/ip4/127.0.0.1/udp/0/quic-v1",
		},
		EnableAutoNAT: true,
		EnableRelay:   true,
	})
	if err != nil {
		t.Fatalf("failed starting Node 1: %v", err)
	}
	defer node1.Close()

	// 2. Start Node 2 (Simulated WAN Node 2)
	dir2 := filepath.Join(tempBase, "node_wan_2")
	node2, err := network.NewNodeService(ctx, network.NodeConfig{
		DataDir: dir2,
		ListenAddrs: []string{
			"/ip4/127.0.0.1/tcp/0",
			"/ip4/127.0.0.1/udp/0/quic-v1",
		},
		EnableAutoNAT: true,
		EnableRelay:   true,
	})
	if err != nil {
		t.Fatalf("failed starting Node 2: %v", err)
	}
	defer node2.Close()

	// 3. Test PingPeer against Node 1 and Node 2
	addr1 := node1.Multiaddrs()[0]
	rtt1, peerID1, err := network.PingPeer(ctx, addr1)
	if err != nil {
		t.Fatalf("PingPeer to Node 1 failed: %v", err)
	}
	t.Logf("Ping to Node 1 (%s): %v, PeerID: %s", addr1, rtt1, peerID1)
	if peerID1 != node1.Host.ID() {
		t.Fatalf("Peer ID mismatch: got %s, want %s", peerID1, node1.Host.ID())
	}

	addr2 := node2.Multiaddrs()[0]
	rtt2, peerID2, err := network.PingPeer(ctx, addr2)
	if err != nil {
		t.Fatalf("PingPeer to Node 2 failed: %v", err)
	}
	t.Logf("Ping to Node 2 (%s): %v, PeerID: %s", addr2, rtt2, peerID2)

	// 4. Create ClientSession connected to both nodes
	cs, err := network.NewClientSession(ctx, []string{addr1, addr2})
	if err != nil {
		t.Fatalf("failed to create ClientSession: %v", err)
	}
	defer cs.Close()

	if len(cs.Peers) != 2 {
		t.Fatalf("expected 2 connected peers, got %d", len(cs.Peers))
	}

	// 5. Ingest a test file through the client pipeline
	secret, err := crypto.GenerateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := crypto.DeriveKeyring(secret)
	if err != nil {
		t.Fatal(err)
	}

	pipeline, err := object.NewPipeline(keyring, 256*1024, 0) // 256 KiB chunks
	if err != nil {
		t.Fatal(err)
	}

	originalData := make([]byte, 512*1024) // 512 KiB (exactly 2 chunks, 20 shards total)
	if _, err := io.ReadFull(rand.Reader, originalData); err != nil {
		t.Fatal(err)
	}
	expectedHash := blake3.Sum256(originalData)

	manifest, chunks, err := pipeline.Ingest(bytes.NewReader(originalData), "test_wan_document.pdf")
	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}

	// 6. Distribute shards across the two nodes over the wire
	t.Log("Distributing shards to Node 1 and Node 2 across the network...")
	for _, chunk := range chunks {
		var shards []erasure.Shard
		var routingIDs []string
		for _, s := range chunk.Shards {
			shards = append(shards, s)
			routingIDs = append(routingIDs, chunk.Ref.Shards[s.Index].RoutingID)
		}
		if err := cs.DistributeAllShards(ctx, shards, routingIDs, 3600); err != nil {
			t.Fatalf("DistributeAllShards failed: %v", err)
		}
	}

	// 7. Verify both nodes received shards
	u1, c1, _ := node1.DB.TotalUsage()
	u2, c2, _ := node2.DB.TotalUsage()
	t.Logf("Node 1 holds: %d shards (%d bytes)", c1, u1)
	t.Logf("Node 2 holds: %d shards (%d bytes)", c2, u2)
	if c1 == 0 || c2 == 0 {
		t.Fatalf("expected shards on both nodes, got Node 1: %d, Node 2: %d", c1, c2)
	}
	if c1+c2 != 20 {
		t.Fatalf("expected 20 total shards stored across nodes, got %d", c1+c2)
	}

	// 8. Test ProbeShard (Zero-Knowledge possession challenge over network)
	firstRoutingID := chunks[0].Ref.Shards[0].RoutingID
	firstChecksum := chunks[0].Shards[0].Checksum
	has, holderID, err := cs.ProbeShard(ctx, firstRoutingID, firstChecksum)
	if err != nil {
		t.Fatalf("ProbeShard error: %v", err)
	}
	if !has {
		t.Fatal("ProbeShard returned false for existing shard")
	}
	t.Logf("ProbeShard confirmed shard possession on peer: %s", holderID)

	// 9. Reconstruct file from the swarm over the wire
	var reconstructed bytes.Buffer
	getter := func(routingID string) (*erasure.Shard, error) {
		return cs.FetchShard(ctx, routingID)
	}

	if err := pipeline.Reconstruct(&reconstructed, manifest, getter); err != nil {
		t.Fatalf("Reconstruct failed: %v", err)
	}

	// 10. Verify byte-perfect recovery
	recoveredHash := blake3.Sum256(reconstructed.Bytes())
	if recoveredHash != expectedHash {
		t.Fatalf("recovered file hash mismatch!\nGot:  %x\nWant: %x", recoveredHash, expectedHash)
	}
	t.Log("SUCCESS: 512 KiB file chunked, encrypted, erasure-coded, distributed across WAN nodes, probed, and reconstructed byte-perfect over network streams!")
}
