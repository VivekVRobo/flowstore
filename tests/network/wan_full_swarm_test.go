package network_test

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

	"flowstore/internal/catalog"
	"flowstore/internal/crypto"
	"flowstore/internal/erasure"
	"flowstore/internal/network"
	"flowstore/internal/object"
	"lukechampine.com/blake3"
)

func TestWANFullSwarmIngestKillNodeAndSecretRestore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tempBase, err := os.MkdirTemp("", "flowstore_full_wan_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempBase)

	// 1. Start 3 independent storage peer nodes
	var nodes []*network.NodeService
	var peerAddrs []string

	for i := 1; i <= 3; i++ {
		nodeDir := filepath.Join(tempBase, fmt.Sprintf("peer_%d", i))
		svc, err := network.NewNodeService(ctx, network.NodeConfig{
			DataDir: nodeDir,
			ListenAddrs: []string{
				"/ip4/127.0.0.1/tcp/0",
				"/ip4/127.0.0.1/udp/0/quic-v1",
			},
			EnableAutoNAT: true,
			EnableRelay:   true,
		})
		if err != nil {
			t.Fatalf("failed starting peer %d: %v", i, err)
		}
		defer svc.Close()
		nodes = append(nodes, svc)
		peerAddrs = append(peerAddrs, svc.Multiaddrs()[0])
	}

	t.Logf("Initialized %d storage peers on network ports", len(nodes))

	// 2. Client Identity & Master Recovery Secret
	secret, err := crypto.GenerateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	recoveryCode := crypto.FormatRecoveryCode(secret)
	keyring, err := crypto.DeriveKeyring(secret)
	if err != nil {
		t.Fatal(err)
	}
	id := crypto.NewIdentityFromPrivateKey(keyring.IdentityPriv)

	t.Logf("Client Master Secret: %s", recoveryCode)
	t.Logf("Client Node ID:       %s", id.NodeID())

	// 3. Connect Client to Swarm
	cs, err := network.NewClientSession(ctx, peerAddrs)
	if err != nil {
		t.Fatalf("ClientSession failed: %v", err)
	}
	defer cs.Close()

	// 4. Create and ingest 2 distinct test files
	file1Data := make([]byte, 128*1024)
	io.ReadFull(rand.Reader, file1Data)
	file1Hash := blake3.Sum256(file1Data)

	file2Data := make([]byte, 256*1024)
	io.ReadFull(rand.Reader, file2Data)
	file2Hash := blake3.Sum256(file2Data)

	pipeline, err := object.NewPipeline(keyring, 64*1024, 0) // 64 KiB chunks
	if err != nil {
		t.Fatal(err)
	}

	m1, chunks1, err := pipeline.Ingest(bytes.NewReader(file1Data), "whitepaper.pdf")
	if err != nil {
		t.Fatalf("ingest file 1 failed: %v", err)
	}
	m2, chunks2, err := pipeline.Ingest(bytes.NewReader(file2Data), "credentials.enc")
	if err != nil {
		t.Fatalf("ingest file 2 failed: %v", err)
	}

	// 5. Distribute shards across the 3 peers over network streams
	for _, chunk := range append(chunks1, chunks2...) {
		var shards []erasure.Shard
		var rIDs []string
		for _, s := range chunk.Shards {
			shards = append(shards, s)
			rIDs = append(rIDs, chunk.Ref.Shards[s.Index].RoutingID)
		}
		if err := cs.DistributeAllShards(ctx, shards, rIDs, 86400); err != nil {
			t.Fatalf("DistributeAllShards failed: %v", err)
		}
	}

	// 6. Register in Encrypted Catalog and Distribute Catalog Shards
	cat := catalog.NewCatalog(id.NodeID())
	cat.AddFile(m1)
	cat.AddFile(m2)

	if err := catalog.DistributeCatalog(ctx, cs.Host, nil, cat, keyring, cs.PeerIDs(), 0); err != nil {
		t.Fatalf("DistributeCatalog failed: %v", err)
	}
	t.Log("Encrypted catalog and file shards successfully distributed across peers.")

	// 7. Verify all 3 peers hold shards
	for i, n := range nodes {
		u, c, _ := n.DB.TotalUsage()
		t.Logf("Peer %d holds: %d shards (%d bytes)", i+1, c, u)
		if c == 0 {
			t.Fatalf("Peer %d holds 0 shards", i+1)
		}
	}

	// 8. Probe Possession Proofs
	probeRoutingID := chunks1[0].Ref.Shards[0].RoutingID
	probeChecksum := chunks1[0].Shards[0].Checksum
	has, peerID, err := cs.ProbeShard(ctx, probeRoutingID, probeChecksum)
	if err != nil || !has {
		t.Fatalf("ProbeShard failed: has=%v, err=%v", has, err)
	}
	t.Logf("Cryptographic possession verified for shard %s on peer %s", probeRoutingID[:12], peerID)

	// 9. SIMULATE CATASTROPHIC NODE DEATH: Stop Peer 1 completely
	t.Log("Simulating catastrophic failure: Shutting down Peer 1...")
	nodes[0].Close()

	// Remaining peers: Peer 2 and Peer 3
	survivingPeerAddrs := peerAddrs[1:]

	// 10. SIMULATE CLEAN MACHINE DISCOVERY & RECOVERY:
	// A new, completely clean client machine powers on with ZERO disk state,
	// knowing ONLY the 256-bit Master Secret (recoveryCode) and the survivor peer addresses.
	t.Log("Starting Root Secret restoration on a clean client machine...")
	cleanClient, err := network.NewClientSession(ctx, survivingPeerAddrs)
	if err != nil {
		t.Fatalf("clean client connection failed: %v", err)
	}
	defer cleanClient.Close()

	recoveredCat, cleanKeyring, err := catalog.RecoverCatalogFromSecret(ctx, cleanClient.Host, nil, recoveryCode, 0, cleanClient.PeerIDs())
	if err != nil {
		t.Fatalf("RecoverCatalogFromSecret failed: %v", err)
	}

	t.Logf("Recovered Catalog: Owner=%s, Version=%d, Files=%d", recoveredCat.OwnerID, recoveredCat.Version, len(recoveredCat.Files))
	if len(recoveredCat.Files) != 2 {
		t.Fatalf("expected 2 files in catalog, got %d", len(recoveredCat.Files))
	}

	// 11. Reconstruct all files from the surviving swarm peers
	cleanGetter := func(routingID string) (*erasure.Shard, error) {
		return cleanClient.FetchShard(ctx, routingID)
	}

	for fileName, expectedHash := range map[string][32]byte{
		"whitepaper.pdf":  file1Hash,
		"credentials.enc": file2Hash,
	} {
		entry, err := recoveredCat.GetFile(fileName)
		if err != nil {
			t.Fatalf("missing file %s: %v", fileName, err)
		}

		cleanPipeline, err := object.NewPipeline(cleanKeyring, entry.Manifest.ChunkSize, 0)
		if err != nil {
			t.Fatal(err)
		}

		var reconstructed bytes.Buffer
		if err := cleanPipeline.Reconstruct(&reconstructed, entry.Manifest, cleanGetter); err != nil {
			t.Fatalf("failed reconstructing %s: %v", fileName, err)
		}

		recHash := blake3.Sum256(reconstructed.Bytes())
		if recHash != expectedHash {
			t.Fatalf("recovered file hash mismatch for %s!\nGot:  %x\nWant: %x", fileName, recHash, expectedHash)
		}
		t.Logf("SUCCESS: Reconstructed %s byte-perfect (%d bytes) from surviving peers!", fileName, reconstructed.Len())
	}
}
