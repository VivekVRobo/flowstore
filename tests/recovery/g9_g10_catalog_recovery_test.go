package recovery_test

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
	"github.com/libp2p/go-libp2p/core/peer"
	"lukechampine.com/blake3"
)

func TestG9G10CatalogDistributionAndRootSecretRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tempBase, err := os.MkdirTemp("", "flowstore_g9_g10_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempBase)

	// 1. Setup Swarm: 10 independent P2P storage peer nodes
	numPeers := 10
	peerNodes := make([]*network.NodeService, numPeers)
	peerIDs := make([]peer.ID, numPeers)

	for i := 0; i < numPeers; i++ {
		pDir := filepath.Join(tempBase, fmt.Sprintf("swarm_peer_%02d", i))
		node, err := network.NewNodeService(ctx, network.NodeConfig{
			DataDir:     pDir,
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		})
		if err != nil {
			t.Fatalf("failed to start peer %d: %v", i, err)
		}
		defer node.Close()
		peerNodes[i] = node
		peerIDs[i] = node.Host.ID()
	}

	// =========================================================================
	// PHASE I: PC #1 (The Uploader Machine)
	// =========================================================================
	t.Log("--- PHASE I: PC #1 Ingestion & Swarm Distribution ---")
	pc1Host, err := network.NewHost(ctx, network.Config{
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatalf("failed to start PC #1 host: %v", err)
	}

	// Connect PC #1 to swarm peers
	for _, node := range peerNodes {
		if err := pc1Host.Connect(ctx, node.AddrInfo()); err != nil {
			t.Fatalf("PC #1 failed to connect to peer %s: %v", node.Host.ID(), err)
		}
	}

	// Generate Master Recovery Secret
	masterSecret, _ := crypto.GenerateMasterSecret()
	recoveryCode := crypto.FormatRecoveryCode(masterSecret)
	t.Logf("PC #1 Generated Master Recovery Secret: %s", recoveryCode)

	keyring1, _ := crypto.DeriveKeyring(masterSecret)
	id1 := crypto.NewIdentityFromPrivateKey(keyring1.IdentityPriv)
	cat1 := catalog.NewCatalog(id1.NodeID())

	// Create test files
	file1Data := make([]byte, 256*1024) // 256 KiB
	file2Data := make([]byte, 512*1024) // 512 KiB
	file3Data := []byte("FlowStore autonomous peer-to-peer virtual filesystem without central servers.")
	io.ReadFull(rand.Reader, file1Data)
	io.ReadFull(rand.Reader, file2Data)

	filesToUpload := map[string][]byte{
		"robotics/arm-design.step": file1Data,
		"research/slam-survey.pdf": file2Data,
		"notes/swarm-protocol.txt": file3Data,
	}

	pipeline1, _ := object.NewPipeline(keyring1, 128*1024, 0) // 128 KiB chunks

	// Ingest and upload each file
	for path, data := range filesToUpload {
		m, encodedChunks, err := pipeline1.Ingest(bytes.NewReader(data), path)
		if err != nil {
			t.Fatalf("failed to ingest %s: %v", path, err)
		}

		// Distribute shards across the 10 peers (shard i -> peer i)
		for _, chunk := range encodedChunks {
			for _, shard := range chunk.Shards {
				targetPeer := peerNodes[shard.Index]
				sRef := chunk.Ref.Shards[shard.Index]

				if err := network.SendStoreShard(ctx, pc1Host, targetPeer.Host.ID(), sRef.RoutingID, shard, 365*24*3600); err != nil {
					t.Fatalf("failed to store shard %d of %s: %v", shard.Index, path, err)
				}
			}
		}

		cat1.AddFile(m)
	}

	// Distribute root catalog shards across the swarm peers
	if err := catalog.DistributeCatalog(ctx, pc1Host, nil, cat1, keyring1, peerIDs, 0); err != nil {
		t.Fatalf("failed to distribute catalog shards to swarm: %v", err)
	}
	t.Logf("PC #1 distributed %d files and the encrypted root catalog into the swarm.", len(filesToUpload))

	// =========================================================================
	// PHASE II: COMPLETE DESTRUCTION OF PC #1
	// =========================================================================
	t.Log("--- PHASE II: PC #1 IS COMPLETELY DESTROYED ---")
	_ = pc1Host.Close()
	pc1Host = nil
	keyring1 = nil
	cat1 = nil
	pipeline1 = nil
	// All local files, variables, and in-memory caches of PC #1 are gone!
	// ONLY recoveryCode ("FLOW-XXXX-...") is remembered by the human user.

	// =========================================================================
	// PHASE III: CATASTROPHIC SWARM FAILURE (40% NODE LOSS)
	// =========================================================================
	t.Log("--- PHASE III: Catastrophic Swarm Failure (Killing 4 of 10 Peers) ---")
	killedPeerIndices := []int{1, 4, 7, 9}
	for _, idx := range killedPeerIndices {
		t.Logf("Permanently destroying Peer %d (%s)...", idx, peerNodes[idx].Host.ID())
		peerNodes[idx].Close()
	}

	var survivingPeerIDs []peer.ID
	var survivingNodes []*network.NodeService
	for i, node := range peerNodes {
		isKilled := false
		for _, k := range killedPeerIndices {
			if i == k {
				isKilled = true
				break
			}
		}
		if !isKilled {
			survivingPeerIDs = append(survivingPeerIDs, node.Host.ID())
			survivingNodes = append(survivingNodes, node)
		}
	}
	t.Logf("Swarm health: exactly 6 peers survive out of 10.")

	// =========================================================================
	// PHASE IV: PC #2 (A BRAND NEW, CLEAN WINDOWS COMPUTER)
	// =========================================================================
	t.Log("--- PHASE IV: Clean PC #2 Recovers Everything From Root Secret ---")
	pc2Host, err := network.NewHost(ctx, network.Config{
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatalf("failed to start PC #2 host: %v", err)
	}
	defer pc2Host.Close()

	// Connect PC #2 to surviving peers
	for _, node := range survivingNodes {
		if err := pc2Host.Connect(ctx, node.AddrInfo()); err != nil {
			t.Fatalf("PC #2 failed to connect to surviving peer: %v", err)
		}
	}

	// PC #2 inputs ONLY the human recoveryCode
	recoveredCatalog, keyring2, err := catalog.RecoverCatalogFromSecret(
		ctx,
		pc2Host,
		nil,
		recoveryCode,
		0,
		survivingPeerIDs,
	)
	if err != nil {
		t.Fatalf("PC #2 failed to recover catalog from root secret: %v", err)
	}

	t.Log("SUCCESS (Gate G9 & G10): Catalog reconstructed and decrypted from root secret under 40% swarm loss!")

	// Verify all original files appear in the recovered catalog
	fileList := recoveredCatalog.ListFiles()
	t.Logf("PC #2 Recovered Catalog Files: %v", fileList)

	if len(fileList) != len(filesToUpload) {
		t.Fatalf("expected %d files in catalog, got %d", len(filesToUpload), len(fileList))
	}

	// PC #2 now stream-reconstructs each file on demand from the surviving swarm
	pipeline2, _ := object.NewPipeline(keyring2, 128*1024, 0)

	for path, expectedBytes := range filesToUpload {
		entry, err := recoveredCatalog.GetFile(path)
		if err != nil {
			t.Fatalf("failed to get catalog entry for %s: %v", path, err)
		}

		getter := func(routingID string) (*erasure.Shard, error) {
			for _, node := range survivingNodes {
				fetchCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				shard, err := network.FetchShard(fetchCtx, pc2Host, node.Host.ID(), routingID)
				cancel()
				if err == nil && shard != nil {
					return shard, nil
				}
			}
			return nil, fmt.Errorf("shard %s not found on surviving peers", routingID)
		}

		var fileBuf bytes.Buffer
		if err := pipeline2.Reconstruct(&fileBuf, entry.Manifest, getter); err != nil {
			t.Fatalf("PC #2 failed to reconstruct file %s: %v", path, err)
		}

		recoveredData := fileBuf.Bytes()
		if !bytes.Equal(expectedBytes, recoveredData) {
			t.Fatalf("file %s recovered bytes do not match original", path)
		}

		origHash := blake3.Sum256(expectedBytes)
		recHash := blake3.Sum256(recoveredData)
		if origHash != recHash {
			t.Fatalf("BLAKE3 hash mismatch on %s", path)
		}
		t.Logf("✓ File '%s' (%d bytes) verified byte-perfect on PC #2!", path, len(recoveredData))
	}

	t.Log("=========================================================================")
	t.Log("MILESTONE V0.5 ACHIEVED: Complete zero-knowledge, zero-central-server swarm!")
	t.Log("Data exists across the Internet, follows no permanent home, and restores")
	t.Log("completely onto a new machine from the root recovery secret alone.")
	t.Log("=========================================================================")
}
