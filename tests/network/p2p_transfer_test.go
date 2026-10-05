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
	"github.com/libp2p/go-libp2p/core/peer"
	"lukechampine.com/blake3"
)

func TestP2PShardTransferAndProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tempBase, err := os.MkdirTemp("", "flowstore_p2p_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempBase)

	// 1. Start Storage Peer Node A
	nodeADir := filepath.Join(tempBase, "node_a")
	nodeA, err := network.NewNodeService(ctx, network.NodeConfig{
		DataDir:     nodeADir,
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatalf("failed to start Node A: %v", err)
	}
	defer nodeA.Close()

	// 2. Start Storage Peer Node B
	nodeBDir := filepath.Join(tempBase, "node_b")
	nodeB, err := network.NewNodeService(ctx, network.NodeConfig{
		DataDir:     nodeBDir,
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatalf("failed to start Node B: %v", err)
	}
	defer nodeB.Close()

	// 3. Start Client Node (Client only needs a libp2p host)
	clientHost, err := network.NewHost(ctx, network.Config{
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatalf("failed to start client host: %v", err)
	}
	defer clientHost.Close()

	// Connect Client to Node A and Node B
	if err := clientHost.Connect(ctx, nodeA.AddrInfo()); err != nil {
		t.Fatalf("failed to connect to Node A: %v", err)
	}
	if err := clientHost.Connect(ctx, nodeB.AddrInfo()); err != nil {
		t.Fatalf("failed to connect to Node B: %v", err)
	}

	// 4. Generate test shard
	payload := make([]byte, 128*1024) // 128 KiB shard
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatal(err)
	}
	checksum := blake3.Sum256(payload)

	shard := erasure.Shard{
		Index:        2,
		Data:         payload,
		Checksum:     checksum,
		OriginalSize: 512 * 1024,
	}
	routingID := "ab12cd34ef567890ab12cd34ef567890ab12cd34ef567890ab12cd34ef567890"

	// 5. Test ProtocolStore: Client -> Node A
	t.Log("Testing /flowstore/store/1.0: Uploading shard to Node A...")
	if err := network.SendStoreShard(ctx, clientHost, nodeA.Host.ID(), routingID, shard, 86400); err != nil {
		t.Fatalf("SendStoreShard failed: %v", err)
	}

	// Verify Node A now has shard in storage and SQLite DB
	if !nodeA.Store.Has(routingID) {
		t.Fatal("Node A does not have shard in store after successful upload")
	}
	meta, err := nodeA.DB.GetShardMeta(routingID)
	if err != nil {
		t.Fatalf("Node A DB missing shard record: %v", err)
	}
	if meta.Size != int64(len(payload)) {
		t.Fatalf("Node A recorded size mismatch: %d != %d", meta.Size, len(payload))
	}

	// 6. Test ProtocolProbe: Client challenges Node A to prove possession
	t.Log("Testing /flowstore/probe/1.0: Executing proof-of-possession challenge against Node A...")
	var nonce [32]byte
	io.ReadFull(rand.Reader, nonce[:])

	hasValidProof, err := network.ProbeShard(ctx, clientHost, nodeA.Host.ID(), routingID, nonce, checksum)
	if err != nil {
		t.Fatalf("ProbeShard returned error: %v", err)
	}
	if !hasValidProof {
		t.Fatal("ProbeShard returned false for existing shard")
	}
	t.Log("SUCCESS: Node A verified possession with valid cryptographic proof without sending payload!")

	// Probing Node B for same routingID should return false (Node B does not hold it)
	hasOnB, err := network.ProbeShard(ctx, clientHost, nodeB.Host.ID(), routingID, nonce, checksum)
	if err != nil {
		t.Fatalf("ProbeShard on Node B failed: %v", err)
	}
	if hasOnB {
		t.Fatal("Node B falsely claimed to possess shard")
	}

	// 7. Test ProtocolGet: Client fetches shard from Node A
	t.Log("Testing /flowstore/get/1.0: Fetching shard from Node A...")
	fetchedShard, err := network.FetchShard(ctx, clientHost, nodeA.Host.ID(), routingID)
	if err != nil {
		t.Fatalf("FetchShard failed: %v", err)
	}

	if fetchedShard.Index != shard.Index {
		t.Fatalf("index mismatch: %d != %d", fetchedShard.Index, shard.Index)
	}
	if fetchedShard.Checksum != shard.Checksum {
		t.Fatalf("checksum mismatch: %x != %x", fetchedShard.Checksum, shard.Checksum)
	}
	if !bytes.Equal(fetchedShard.Data, shard.Data) {
		t.Fatal("fetched shard data does not match uploaded payload")
	}
	t.Log("SUCCESS: Byte-perfect shard fetched over libp2p stream!")
}

func TestKademliaDHTDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tempBase, err := os.MkdirTemp("", "flowstore_dht_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempBase)

	// 1. Node 1: Bootstrap DHT Server Node
	node1Dir := filepath.Join(tempBase, "dht_node_1")
	node1, err := network.NewNodeService(ctx, network.NodeConfig{
		DataDir:       node1Dir,
		ListenAddrs:   []string{"/ip4/127.0.0.1/tcp/0"},
		EnableDHT:     true,
		DHTServerMode: true,
	})
	if err != nil {
		t.Fatalf("failed to start DHT Node 1: %v", err)
	}
	defer node1.Close()

	// 2. Node 2: Storage Peer connected to Node 1
	node2Dir := filepath.Join(tempBase, "dht_node_2")
	node2, err := network.NewNodeService(ctx, network.NodeConfig{
		DataDir:        node2Dir,
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		EnableDHT:      true,
		DHTServerMode:  true,
		BootstrapPeers: []peer.AddrInfo{node1.AddrInfo()},
	})
	if err != nil {
		t.Fatalf("failed to start DHT Node 2: %v", err)
	}
	defer node2.Close()

	// 3. Node 3: Querying Client connected to Node 1
	node3Dir := filepath.Join(tempBase, "dht_node_3")
	node3, err := network.NewNodeService(ctx, network.NodeConfig{
		DataDir:        node3Dir,
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		EnableDHT:      true,
		DHTServerMode:  true,
		BootstrapPeers: []peer.AddrInfo{node1.AddrInfo()},
	})
	if err != nil {
		t.Fatalf("failed to start DHT Node 3: %v", err)
	}
	defer node3.Close()

	// Wait for DHT routing tables to populate
	time.Sleep(500 * time.Millisecond)

	// 4. Node 2 hosts a shard and announces itself as provider on the DHT
	routingSecret, _ := crypto.GenerateMasterSecret()
	routingID := crypto.DeriveRoutingID(routingSecret, []byte("dht-test-object"), 0, 1, 0)

	t.Logf("Node 2 announcing shard %s on Kademlia DHT...", routingID)
	if err := node2.DHT.Provide(ctx, routingID); err != nil {
		t.Fatalf("Node 2 failed to provide shard: %v", err)
	}

	// 5. Node 3 discovers provider for routingID using the DHT
	t.Log("Node 3 discovering providers on DHT...")
	providers, err := node3.DHT.FindProviders(ctx, routingID, 1)
	if err != nil {
		t.Fatalf("FindProviders failed: %v", err)
	}

	foundNode2 := false
	for _, p := range providers {
		if p.ID == node2.Host.ID() {
			foundNode2 = true
			break
		}
	}

	if !foundNode2 {
		t.Fatalf("Node 3 failed to find Node 2 as provider among %d providers", len(providers))
	}
	t.Log("SUCCESS: Node 3 successfully discovered Node 2 as provider of shard via Kademlia DHT!")
}

func TestDiscoveryClientFetchesUnconnectedProviderFromSingleBootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tempBase, err := os.MkdirTemp("", "flowstore_single_bootstrap_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempBase)

	bootstrap, err := network.NewNodeService(ctx, network.NodeConfig{
		DataDir:       filepath.Join(tempBase, "bootstrap"),
		ListenAddrs:   []string{"/ip4/127.0.0.1/tcp/0"},
		EnableDHT:     true,
		DHTServerMode: true,
	})
	if err != nil {
		t.Fatalf("start bootstrap peer: %v", err)
	}
	defer bootstrap.Close()

	provider, err := network.NewNodeService(ctx, network.NodeConfig{
		DataDir:        filepath.Join(tempBase, "provider"),
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		EnableDHT:      true,
		DHTServerMode:  true,
		BootstrapPeers: []peer.AddrInfo{bootstrap.AddrInfo()},
	})
	if err != nil {
		t.Fatalf("start shard provider: %v", err)
	}
	defer provider.Close()

	// The fresh client receives exactly one address: the bootstrap peer. It
	// must discover the provider through DHT rather than a preloaded peer list.
	bootstrapAddr := bootstrap.Multiaddrs()[0]
	client, err := network.NewDiscoveryClientSession(ctx, []string{bootstrapAddr})
	if err != nil {
		t.Fatalf("start fresh discovery client: %v", err)
	}
	defer client.Close()
	if len(client.Peers) != 1 || client.Peers[0].ID != bootstrap.Host.ID() {
		t.Fatalf("fresh client should know only bootstrap peer %s; got %v", bootstrap.Host.ID(), client.PeerIDs())
	}

	data := make([]byte, 128*1024)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatal(err)
	}
	shard := erasure.Shard{
		Index:        4,
		Data:         data,
		Checksum:     blake3.Sum256(data),
		OriginalSize: uint64(len(data)),
	}
	routingID := "d7f400ec583c8b6bd7f400ec583c8b6bd7f400ec583c8b6bd7f400ec583c8b6b"

	if err := provider.Store.Put(routingID, shard); err != nil {
		t.Fatalf("store shard at non-bootstrap provider: %v", err)
	}
	if err := provider.DHT.Provide(ctx, routingID); err != nil {
		t.Fatalf("announce shard provider on DHT: %v", err)
	}

	fetched, err := client.FetchShard(ctx, routingID)
	if err != nil {
		t.Fatalf("fresh client could not discover and fetch provider shard: %v", err)
	}
	if fetched.Index != shard.Index || fetched.Checksum != shard.Checksum || !bytes.Equal(fetched.Data, shard.Data) {
		t.Fatal("fresh-client DHT recovery returned a shard that differs from the stored shard")
	}
}
