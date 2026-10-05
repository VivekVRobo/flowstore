package network_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"flowstore/internal/erasure"
	"flowstore/internal/network"
)

func TestDeleteAndRepairProtocols(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	base, err := os.MkdirTemp("", "flowstore_delete_repair_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)

	server, err := network.NewNodeService(ctx, network.NodeConfig{
		DataDir:     filepath.Join(base, "server"),
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		EnableDHT:   false,
	})
	if err != nil {
		t.Fatalf("NewNodeService failed: %v", err)
	}
	defer server.Close()

	clientHost, err := network.NewHost(ctx, network.Config{
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientHost.Close()

	if err := clientHost.Connect(ctx, server.AddrInfo()); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	target := server.Host.ID()

	// Store a verifiable shard directly through the store protocol.
	engine, err := erasure.DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}
	shards, err := engine.Encode([]byte("delete-repair-alignment-payload"))
	if err != nil {
		t.Fatal(err)
	}
	routingID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := network.SendStoreShard(ctx, clientHost, target, routingID, shards[0], 3600); err != nil {
		t.Fatalf("SendStoreShard failed: %v", err)
	}

	// Repair coordination should report the shard as held with usage stats.
	resp, err := network.RequestRepair(ctx, clientHost, target, []string{routingID, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, false)
	if err != nil {
		t.Fatalf("RequestRepair failed: %v", err)
	}
	if len(resp.Held) != 1 || resp.Held[0] != routingID {
		t.Fatalf("expected held=[%s], got %+v", routingID, resp)
	}
	if len(resp.Missing) != 1 {
		t.Fatalf("expected 1 missing entry, got %+v", resp)
	}
	if resp.ShardCount < 1 || resp.UsedBytes <= 0 {
		t.Fatalf("expected positive shard count/usage, got %+v", resp)
	}

	// Delete must be idempotent and clean the index.
	existed, err := network.SendDeleteShard(ctx, clientHost, target, routingID)
	if err != nil {
		t.Fatalf("SendDeleteShard failed: %v", err)
	}
	if !existed {
		t.Fatal("expected first delete to report existed=true")
	}
	existed, err = network.SendDeleteShard(ctx, clientHost, target, routingID)
	if err != nil {
		t.Fatalf("second SendDeleteShard failed: %v", err)
	}
	if existed {
		t.Fatal("expected second delete to report existed=false")
	}

	after, err := network.RequestRepair(ctx, clientHost, target, []string{routingID}, false)
	if err != nil {
		t.Fatalf("post-delete RequestRepair failed: %v", err)
	}
	if len(after.Held) != 0 || len(after.Missing) != 1 {
		t.Fatalf("expected shard to be missing after delete, got %+v", after)
	}

	// Empty routing ID must be rejected, oversized check lists rejected.
	if _, err := network.SendDeleteShard(ctx, clientHost, target, ""); err == nil {
		t.Fatal("expected empty routing ID delete to fail")
	}
	huge := make([]string, 1001)
	if _, err := network.RequestRepair(ctx, clientHost, target, huge, false); err == nil {
		t.Fatal("expected oversized repair check to fail")
	}
}
