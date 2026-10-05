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

func TestLeaseExpiryEnforcedOnReadPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	base, err := os.MkdirTemp("", "flowstore_gc_read_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)

	server, err := network.NewNodeService(ctx, network.NodeConfig{
		DataDir:     filepath.Join(base, "server"),
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		EnableDHT:   false,
		GCInterval:  -1, // disable background GC; read path must still enforce
	})
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	target := server.Host.ID()

	engine, err := erasure.DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}
	shards, err := engine.Encode([]byte("short-lease-payload"))
	if err != nil {
		t.Fatal(err)
	}
	routingID := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := network.SendStoreShard(ctx, clientHost, target, routingID, shards[0], 1); err != nil {
		t.Fatalf("store failed: %v", err)
	}

	// Immediately present.
	if _, err := network.FetchShard(ctx, clientHost, target, routingID); err != nil {
		t.Fatalf("immediate fetch failed: %v", err)
	}

	// After lease passes, Get/Probe/Repair must treat it as missing even
	// before background GC runs. Read path cleans the expired entry.
	time.Sleep(1100 * time.Millisecond)
	if _, err := network.FetchShard(ctx, clientHost, target, routingID); err == nil {
		t.Fatal("expected fetch to fail after lease expiry")
	}
	resp, err := network.RequestRepair(ctx, clientHost, target, []string{routingID}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Held) != 0 || len(resp.Missing) != 1 {
		t.Fatalf("expected expired shard to be missing, got %+v", resp)
	}

	// Second shard proves manual GC reclaims without a prior read.
	routingGC := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	shards2, err := engine.Encode([]byte("gc-reclaim-payload-2"))
	if err != nil {
		t.Fatal(err)
	}
	if err := network.SendStoreShard(ctx, clientHost, target, routingGC, shards2[0], 1); err != nil {
		t.Fatalf("store for GC failed: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	stats, err := server.RunGCOnce()
	if err != nil {
		t.Fatal(err)
	}
	if stats.ExpiredRemoved != 1 {
		t.Fatalf("expected 1 expired reclaimed, got %+v", stats)
	}
}
