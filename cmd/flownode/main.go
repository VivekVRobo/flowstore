package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"flowstore/internal/network"
	"flowstore/internal/storage"
	"github.com/libp2p/go-libp2p/core/peer"
)

func main() {
	dataDir := flag.String("dir", "./flownode-data", "Local directory for peer metadata and node database")
	shardDir := flag.String("shard-dir", "", "Optional shard-file directory on a separate filesystem (default <dir>/shards)")
	directShardWrite := flag.Bool("shard-direct-write", false, "Write shard files directly and mark them complete without rename (for mounted filesystems)")
	identityKeyPath := flag.String("identity-key", "", "Persistent libp2p Ed25519 private key path (default ~/.flowstore/node.key)")
	port := flag.Int("port", 41001, "Port to listen on (binds both TCP and QUIC across all interfaces)")
	customListen := flag.String("listen", "", "Optional custom libp2p listen multiaddress (e.g. /ip4/0.0.0.0/tcp/41001)")
	bootstrapAddr := flag.String("bootstrap", "", "Optional bootstrap peer multiaddress to connect to")
	quotaGB := flag.Int64("quota-gb", 50, "Maximum shard storage allocation in GiB (0 means unlimited)")
	enableDHT := flag.Bool("dht", true, "Enable Kademlia DHT server")
	enableUPnP := flag.Bool("upnp", true, "Enable UPnP/NAT-PMP automatic router port mapping")
	enableRelayService := flag.Bool("relay-service", false, "Act as a public Circuit Relay v2 for other peers")
	gcInterval := flag.Duration("gc-interval", network.DefaultGCInterval, "Lease expiry + reconciliation interval (0 disables background GC)")
	failureDomain := flag.String("failure-domain", "default", "Failure-domain tag (host/rack/region) advertised for placement diversity")
	flag.Parse()
	if *quotaGB < 0 || *quotaGB > math.MaxInt64/(1024*1024*1024) {
		fmt.Fprintln(os.Stderr, "Invalid --quota-gb: must be non-negative and fit in bytes")
		os.Exit(2)
	}

	absDir, err := filepath.Abs(*dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving directory: %v\n", err)
		os.Exit(1)
	}
	absShardDir := filepath.Join(absDir, "shards")
	if *shardDir != "" {
		absShardDir, err = filepath.Abs(*shardDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving shard directory: %v\n", err)
			os.Exit(1)
		}
	}

	if *identityKeyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving home directory for node identity: %v\n", err)
			os.Exit(1)
		}
		*identityKeyPath = filepath.Join(home, ".flowstore", "node.key")
	}
	identityPriv, err := loadOrCreateNodeIdentity(*identityKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading persistent node identity: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var listenAddrs []string
	if *customListen != "" {
		listenAddrs = []string{*customListen}
	} else {
		listenAddrs = []string{
			fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", *port),
			fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", *port),
		}
	}

	var bootstrapPeers []peer.AddrInfo
	if *bootstrapAddr != "" {
		maddr, err := network.ParseMultiaddr(*bootstrapAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid bootstrap multiaddr: %v\n", err)
			os.Exit(1)
		}
		info, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse bootstrap peer info: %v\n", err)
			os.Exit(1)
		}
		bootstrapPeers = append(bootstrapPeers, *info)
	}

	nodeConfig := network.NodeConfig{
		IdentityPriv:          identityPriv,
		DataDir:               absDir,
		ShardDir:              absShardDir,
		DirectWriteShardStore: *directShardWrite,
		QuotaBytes:            *quotaGB * 1024 * 1024 * 1024,
		ListenAddrs:           listenAddrs,
		EnableDHT:             *enableDHT,
		DHTServerMode:         *enableDHT,
		EnableUPnP:            *enableUPnP,
		EnableAutoNAT:         true,
		EnableRelay:           true,
		RelayService:          *enableRelayService,
		BootstrapPeers:        bootstrapPeers,
		GCInterval:            *gcInterval,
		FailureDomain:         *failureDomain,
	}

	svc, err := network.NewNodeService(ctx, nodeConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start flownode service: %v\n", err)
		os.Exit(1)
	}
	defer svc.Close()

	var usageBytes int64
	shardCount := 0
	if fileStore, ok := svc.Store.(*storage.FileShardStore); ok {
		usageBytes, _ = fileStore.UsageBytes()
		if routingIDs, err := fileStore.List(); err == nil {
			shardCount = len(routingIDs)
		}
	}
	usageMB := float64(usageBytes) / (1024 * 1024)

	fmt.Println("=================================================================")
	fmt.Println("             FLOWSTORE STORAGE PEER DAEMON (v0.5)               ")
	fmt.Println("=================================================================")
	fmt.Printf("Peer ID:            %s\n", svc.Host.ID().String())
	fmt.Printf("Metadata Directory: %s\n", absDir)
	fmt.Printf("Shard Directory:    %s\n", absShardDir)
	if *directShardWrite {
		fmt.Println("Shard Commit Mode:  direct write + completion marker")
	} else {
		fmt.Println("Shard Commit Mode:  atomic rename")
	}
	fmt.Printf("Storage Quota:      %d GB\n", *quotaGB)
	fmt.Printf("Current Stored:     %.2f MB (%d shards)\n", usageMB, shardCount)
	fmt.Printf("GC Interval:        %s\n", gcInterval.String())
	fmt.Printf("Failure Domain:     %s\n", *failureDomain)
	fmt.Printf("UPnP Port Mapping:  %v\n", *enableUPnP)
	fmt.Printf("AutoNAT & Relays:   Enabled\n")
	fmt.Printf("Circuit Relay Svc:  %v\n", *enableRelayService)
	fmt.Println("\nListening Multiaddresses (Share these with peers to connect):")
	for _, a := range svc.Multiaddrs() {
		fmt.Printf("  -> %s\n", a)
	}
	if len(bootstrapPeers) > 0 {
		fmt.Printf("\nConnected to bootstrap peer: %s\n", *bootstrapAddr)
	}
	fmt.Println("\nNode status:        ONLINE (Serving /flowstore/store, /flowstore/get, /flowstore/probe, /flowstore/delete, /flowstore/repair)")
	fmt.Println("Press Ctrl+C to terminate peer cleanly.")

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down FlowStore peer node...")
}

func loadOrCreateNodeIdentity(path string) (ed25519.PrivateKey, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create identity directory: %w", err)
	}

	key, err := readNodeIdentity(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	_, key, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 node identity: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		// Another daemon process created the key after our initial read.
		return readNodeIdentity(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create identity key file: %w", err)
	}
	created := true
	defer func() {
		if created {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write identity key file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("sync identity key file: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close identity key file: %w", err)
	}
	created = false
	return key, nil
}

func readNodeIdentity(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat identity key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("identity key path %s is not a regular file", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		if err := os.Chmod(path, 0600); err != nil {
			return nil, fmt.Errorf("restrict identity key file permissions: %w", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity key file: %w", err)
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("identity key file has %d bytes; expected %d", len(data), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(data), nil
}
