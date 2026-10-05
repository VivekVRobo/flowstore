package network

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"time"

	"flowstore/internal/storage"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// DefaultGCInterval reclaims expired leases every 5 minutes.
const DefaultGCInterval = 5 * time.Minute

// LeaseRenewalLead is the window in which an online node renews a live shard
// lease by its original duration. The DHT reprovider refreshes provider records
// independently of this storage lease.
const LeaseRenewalLead = 24 * time.Hour

const leaseRenewalBatchSize = 512

// NodeConfig specifies configuration for an autonomous storage peer node.
type NodeConfig struct {
	IdentityPriv ed25519.PrivateKey
	DataDir      string
	// ShardDir optionally places opaque shard files on a separate filesystem.
	// Node metadata (including node.db) remains in DataDir. An empty value keeps
	// the historical layout of DataDir/shards.
	ShardDir string
	// DirectWriteShardStore disables rename-based shard commits for mounted
	// filesystems. A completion marker distinguishes committed shards from
	// interrupted writes.
	DirectWriteShardStore bool
	QuotaBytes            int64
	ListenAddrs           []string
	EnableDHT             bool
	DHTServerMode         bool
	EnableUPnP            bool
	EnableAutoNAT         bool
	EnableRelay           bool
	RelayService          bool
	StaticRelays          []peer.AddrInfo
	BootstrapPeers        []peer.AddrInfo
	// GCInterval controls background lease expiry + reconciliation.
	// Zero means DefaultGCInterval; negative disables background GC.
	GCInterval time.Duration
	// FailureDomain advertises host/rack/region for placement diversity.
	FailureDomain string
}

// NodeService encapsulates a complete FlowStore P2P storage node.
type NodeService struct {
	Host     host.Host
	Store    storage.ShardStore
	DB       *storage.NodeDB
	Handler  *ProtocolHandler
	DHT      *ShardRouting
	Domain   string
	cancelFn context.CancelFunc
}

// NewNodeService initializes and starts a FlowStore peer node.
func NewNodeService(ctx context.Context, cfg NodeConfig) (*NodeService, error) {
	ctx, cancel := context.WithCancel(ctx)

	// 1. Shard Store & DB
	shardDir := cfg.ShardDir
	if shardDir == "" {
		shardDir = filepath.Join(cfg.DataDir, "shards")
	}
	var (
		store storage.ShardStore
		err   error
	)
	if cfg.DirectWriteShardStore {
		store, err = storage.NewDirectWriteShardStore(shardDir, cfg.QuotaBytes)
	} else {
		store, err = storage.NewFileShardStore(shardDir, cfg.QuotaBytes)
	}
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to init shard store: %w", err)
	}

	dbPath := filepath.Join(cfg.DataDir, "node.db")
	db, err := storage.OpenNodeDB(dbPath)
	if err != nil {
		store.Close()
		cancel()
		return nil, fmt.Errorf("failed to init node db: %w", err)
	}

	// 2. libp2p Host
	h, err := NewHost(ctx, Config{
		PrivateKey:    cfg.IdentityPriv,
		ListenAddrs:   cfg.ListenAddrs,
		EnableUPnP:    cfg.EnableUPnP,
		EnableAutoNAT: cfg.EnableAutoNAT,
		EnableRelay:   cfg.EnableRelay,
		RelayService:  cfg.RelayService,
		StaticRelays:  cfg.StaticRelays,
	})
	if err != nil {
		db.Close()
		store.Close()
		cancel()
		return nil, fmt.Errorf("failed to init libp2p host: %w", err)
	}

	// 3. Kademlia DHT
	var routing *ShardRouting
	if cfg.EnableDHT {
		r, err := NewShardRouting(ctx, h, cfg.DHTServerMode)
		if err != nil {
			h.Close()
			db.Close()
			store.Close()
			cancel()
			return nil, fmt.Errorf("failed to init DHT: %w", err)
		}
		routing = r

		if len(cfg.BootstrapPeers) > 0 {
			if err := routing.Bootstrap(ctx, cfg.BootstrapPeers); err != nil {
				_ = routing.Close()
				h.Close()
				db.Close()
				store.Close()
				cancel()
				return nil, fmt.Errorf("failed to join configured discovery DHT bootstrap peers: %w", err)
			}
		}
	}

	// 4. Register protocol handlers after routing is ready, so stored shards
	// can be announced by the peer that actually owns them.
	handler := NewProtocolHandler(h, store, db, routing)
	if cfg.FailureDomain != "" {
		handler.SetFailureDomain(cfg.FailureDomain)
	} else {
		handler.SetFailureDomain("default")
	}

	domain := cfg.FailureDomain
	if domain == "" {
		domain = "default"
	}
	svc := &NodeService{
		Host:     h,
		Store:    store,
		DB:       db,
		Handler:  handler,
		DHT:      routing,
		Domain:   domain,
		cancelFn: cancel,
	}

	// 5. Reconcile index and disk once at startup, then run background GC.
	// Startup sweep keeps quota and List() honest after crashes.
	_, _ = svc.RunGCOnce()
	gcInterval := cfg.GCInterval
	if cfg.GCInterval == 0 {
		gcInterval = DefaultGCInterval
	}
	if gcInterval > 0 {
		go svc.gcLoop(ctx, gcInterval)
	}

	return svc, nil
}

// gcLoop periodically expires leases and reconciles index and disk.
func (ns *NodeService) gcLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = ns.RunGCOnce()
		}
	}
}

// RunGCOnce expires leases and reconciles index and disk immediately.
func (ns *NodeService) RunGCOnce() (storage.GCStats, error) {
	now := time.Now().UTC()
	renewed, skipped, err := ns.renewExpiringLeases(now, LeaseRenewalLead)
	if err != nil {
		return storage.GCStats{}, err
	}
	stats, err := storage.CollectGarbage(ns.Store, ns.DB, now)
	if err != nil {
		return stats, err
	}
	stats.LeaseRenewed = renewed
	stats.LeaseRenewSkipped = skipped
	return stats, nil
}

// renewExpiringLeases keeps live, present shards from expiring while this node
// is online. Missing files are left for reconciliation rather than receiving
// a fresh lease. Batches bound metadata memory on large nodes.
func (ns *NodeService) renewExpiringLeases(now time.Time, lead time.Duration) (renewed, skipped int, err error) {
	if ns.DB == nil || ns.Store == nil || lead <= 0 {
		return 0, 0, nil
	}
	cutoff := now.Add(lead)
	for {
		batch, err := ns.DB.ListExpiring(now, cutoff, leaseRenewalBatchSize)
		if err != nil {
			return renewed, skipped, err
		}
		if len(batch) == 0 {
			return renewed, skipped, nil
		}
		changed := 0
		for _, meta := range batch {
			if !ns.Store.Has(meta.RoutingID) {
				skipped++
				continue
			}
			ok, err := ns.DB.RenewLease(meta, now)
			if err != nil {
				return renewed, skipped, err
			}
			if ok {
				renewed++
				changed++
			}
		}
		// Missing or concurrently changed rows remain in the query range. Stop
		// if a full batch made no progress; GC/reconciliation can remove orphans.
		if changed == 0 {
			return renewed, skipped, nil
		}
	}
}

// AddrInfo returns the peer.AddrInfo for this node.
func (ns *NodeService) AddrInfo() peer.AddrInfo {
	return peer.AddrInfo{
		ID:    ns.Host.ID(),
		Addrs: ns.Host.Addrs(),
	}
}

// Multiaddrs returns formatted multiaddrs with peer ID.
func (ns *NodeService) Multiaddrs() []string {
	return FormatMultiaddrs(ns.Host)
}

// Close gracefully stops the node service.
func (ns *NodeService) Close() error {
	ns.cancelFn()
	if ns.DHT != nil {
		_ = ns.DHT.Close()
	}
	_ = ns.Host.Close()
	_ = ns.DB.Close()
	_ = ns.Store.Close()
	return nil
}
