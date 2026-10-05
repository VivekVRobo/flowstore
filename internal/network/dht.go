package network

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/ipfs/go-cid"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multihash"
)

const (
	DHTProtocolPrefix = "/flowstore/kad/1.0"
	// DHTProviderRecordValidity mirrors go-libp2p-kad-dht v0.42.2's default
	// provider-record lifetime. That version's IpfsDHT API has no Unprovide;
	// remote records expire naturally and may remain discoverable until then.
	DHTProviderRecordValidity = 48 * time.Hour
)

// ShardRouting wraps libp2p Kademlia DHT for oblivious shard lookup and provider announcement.
type ShardRouting struct {
	kaddht *dht.IpfsDHT
	h      host.Host
}

// NewShardRouting initializes a Kademlia DHT instance on the host.
func NewShardRouting(ctx context.Context, h host.Host, serverMode bool) (*ShardRouting, error) {
	opts := []dht.Option{
		dht.ProtocolPrefix(DHTProtocolPrefix),
	}
	if serverMode {
		opts = append(opts, dht.Mode(dht.ModeServer))
	} else {
		opts = append(opts, dht.Mode(dht.ModeClient))
	}

	kdht, err := dht.New(h, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create kademlia dht: %w", err)
	}

	return &ShardRouting{
		kaddht: kdht,
		h:      h,
	}, nil
}

// Bootstrap connects to bootstrap peers and refreshes the DHT routing table.
func (sr *ShardRouting) Bootstrap(ctx context.Context, bootstrapPeers []peer.AddrInfo) error {
	var wg sync.WaitGroup
	for _, pInfo := range bootstrapPeers {
		if pInfo.ID == sr.h.ID() {
			continue
		}
		wg.Add(1)
		go func(p peer.AddrInfo) {
			defer wg.Done()
			ctxConn, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_ = sr.h.Connect(ctxConn, p)
		}(pInfo)
	}
	wg.Wait()
	if len(bootstrapPeers) > 0 && len(sr.h.Network().Peers()) == 0 {
		return fmt.Errorf("could not connect to any configured DHT bootstrap peer")
	}

	return sr.kaddht.Bootstrap(ctx)
}

// RoutingIDToCID converts an oblivious hex RoutingID into a deterministic CID for DHT provider indexing.
func RoutingIDToCID(routingID string) (cid.Cid, error) {
	raw, err := hex.DecodeString(routingID)
	if err != nil {
		return cid.Undef, fmt.Errorf("invalid hex routing ID: %w", err)
	}

	mh, err := multihash.Encode(raw, multihash.BLAKE3)
	if err != nil {
		return cid.Undef, fmt.Errorf("failed to encode multihash: %w", err)
	}

	return cid.NewCidV1(cid.Raw, mh), nil
}

// Provide announces that this host provides the shard identified by routingID.
func (sr *ShardRouting) Provide(ctx context.Context, routingID string) error {
	c, err := RoutingIDToCID(routingID)
	if err != nil {
		return err
	}
	return sr.kaddht.Provide(ctx, c, true)
}

// FindProviders queries the DHT for peers providing the specified shard.
func (sr *ShardRouting) FindProviders(ctx context.Context, routingID string, maxCount int) ([]peer.AddrInfo, error) {
	c, err := RoutingIDToCID(routingID)
	if err != nil {
		return nil, err
	}

	providerChan := sr.kaddht.FindProvidersAsync(ctx, c, maxCount)
	var providers []peer.AddrInfo

	for p := range providerChan {
		if p.ID != "" {
			providers = append(providers, p)
			if maxCount > 0 && len(providers) >= maxCount {
				break
			}
		}
	}

	return providers, nil
}

// Close cleanly shuts down the DHT.
func (sr *ShardRouting) Close() error {
	return sr.kaddht.Close()
}
