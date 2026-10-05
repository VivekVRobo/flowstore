package network

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"flowstore/internal/erasure"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

var (
	ErrNoPeersConnected = errors.New("could not establish connection to any specified peers")
	ErrShardNotFound    = errors.New("shard not found on any connected peer")
)

// ClientSession manages an ephemeral libp2p client connection to a swarm of peers.
type ClientSession struct {
	Host  host.Host
	Peers []peer.AddrInfo
	DHT   *ShardRouting
}

// ParsePeerAddr parses a multiaddr or IP:port string into a peer.AddrInfo.
func ParsePeerAddr(addrStr string) (*peer.AddrInfo, error) {
	addrStr = strings.TrimSpace(addrStr)
	if addrStr == "" {
		return nil, errors.New("empty peer address")
	}

	// Support simple ip:port format if user omitted multiaddr syntax
	if !strings.HasPrefix(addrStr, "/") {
		parts := strings.Split(addrStr, ":")
		if len(parts) == 2 {
			addrStr = fmt.Sprintf("/ip4/%s/tcp/%s", parts[0], parts[1])
		}
	}

	maddr, err := multiaddr.NewMultiaddr(addrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid multiaddress format: %w", err)
	}

	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return nil, fmt.Errorf("address must include /p2p/<PeerID>: %w", err)
	}

	return info, nil
}

// NewClientSession creates an ephemeral libp2p client and connects to the specified peer addresses.
func NewClientSession(ctx context.Context, peerAddrs []string) (*ClientSession, error) {
	h, err := NewHost(ctx, Config{
		ListenAddrs: []string{
			"/ip4/0.0.0.0/tcp/0",
			"/ip4/0.0.0.0/udp/0/quic-v1",
		},
		EnableAutoNAT: true,
		EnableRelay:   true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create client host: %w", err)
	}

	var connectedPeers []peer.AddrInfo
	seenPeers := make(map[peer.ID]struct{})
	var lastErr error

	for _, addrStr := range peerAddrs {
		info, err := ParsePeerAddr(addrStr)
		if err != nil {
			lastErr = err
			continue
		}

		connCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = h.Connect(connCtx, *info)
		cancel()

		if err != nil {
			lastErr = err
			continue
		}
		if _, duplicate := seenPeers[info.ID]; duplicate {
			continue
		}
		seenPeers[info.ID] = struct{}{}

		connectedPeers = append(connectedPeers, *info)
	}

	if len(connectedPeers) == 0 {
		h.Close()
		if lastErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrNoPeersConnected, lastErr)
		}
		return nil, ErrNoPeersConnected
	}

	return &ClientSession{
		Host:  h,
		Peers: connectedPeers,
	}, nil
}

// NewDiscoveryClientSession connects to bootstrap peers and joins the
// FlowStore DHT as a client. At least one reachable bootstrap peer is required.
func NewDiscoveryClientSession(ctx context.Context, peerAddrs []string) (*ClientSession, error) {
	cs, err := NewClientSession(ctx, peerAddrs)
	if err != nil {
		return nil, err
	}
	routing, err := NewShardRouting(ctx, cs.Host, false)
	if err != nil {
		_ = cs.Close()
		return nil, fmt.Errorf("failed to create discovery routing: %w", err)
	}
	if err := routing.Bootstrap(ctx, cs.Peers); err != nil {
		_ = routing.Close()
		_ = cs.Close()
		return nil, fmt.Errorf("failed to join FlowStore discovery DHT: %w", err)
	}
	cs.DHT = routing
	return cs, nil
}

// PeerIDs returns the list of connected peer IDs.
func (cs *ClientSession) PeerIDs() []peer.ID {
	ids := make([]peer.ID, len(cs.Peers))
	for i, p := range cs.Peers {
		ids[i] = p.ID
	}
	return ids
}

// DistributeShard stores a single shard to a specified peer.
func (cs *ClientSession) DistributeShard(ctx context.Context, target peer.ID, routingID string, shard erasure.Shard, leaseSeconds int64) error {
	return SendStoreShard(ctx, cs.Host, target, routingID, shard, leaseSeconds)
}

// DistributeAllShards sends shards across connected peers. If there are at least as
// many peers as shards, it enforces distinct-peer placement (one shard per peer).
// If fewer peers are connected (e.g. in test swarms or constrained setups), it
// distributes shards round-robin across available peers.
func (cs *ClientSession) DistributeAllShards(ctx context.Context, shards []erasure.Shard, routingIDs []string, leaseSeconds int64) error {
	if len(cs.Peers) == 0 {
		return ErrNoPeersConnected
	}
	if len(shards) != len(routingIDs) {
		return fmt.Errorf("shard and routing ID counts differ: %d shards, %d routing IDs", len(shards), len(routingIDs))
	}
	if len(cs.Peers) >= len(shards) {
		return cs.DistributeDistinctShards(ctx, shards, routingIDs, leaseSeconds)
	}

	for i, shard := range shards {
		targetPeer := cs.Peers[i%len(cs.Peers)].ID
		rID := routingIDs[i]

		err := SendStoreShard(ctx, cs.Host, targetPeer, rID, shard, leaseSeconds, cs.DHT != nil)
		if err != nil {
			return fmt.Errorf("failed storing shard %d on peer %s: %w", shard.Index, targetPeer, err)
		}
	}
	return nil
}

// DistributeDistinctShards sends one shard to each of a set of distinct connected peers.
// It fails if fewer distinct peers are connected than shards to distribute.
func (cs *ClientSession) DistributeDistinctShards(ctx context.Context, shards []erasure.Shard, routingIDs []string, leaseSeconds int64) error {
	if len(cs.Peers) == 0 {
		return ErrNoPeersConnected
	}
	if len(shards) != len(routingIDs) {
		return fmt.Errorf("shard and routing ID counts differ: %d shards, %d routing IDs", len(shards), len(routingIDs))
	}
	if len(cs.Peers) < len(shards) {
		return fmt.Errorf("distinct-peer placement requires %d peers for %d shards; connected to %d", len(shards), len(shards), len(cs.Peers))
	}
	seen := make(map[peer.ID]struct{}, len(shards))
	for _, p := range cs.Peers[:len(shards)] {
		if _, duplicate := seen[p.ID]; duplicate {
			return fmt.Errorf("distinct-peer placement received duplicate peer ID %s", p.ID)
		}
		seen[p.ID] = struct{}{}
	}

	for i, shard := range shards {
		targetPeer := cs.Peers[i].ID
		rID := routingIDs[i]

		err := SendStoreShard(ctx, cs.Host, targetPeer, rID, shard, leaseSeconds, cs.DHT != nil)
		if err != nil {
			return fmt.Errorf("failed storing shard %d on peer %s: %w", shard.Index, targetPeer, err)
		}
	}
	return nil
}

// FetchShard searches all connected peers concurrently and returns the first verified shard.
func (cs *ClientSession) FetchShard(ctx context.Context, routingID string) (*erasure.Shard, error) {
	if len(cs.Peers) == 0 {
		return nil, ErrNoPeersConnected
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		shard *erasure.Shard
		err   error
	}

	resCh := make(chan result, len(cs.Peers))
	var wg sync.WaitGroup

	for _, p := range cs.Peers {
		wg.Add(1)
		go func(pID peer.ID) {
			defer wg.Done()
			fetchCtx, fCancel := context.WithTimeout(ctx, 5*time.Second)
			defer fCancel()

			shard, err := FetchShard(fetchCtx, cs.Host, pID, routingID)
			if err == nil && shard != nil {
				select {
				case resCh <- result{shard: shard}:
					cancel() // cancel other pending requests
				default:
				}
			}
		}(p.ID)
	}

	// Closer routine
	go func() {
		wg.Wait()
		close(resCh)
	}()

	for res := range resCh {
		if res.shard != nil {
			return res.shard, nil
		}
	}
	if cs.DHT != nil {
		discoveryCtx, discoveryCancel := context.WithTimeout(ctx, 10*time.Second)
		defer discoveryCancel()
		providers, err := cs.DHT.FindProviders(discoveryCtx, routingID, 10)
		if err == nil {
			for _, provider := range providers {
				if err := cs.Host.Connect(discoveryCtx, provider); err != nil {
					continue
				}
				fetchCtx, fetchCancel := context.WithTimeout(discoveryCtx, 10*time.Second)
				shard, fetchErr := FetchShard(fetchCtx, cs.Host, provider.ID, routingID)
				fetchCancel()
				if fetchErr == nil && shard != nil {
					return shard, nil
				}
			}
		}
	}

	return nil, ErrShardNotFound
}

// ProbeShard challenges connected peers to prove possession of a shard.
func (cs *ClientSession) ProbeShard(ctx context.Context, routingID string, expectedChecksum [32]byte) (bool, peer.ID, error) {
	var nonce [32]byte
	_, _ = rand.Read(nonce[:])

	for _, p := range cs.Peers {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		has, err := ProbeShard(probeCtx, cs.Host, p.ID, routingID, nonce, expectedChecksum)
		cancel()

		if err == nil && has {
			return true, p.ID, nil
		}
	}

	return false, "", nil
}

// DeleteShard broadcasts an explicit reclaim for one RoutingID to all
// connected peers. It returns the number of peers that held the shard.
func (cs *ClientSession) DeleteShard(ctx context.Context, routingID string) (int, error) {
	if len(cs.Peers) == 0 {
		return 0, ErrNoPeersConnected
	}
	if routingID == "" {
		return 0, errors.New("empty routing ID")
	}
	deleted := 0
	var lastErr error
	for _, p := range cs.Peers {
		dCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		existed, err := SendDeleteShard(dCtx, cs.Host, p.ID, routingID)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if existed {
			deleted++
		}
	}
	if deleted == 0 && lastErr != nil {
		return 0, lastErr
	}
	return deleted, nil
}

// RepairStatus queries one connected peer for storage health coordination.
func (cs *ClientSession) RepairStatus(ctx context.Context, target peer.ID, check []string, reannounce bool) (*RepairResponse, error) {
	return RequestRepair(ctx, cs.Host, target, check, reannounce)
}

// PingPeer dials a peer multiaddr and measures round-trip time.
func PingPeer(ctx context.Context, addrStr string) (time.Duration, peer.ID, error) {
	info, err := ParsePeerAddr(addrStr)
	if err != nil {
		return 0, "", err
	}

	h, err := NewHost(ctx, Config{
		ListenAddrs: []string{"/ip4/0.0.0.0/tcp/0"},
	})
	if err != nil {
		return 0, "", fmt.Errorf("failed to create ping host: %w", err)
	}
	defer h.Close()

	start := time.Now()
	connCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := h.Connect(connCtx, *info); err != nil {
		return 0, "", fmt.Errorf("ping connection failed: %w", err)
	}

	rtt := time.Since(start)
	return rtt, info.ID, nil
}

// Close gracefully closes the client libp2p host.
func (cs *ClientSession) Close() error {
	if cs.DHT != nil {
		_ = cs.DHT.Close()
	}
	if cs.Host != nil {
		return cs.Host.Close()
	}
	return nil
}
