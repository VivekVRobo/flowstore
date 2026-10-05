package network

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/libp2p/go-libp2p"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Config holds network host options.
type Config struct {
	PrivateKey    ed25519.PrivateKey
	ListenAddrs   []string
	EnableRelay   bool
	EnableAutoNAT bool
	EnableUPnP    bool
	RelayService  bool
	StaticRelays  []peer.AddrInfo
}

// NewHost creates and initializes a libp2p Host with QUIC and TCP transports,
// UPnP port mapping, AutoNAT hole punching, and Circuit Relay v2 support.
func NewHost(ctx context.Context, cfg Config) (host.Host, error) {
	var opts []libp2p.Option

	// Identity: Convert Ed25519 key to libp2p crypto format
	if cfg.PrivateKey != nil {
		priv, err := p2pcrypto.UnmarshalEd25519PrivateKey(cfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal ed25519 private key: %w", err)
		}
		opts = append(opts, libp2p.Identity(priv))
	}

	// Listen addresses
	if len(cfg.ListenAddrs) == 0 {
		// Default to all network interfaces on random available ports
		opts = append(opts, libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/0",
			"/ip4/0.0.0.0/udp/0/quic-v1",
		))
	} else {
		opts = append(opts, libp2p.ListenAddrStrings(cfg.ListenAddrs...))
	}

	// UPnP Automatic Router Port-Mapping
	if cfg.EnableUPnP {
		opts = append(opts, libp2p.NATPortMap())
	}

	// NAT Traversal & Hole Punching
	if cfg.EnableAutoNAT {
		opts = append(opts, libp2p.EnableNATService())
		opts = append(opts, libp2p.EnableHolePunching())
	}

	// Circuit Relay v2 Service
	if cfg.RelayService {
		opts = append(opts, libp2p.EnableRelayService())
	}

	// Circuit Relay Client & AutoRelay fallback
	if cfg.EnableRelay {
		opts = append(opts, libp2p.EnableRelay())
		if len(cfg.StaticRelays) > 0 {
			opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays(cfg.StaticRelays))
		}
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize libp2p host: %w", err)
	}

	return h, nil
}

// FormatMultiaddrs returns human-readable multiaddrs with PeerID appended.
func FormatMultiaddrs(h host.Host) []string {
	var addrs []string
	peerID := h.ID().String()
	for _, a := range h.Addrs() {
		full := fmt.Sprintf("%s/p2p/%s", a.String(), peerID)
		addrs = append(addrs, full)
	}
	return addrs
}

// ParseMultiaddr parses a string into a multiaddr.Multiaddr.
func ParseMultiaddr(s string) (multiaddr.Multiaddr, error) {
	return multiaddr.NewMultiaddr(s)
}
