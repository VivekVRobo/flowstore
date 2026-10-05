package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"flowstore/internal/crypto"
	"flowstore/internal/erasure"
	"flowstore/internal/network"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

var (
	ErrCatalogReconstructionFailed = errors.New("failed to gather sufficient catalog shards from the swarm")
)

// RecoverCatalogFromSecret reconstructs the user's complete virtual filesystem catalog
// starting from nothing other than the human-readable 256-bit Master Recovery Secret.
// It first tries the generational root pointer (any 1 of 10 copies), then the
// generation shards at the pointed epoch. Legacy epoch-0 catalogs without a
// root pointer fall back to the deprecated epoch argument.
func RecoverCatalogFromSecret(
	ctx context.Context,
	h host.Host,
	dht *network.ShardRouting,
	recoveryCode string,
	epoch uint32,
	knownPeers []peer.ID,
) (*Catalog, *crypto.Keyring, error) {
	// 1. Parse master secret and deterministically derive all operational keys
	secret, err := crypto.ParseRecoveryCode(recoveryCode)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid recovery code: %w", err)
	}

	keyring, err := crypto.DeriveKeyring(secret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive keyring: %w", err)
	}

	id := crypto.NewIdentityFromPrivateKey(keyring.IdentityPriv)
	ownerID := id.NodeID()

	// 2. Try generational root pointer first.
	if ptr := fetchRootPointer(ctx, h, dht, keyring, ownerID, knownPeers); ptr != nil {
		if cat, _, err := fetchGeneration(ctx, h, dht, keyring, ownerID, ptr.CatalogEpoch, knownPeers); err == nil {
			return cat, keyring, nil
		}
	}

	// 3. Fallback to legacy fixed-epoch catalog (pre-generational).
	return fetchGeneration(ctx, h, dht, keyring, ownerID, epoch, knownPeers)
}

func fetchRootPointer(ctx context.Context, h host.Host, dht *network.ShardRouting, keyring *crypto.Keyring, ownerID string, knownPeers []peer.ID) *CatalogRootPointer {
	for replica := 0; replica < 10; replica++ {
		routingID := DeriveCatalogRootLocator(keyring.CatalogKey[:], uint8(replica))
		if shard := fetchOneShard(ctx, h, dht, routingID, uint8(replica), knownPeers); shard != nil {
			if ptr, err := decryptRootPointer(shard.Data, keyring.CatalogKey[:], ownerID); err == nil {
				return ptr
			}
		}
	}
	return nil
}

func fetchGeneration(ctx context.Context, h host.Host, dht *network.ShardRouting, keyring *crypto.Keyring, ownerID string, epoch uint32, knownPeers []peer.ID) (*Catalog, *crypto.Keyring, error) {
	engine, err := erasure.DefaultEngine()
	if err != nil {
		return nil, nil, err
	}

	// Discover and collect catalog shards from the swarm
	var survivingShards []erasure.Shard

	for i := 0; i < engine.TotalShards(); i++ {
		shardIdx := uint8(i)
		routingID := DeriveCatalogShardLocator(keyring.CatalogKey[:], shardIdx, epoch)

		if shard := fetchOneShard(ctx, h, dht, routingID, shardIdx, knownPeers); shard != nil {
			survivingShards = append(survivingShards, *shard)
		}
	}

	if len(survivingShards) < engine.DataShards() {
		return nil, nil, fmt.Errorf("%w: found %d valid shards, need at least %d",
			ErrCatalogReconstructionFailed, len(survivingShards), engine.DataShards())
	}

	// Reconstruct encrypted catalog payload using Reed-Solomon (6+4)
	encryptedCatalog, err := engine.Decode(survivingShards)
	if err != nil {
		return nil, nil, fmt.Errorf("erasure decode of catalog failed: %w", err)
	}

	// Decrypt catalog using CatalogKey
	aad := []byte(fmt.Sprintf("flowstore:catalog:%s", ownerID))
	plaintext, err := crypto.Decrypt(encryptedCatalog, keyring.CatalogKey[:], aad)
	if err != nil {
		return nil, nil, fmt.Errorf("cryptographic decryption of catalog failed: %w", err)
	}

	// Unmarshal virtual filesystem
	var cat Catalog
	if err := json.Unmarshal(plaintext, &cat); err != nil {
		return nil, nil, fmt.Errorf("failed to parse catalog JSON: %w", err)
	}

	return &cat, keyring, nil
}

func fetchOneShard(ctx context.Context, h host.Host, dht *network.ShardRouting, routingID string, shardIdx uint8, knownPeers []peer.ID) *erasure.Shard {
	// Check DHT first if available
	if dht != nil {
		dhtCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		providers, err := dht.FindProviders(dhtCtx, routingID, 10)
		if err == nil {
			for _, provider := range providers {
				fetchCtx, fetchCancel := context.WithTimeout(ctx, 3*time.Second)
				if connectErr := h.Connect(fetchCtx, provider); connectErr == nil {
					shard, fetchErr := network.FetchShard(fetchCtx, h, provider.ID, routingID)
					if fetchErr == nil && shard != nil {
						fetchCancel()
						cancel()
						return shard
					}
				}
				fetchCancel()
			}
		}
		cancel()
	}

	// Check known swarm peers directly
	for _, pID := range knownPeers {
		fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		shard, err := network.FetchShard(fetchCtx, h, pID, routingID)
		cancel()
		if err == nil && shard != nil {
			return shard
		}
	}
	return nil
}
