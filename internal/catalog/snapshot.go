package catalog

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"flowstore/internal/crypto"
	"flowstore/internal/erasure"
	"flowstore/internal/network"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"lukechampine.com/blake3"
)

// DeriveCatalogShardLocator computes the deterministic oblivious DHT routing ID for a catalog shard.
// RoutingID = BLAKE3-KeyedHash(CatalogKey, "flowstore:catalog:root" || shardIndex || epoch)
func DeriveCatalogShardLocator(catalogKey []byte, shardIndex uint8, epoch uint32) string {
	hasher := blake3.New(32, catalogKey)

	tag := []byte("flowstore:catalog:root")
	buf := make([]byte, len(tag)+5)
	copy(buf, tag)
	buf[len(tag)] = shardIndex
	binary.BigEndian.PutUint32(buf[len(tag)+1:], epoch)

	hasher.Write(buf)
	return hex.EncodeToString(hasher.Sum(nil))
}

// DeriveCatalogRootLocator computes the fixed locator for a replicated root
// pointer copy. Generations live at epoch=Version locators; the root lives at
// a reserved namespace so interrupted generation writes never corrupt it.
func DeriveCatalogRootLocator(catalogKey []byte, replica uint8) string {
	hasher := blake3.New(32, catalogKey)
	tag := []byte("flowstore:catalog:rootptr")
	buf := make([]byte, len(tag)+1)
	copy(buf, tag)
	buf[len(tag)] = replica
	hasher.Write(buf)
	return hex.EncodeToString(hasher.Sum(nil))
}

// CatalogRootPointer is the atomic commit record. It is tiny and replicated
// identically to all peers (any 1 copy recovers the version), so a partial
// root update still leaves a readable old or new pointer, never a corrupt mix.
type CatalogRootPointer struct {
	FormatVersion  uint8  `json:"format_version"`
	OwnerID        string `json:"owner_id"`
	CatalogVersion uint64 `json:"catalog_version"`
	CatalogEpoch   uint32 `json:"catalog_epoch"`
}

const rootPointerFormatVersion = 1

func rootPointerAAD(ownerID string) []byte {
	return []byte("flowstore:catalog:rootptr:" + ownerID)
}

func encryptRootPointer(ptr *CatalogRootPointer, catalogKey []byte) ([]byte, error) {
	data, err := json.Marshal(ptr)
	if err != nil {
		return nil, err
	}
	return crypto.Encrypt(data, catalogKey, rootPointerAAD(ptr.OwnerID))
}

func decryptRootPointer(ciphertext, catalogKey []byte, ownerID string) (*CatalogRootPointer, error) {
	plaintext, err := crypto.Decrypt(ciphertext, catalogKey, rootPointerAAD(ownerID))
	if err != nil {
		return nil, err
	}
	var ptr CatalogRootPointer
	if err := json.Unmarshal(plaintext, &ptr); err != nil {
		return nil, err
	}
	if ptr.FormatVersion != rootPointerFormatVersion || ptr.OwnerID != ownerID || ptr.CatalogVersion == 0 {
		return nil, fmt.Errorf("invalid root pointer")
	}
	return &ptr, nil
}

// DistributeCatalog serializes, encrypts, erasure-codes (6+4), and distributes the catalog to swarm peers.
// The epoch parameter is deprecated: generations are immutable at epoch=Version,
// with a replicated root pointer as the atomic commit. Generation shards are
// stored first; the root is updated only after they succeed, so interrupted
// publishes leave the prior root intact.
func DistributeCatalog(
	ctx context.Context,
	h host.Host,
	dht *network.ShardRouting,
	cat *Catalog,
	keyring *crypto.Keyring,
	targetPeers []peer.ID,
	epoch uint32,
) error {
	engine, err := erasure.DefaultEngine()
	if err != nil {
		return err
	}

	if len(targetPeers) == 0 {
		return fmt.Errorf("need at least 1 peer to distribute catalog shards")
	}

	// 1. Serialize catalog to JSON
	data, err := json.Marshal(cat)
	if err != nil {
		return fmt.Errorf("failed to marshal catalog: %w", err)
	}

	// 2. Encrypt with XChaCha20-Poly1305 using CatalogKey
	aad := []byte(fmt.Sprintf("flowstore:catalog:%s", cat.OwnerID))
	encryptedCatalog, err := crypto.Encrypt(data, keyring.CatalogKey[:], aad)
	if err != nil {
		return fmt.Errorf("failed to encrypt catalog: %w", err)
	}

	// 3. Erasure-code into 10 shards (6 data + 4 parity)
	shards, err := engine.Encode(encryptedCatalog)
	if err != nil {
		return fmt.Errorf("failed to erasure-code catalog: %w", err)
	}
	distinctPeers := len(targetPeers) >= len(shards)
	if distinctPeers {
		seenPeers := make(map[peer.ID]struct{}, len(shards))
		for _, targetPeer := range targetPeers[:len(shards)] {
			if _, duplicate := seenPeers[targetPeer]; duplicate {
				return fmt.Errorf("distinct-peer catalog placement received duplicate peer ID %s", targetPeer)
			}
			seenPeers[targetPeer] = struct{}{}
		}
	}

	// 4. Distribute each generation shard immutably at epoch=Version.
	// The deprecated epoch argument is ignored so old callers get safe behavior.
	generation := uint32(cat.Version)
	_ = epoch
	for i, s := range shards {
		routingID := DeriveCatalogShardLocator(keyring.CatalogKey[:], s.Index, generation)
		destPeer := targetPeers[i%len(targetPeers)]

		storeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := network.SendStoreShard(storeCtx, h, destPeer, routingID, s, 365*24*3600, dht != nil) // 1-year lease
		cancel()

		if err != nil {
			return fmt.Errorf("failed to store catalog shard %d on peer %s: %w", s.Index, destPeer, err)
		}

	}

	// 5. Commit the atomic root pointer only after all generation shards
	// succeed. The pointer is replicated identically; any 1 copy recovers.
	ptr := &CatalogRootPointer{
		FormatVersion:  rootPointerFormatVersion,
		OwnerID:        cat.OwnerID,
		CatalogVersion: cat.Version,
		CatalogEpoch:   generation,
	}
	encryptedPtr, err := encryptRootPointer(ptr, keyring.CatalogKey[:])
	if err != nil {
		return fmt.Errorf("failed to encrypt catalog root pointer: %w", err)
	}
	ptrChecksum := blake3.Sum256(encryptedPtr)
	for replica := 0; replica < 10; replica++ {
		routingID := DeriveCatalogRootLocator(keyring.CatalogKey[:], uint8(replica))
		destPeer := targetPeers[replica%len(targetPeers)]
		shard := erasure.Shard{
			Index:        uint8(replica),
			OriginalSize: uint64(len(encryptedPtr)),
			Checksum:     ptrChecksum,
			Data:         encryptedPtr,
		}
		storeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := network.SendStoreShard(storeCtx, h, destPeer, routingID, shard, 365*24*3600, dht != nil)
		cancel()
		if err != nil {
			return fmt.Errorf("failed to store catalog root pointer %d on peer %s: %w", replica, destPeer, err)
		}
	}

	return nil
}
