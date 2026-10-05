# FlowStore Swarm Protocol Specification (v0.2)

## 1. Overview
FlowStore is a zero-central-server, client-encrypted, peer-to-peer self-healing information swarm.
Logical files are never stored intact on any single peer. Instead, they are chunked, encrypted with XChaCha20-Poly1305, erasure-coded using Reed-Solomon (6 data shards + 4 parity shards), and distributed among autonomous volunteer peers.

## 2. Threat & Security Model
1. **Opaque Shards**: Peering nodes receive opaque binary blobs identified only by pseudorandom routing tokens (`RoutingID`). Nodes cannot determine:
   - File plaintext
   - File name, extension, or directory path
   - Shard order or relationship to other shards
   - Data owner identity
2. **Attacker Capabilities**:
   - An adversary observing network traffic, holding protocol docs, and controlling multiple storage nodes cannot reconstruct data without the 256-bit cryptographic recovery secret.
3. **Data Authenticity**:
   - Every chunk is protected by XChaCha20-Poly1305 authenticated encryption (AEAD) with 192-bit random nonces and 128-bit authentication tags.
   - Every shard carries a BLAKE3 integrity digest computed by the client. Tampered shards are rejected during audit and reconstruction.

## 3. Cryptographic Key Hierarchy

FlowStore derives all operational keys deterministically from a single **256-bit Master Recovery Secret** using HKDF-SHA256:

```
                      Master Recovery Secret (256-bit)
                                    │
           ┌────────────────────────┼────────────────────────┐
           ▼                        ▼                        ▼
    Identity KeyPair           Catalog Key             Routing Key
      (Ed25519)             (256-bit AEAD)           (256-bit HMAC)
                                    │                        │
                                    ▼                        ▼
                               Metadata Key             Wrapping Key
                              (256-bit AEAD)           (256-bit AES/Cha)
```

- **Identity Key**: Used for signing peer requests, leases, and proof-of-possession challenges.
- **Catalog Key**: Encrypts the user's private filesystem directory tree and object manifests.
- **Routing Key**: Seeds HMAC calculations to produce unpredictable, un-linkable DHT routing IDs.
- **Metadata Key**: Encrypts per-object attributes (MIME types, timestamps, custom tags).

## 4. Shard Addressing & Oblivious Routing

To prevent an adversary from correlating known file hashes with network queries:
```
RoutingID = HMAC-BLAKE3( RoutingKey, ObjectID || ChunkIndex || ShardIndex || Epoch )
```
- Nodes on the network store and index blobs by `RoutingID`.
- No node knows the underlying `ObjectID` or `ChunkIndex`.
- `Epoch` allows graceful rotation or migration of shard identities over time.

## 5. Erasure Coding Parameters (6 + 4)
- **Data Shards ($K$)**: 6
- **Parity Shards ($M$)**: 4
- **Total Shards ($N$)**: 10
- **Expansion Ratio**: $10 / 6 \approx 1.667\times$
- **Fault Tolerance**: Up to 4 arbitrary shards can be lost, corrupted, or unreachable without data loss. Reconstructing original chunk requires any 6 surviving shards.

## 6. Pipeline: File Ingestion Flow
```
1. Plaintext File (Stream / File)
      │
2. Fixed Chunking (64 MiB blocks; customizable for testing)
      │
3. Per-Chunk Key Derivation / Nonce Generation (XChaCha20-Poly1305)
      │
4. Chunk Ciphertext (Payload + 16-byte Poly1305 Tag)
      │
5. Reed-Solomon Encoding (6 data shards + 4 parity shards)
      │
6. Integrity Checksum (BLAKE3 per shard)
      │
7. Obfuscated Routing Token (HMAC-BLAKE3 routing ID per shard)
      │
8. Distribution across 10 distinct failure domains / peers
```

## 7. Node Wire Protocol (Application Layer)
Protocols implemented on top of libp2p:
- `/flowstore/store/1.0`: Upload shard with lease duration and integrity proof.
- `/flowstore/get/1.0`: Retrieve shard by `RoutingID`.
- `/flowstore/probe/1.0`: Proof-of-possession challenge/response without transferring the full shard.
- `/flowstore/delete/1.0`: Idempotent explicit reclaim by `RoutingID`. Request `{routing_id}`; response `{success, existed}`. Handler removes the shard file and its SQLite index record. Missing shards succeed with `existed=false`.
- `/flowstore/repair/1.0`: Swarm health coordination and re-replication trigger. Request `{check?: RoutingID[<=1000], reannounce?: bool}`; response `{success, held[], missing[], shard_count, used_bytes, quota_bytes, failure_domain, reannounced}`. Used by `flow repair-status` to audit presence without bulk transfer and to ask a peer to re-`Provide` held shards on the DHT after restarts.
