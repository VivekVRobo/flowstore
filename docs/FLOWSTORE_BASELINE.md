# FlowStore baseline

**Status:** experimental prototype. This document records what exists in the workspace and what the Sovereign Computer V2 plan still needs. It does not imply production readiness; acceptance outcomes are recorded separately in `docs/LOCAL_LINUX_VM_SNAPSHOT.md`.

## Implemented in the current source tree

- A 256-bit master recovery secret and HKDF-derived identity, catalog, routing, metadata, and wrapping keys in `internal/crypto`.
- XChaCha20-Poly1305 encryption for object chunks and catalogs.
- Fixed-size object chunking (64 MiB by default), BLAKE3 hashes, and 6+4 Reed-Solomon coding in `internal/object` and `internal/erasure`.
- A local file-backed shard store and a libp2p peer daemon with store, get, and possession-probe handlers in `internal/storage` and `internal/network`.
- The `flownode` daemon now persists its Ed25519 libp2p identity at `~/.flowstore/node.key` by default (or `--identity-key` when explicitly set), so restarts keep the same peer ID. Linux deployment uses a systemd unit with a dedicated service account and a persistent state directory.
- Encrypted catalog distribution and recovery code in `internal/catalog`.
- Peer selection, audit, reconstruction, repair, and migration building blocks in `internal/placement` and `internal/repair`.
- Network, recovery, and repair test sources under `tests/`.

## Known gaps to close before using this as the VM-state substrate

- The compatibility `Pipeline.Ingest` method still returns every encoded chunk to its caller. The CLI uses `Pipeline.IngestStreamPaged`, which hands each encoded chunk to storage before reading the next and encrypts each bounded page of ChunkRef metadata. The default page size is 256 chunks and the CLI caps it at 4,096. Encoded payload buffers are bounded by the configured data chunk, one manifest page, and sink/network buffers. The compact paged descriptor keeps one storage manifest per metadata page, so descriptor/catalog size still grows with page count; multi-terabyte scale needs measured catalog size and memory benchmarks.
- Each encrypted metadata page is stored as a regular FlowStore object. The CLI writes the encrypted `*.flowmanifest.enc` descriptor only after all data chunks and page objects have been stored and verified. Catalog entries reference the paged descriptor; `flow recover`, `flow restore`, `flow audit`, and `flow delete` process one metadata page at a time. Legacy inline encrypted manifests and plaintext `*.flowmanifest.json` files remain readable; plaintext files warn because they contain paths and per-chunk keys.
- Runtime qualification passed on a disposable 1 GiB random file with 16 MiB chunks and `--page-size 2`: ingest created 64 data chunks and 32 encrypted manifest pages; fresh-client `flow recover` and catalog-based `flow restore` both used only one bootstrap address, succeeded, and produced SHA-256 values matching the source. GNU `time` recorded maximum RSS of 191,716 KiB for ingest (1:13.72), 179,980 KiB for direct recover (1:05.38), and 177,892 KiB for catalog restore (46.24 s). The encrypted paged descriptor was 125,014 bytes and the encrypted catalog was 125,575 bytes. This deliberately small page size inflates metadata; these measurements do not establish multi-terabyte capacity.
- The local catalog is now encrypted on write. Existing plaintext local catalogs are migrated to the encrypted envelope when loaded for ingest.
- Distributed object and catalog writes require ten distinct peer IDs for each 6+4 shard set and assign one shard per peer. Peers advertise `--failure-domain` via `/flowstore/repair/1.0`; `placement.Scheduler` tracks domains, `SelectDiversePeers` round-robins across domains, and repair/migration prefer spread. Single-host tests still succeed with domain shortfall reported; production needs 10 distinct domains for full independence.
- The daemon's `--quota-gb` is enforced at the file-store write boundary against on-disk shard bytes, including the shard header. Existing shard files are counted at startup. A zero quota means unlimited. Leases expire via background GC (`--gc-interval`, default 5m, `0` disables): `storage.CollectGarbage` expires DB leases, deletes files + records, and reconciles orphans both ways at startup and on interval. Live shards with files present are now renewed by their original lease duration when they enter a 24-hour renewal window; old node databases migrate their lease duration when opened. Get/probe/repair treat expired leases as missing even before the next sweep.
- The daemon serves store, get, probe, delete, and repair handlers (`/flowstore/delete/1.0` for idempotent explicit reclaim with index cleanup; `/flowstore/repair/1.0` for batch presence checks, usage reporting, and DHT re-announcement). The CLI exposes `flow delete <manifest>` and `flow repair-status <peer> [-reannounce]`.
- Ingest, `flow recover`, and `flow restore` join the FlowStore DHT through supplied bootstrap peer addresses. Storage peers announce their own shard records after storing. A fresh client can discover shard providers from one reachable bootstrap multiaddress when the storage nodes participate in the same DHT; the recovery secret does not contain network addresses. `flow recover` writes to a sibling temporary file and publishes it only after reconstruction passes the whole-object BLAKE3 check, leaving an existing output intact on a failed recovery.
- Catalog generations are immutable at epoch=Version with a replicated root pointer as the atomic commit (`DeriveCatalogRootLocator`, any 1 of 10 copies recovers). Generation shards are stored first; the root is updated only after they succeed, so interrupted publishes leave the prior root intact. Recovery tries the root pointer first, then the pointed generation, with legacy epoch-0 fallback for pre-generational catalogs.
- The Linux QEMU adapter captures a powered-off disk into a standalone qcow2 image, records allocated overlay extents and a BLAKE3 image hash, ingests the image and descriptor, and publishes the catalog only after both objects are committed. The local acceptance record documents a same-laptop WSL test: a clean Linux runner restored through one bootstrap address, the image hash matched, `qemu-img check` passed, and the restored guest booted. This does not demonstrate recovery from another physical host. The adapter does not live-quiesce a guest.
- There is no compute broker, runner lifecycle controller, or browser desktop flow.
- Compression, deduplication, measured repair headroom, and large-object benchmarks are not established.

## Default-setting 2 GiB runtime qualification (2026-10-04)

A synthetic 2 GiB zero-filled file was ingested with the intended defaults: 64 MiB chunks and 256 chunk references per metadata page. It produced 32 data chunks and one metadata page. Ingest used ten peers, all on one WSL laptop and in the same failure domain. A fresh client with the same recovery secret and only node 1 as its bootstrap address recovered the file. The original and recovered SHA-256 values matched (`a7c744c13cc11d0cdca82dded949ecfaf6073e7b29a0e91ab82763fa1bcaed`); FlowStore's BLAKE3 validation also passed.

| Operation | Elapsed | Maximum RSS |
| --- | ---: | ---: |
| `flow ingest` | 1:25.08 | 651,340 KiB (636 MiB) |
| `flow recover` | 1:26.26 | 603,020 KiB (589 MiB) |

The encrypted descriptor was 4,578 bytes. The encrypted catalog was copied from the earlier qualification client before measurement: 125,575 bytes before and 130,299 bytes after ingest, a 4,724-byte increase for this second catalog entry. This is one page at the default settings, not a multi-page measurement: the first page boundary is 256 × 64 MiB = 16 GiB. The observed resident memory stayed below the 2 GiB input size but is several hundred MiB for a 64 MiB chunk; profile the per-chunk/network-buffer overhead before setting a production memory budget. The ten peers still shared one laptop, so this does not qualify independent-host availability.

## Lease renewal and DHT provider expiry

The daemon's existing GC cycle now renews a still-live lease when it is due within 24 hours, provided the shard file remains present. Renewal extends by the duration originally requested at store time, which is persisted in SQLite; legacy database rows seed a conservative term from the remaining validity when migrated on open. Expired leases and records without shard files are not renewed.

Immediate DHT withdrawal is not available through the current `go-libp2p-kad-dht` `IpfsDHT` API. Its default provider-record validity is 48 hours, so DHT peers can return a stale provider until that record ages out; the shard's own get/probe handlers still treat the expired or deleted shard as absent. The repair re-announcement path now checks that each shard has a live lease before advertising it, and `flow delete` reports the DHT expiry limitation instead of claiming immediate withdrawal. Immediate remote unannouncement remains a protocol limitation that needs a FlowStore-specific revocation mechanism or a DHT adapter with a supported stop-providing operation.

## Local files that are not source

- `config/rclone.conf` contains token-like credential fields. Its backup is ignored too, even though common token/secret field names were not detected there.
- Legacy `*.flowmanifest.json` files contain paths and per-chunk keys; new `*.flowmanifest.enc` files contain encrypted manifests.
- `flownode-data/`, shard blobs, executables, render job state, and VM images are local state or build outputs.

The `.gitignore` protects the known paths. Recheck it whenever a provider, key, manifest, or local data directory is added.
