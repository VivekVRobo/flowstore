# Sovereign Computer V2 — engineering sequence

**Status reviewed:** 2026-10-04. FlowStore is an existing experimental storage foundation to harden, not a future phase to build from scratch. This plan records the current state and the next gates; it does not claim production readiness.

## Goal

Rebuild a Linux computer from encrypted VM snapshots onto a fresh runner. The first demonstrated path is local. A free external provider is optional and must be qualified; guaranteed 24/7 service is not assumed.

With 6+4 erasure coding, 100 TB of logical data requires at least about 167 TB of shard capacity before headers, replicas, repair headroom, retention, and other overhead. Until that capacity is measured and available, 100 TB is a namespace goal, not durable physical capacity.

## Sequence and current state

### 1. Baseline and repository hygiene — prepared locally

- The existing FlowStore baseline and local snapshot acceptance record are documented in `docs/FLOWSTORE_BASELINE.md` and `docs/LOCAL_LINUX_VM_SNAPSHOT.md`.
- The root `.gitignore` excludes provider config and backups, local manifests, peer state, shard data, binaries, and VM images.
- The workspace has no Git metadata yet. Keep it uninitialized until the source boundary and credential review are ready for a shared or public repository; review `.gitignore` again before that step.

### 2. Harden FlowStore for large state objects — default-setting 2 GiB smoke passed; multi-page scale remains

- The CLI streams one encoded chunk to storage at a time. It writes the encrypted object manifest only after all chunk-store calls succeed and verifies the stored shards.
- Shard writes enforce configured byte quotas. 6+4 placement requires ten distinct peer IDs and reports failure-domain diversity; peer IDs on one laptop do not provide independent-host resilience.
- Ingest, `flow recover`, and `flow restore` join the FlowStore DHT from supplied bootstrap addresses. A fresh client can discover shard providers from one reachable bootstrap peer. `flow recover` preserves an existing output until the recovered object passes its BLAKE3 check.
- CLI ingestion stores bounded encrypted manifest pages as FlowStore objects, while local and distributed catalogs keep their page references in an encrypted paged descriptor. Recover, restore, audit, and delete understand both paged and legacy inline manifests. A 2 GiB runtime qualification passed at intended defaults: 32 data chunks (64 MiB each), one page (256 references per page), and one-bootstrap fresh-client recovery with a matching SHA-256. Peak RSS was 636 MiB for ingest and 589 MiB for direct recovery. The descriptor was 4,578 bytes; an existing encrypted catalog grew by 4,724 bytes. This one-page result does not measure growth beyond the 16 GiB page boundary.
- Catalog generations use immutable versioned shards and a replicated root pointer as the commit point. Lease expiry, garbage collection, and disk/index reconciliation are implemented.
- Online peers now renew present, live shards as they approach lease expiry. The `go-libp2p-kad-dht` API in use has no immediate `Unprovide`; provider records age out under its 48-hour default validity, and repair no longer re-announces expired shards. Immediate remote withdrawal remains open pending a FlowStore revocation layer or a DHT adapter with stop-providing support. The paged descriptor stores one small manifest per metadata page, so catalog references still grow with page count; measure multi-page growth before targeting multi-terabyte objects.

### 3. Local Linux VM snapshots — current paged path boot passed locally; independent-host proof remains

- The QEMU adapter captures a powered-off Linux disk into a standalone qcow2 image, records metadata and a BLAKE3 hash, stores both image and descriptor, and publishes the catalog after both objects commit.
- The acceptance record documents a same-laptop WSL run: a clean Linux VM restored using one bootstrap address, the disk hash matched, `qemu-img check` passed, and the restored guest booted.
- The current paged path was also exercised with a stopped Alpine Linux QCOW2 disk: `flow snapshot capture` published the disk and descriptor, a clean client restored both through one bootstrap address, the restored BLAKE3 matched, `qemu-img check` passed, and QEMU reached the Alpine login prompt. All peers were still on this laptop.
- This proves the local capture, discovery, restore, and boot path. It does not prove recovery after losing the laptop or from an independent physical host. The adapter does not live-quiesce a running guest.
- The next availability gate requires peers on a different physical host, then a clean runner on another host. No such device is currently available, so this gate is pending external capacity rather than a software dependency.

### 4. Qualify external compute — optional and parallel

- Probe candidate runners for architecture, memory, disk, networking, virtualization, and session limits. Check current terms, quotas, card requirements, idle reclamation, and billing controls separately.
- Do not make a free provider a prerequisite for building or improving the local snapshot path. Reject any option that cannot run the workload under its published rules or expected spend cap.
- No external provider is currently qualified for the always-on goal.

### 5. Private browser access, then Windows — not started

- Add a Linux browser desktop behind private networking after the local snapshot path is reliable on a runner that can stay available.
- Qualify virtualization, architecture, license, and resource requirements before adding Windows. Keep Linux as the first snapshot target.

### 6. Multi-provider storage and scale — later experiments

- Add storage adapters and multi-provider repair after the single-provider FlowStore path is reliable.
- Scale in measured steps. Record logical size, physical shard bytes, coding overhead, repair headroom, restore duration, bandwidth, peer churn, and retention. Do not describe a 100 TB namespace as 100 TB of durable storage without that capacity.

## Next engineering work

1. Profile the several-hundred-MiB RSS observed at the 64 MiB chunk default, then measure a multi-page object once there is enough safe local capacity; at current defaults that boundary is 16 GiB.
2. Design immediate provider revocation for the Kademlia API limitation, or explicitly accept its 48-hour stale-record window.
3. When another physical host becomes available, repeat snapshot restore with peers and runner separated across hosts; verify the disk hash, image check, and guest boot there.

Follow `docs/LOCAL_LINUX_VM_SNAPSHOT.md` for the local acceptance details. Provider qualification and Windows remain separate workstreams; neither blocks local FlowStore development.
