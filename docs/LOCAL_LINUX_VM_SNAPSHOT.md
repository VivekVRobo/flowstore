# Local Linux VM snapshot acceptance

This first adapter targets an offline QEMU disk image. It runs only on Linux and requires `qemu-img`. Shut the guest down before capture; the adapter does not live-freeze filesystems. If the input is a qcow2 overlay, the descriptor records data and explicit-zero extents stored in that overlay. Capture flattens the disk to a standalone qcow2 image and records its virtual size and BLAKE3 hash.

For an isolated Flow CLI profile, set `FLOWSTORE_CONFIG_DIR` on `flow init`, capture, and catalog-publishing commands. The default remains `~/.flowstore`; protect either location because it contains the recovery secret and encrypted local catalog.

## Storage prerequisites

- Keep the FlowStore storage peers outside the disposable VM runner. The peers must remain available when runner A is removed.
- Start at least ten storage peers with unique peer IDs and DHT enabled. Configure the nodes to join the same FlowStore DHT; one peer can be the bootstrap peer for the rest.
- Peer IDs on one machine exercise placement logic only. They do not demonstrate host, rack, or power-domain resilience.
- Make each peer's quota large enough for its share of the encoded snapshot plus headroom. With 6+4 coding, total stored shard bytes are about 1.67 times the logical image size before headers and metadata.
- Initialize the FlowStore identity on runner A with `flow init` and retain the recovery secret outside the VM being captured.

For an intentionally local, same-laptop qualification, start every peer with `--upnp=false --autonat=false --relay-client=false --relay-service=false` while leaving DHT enabled. This avoids unnecessary router mapping and public reachability services during the local test; it does not establish cross-host availability.

## Capture and commit on runner A

With the Linux guest shut down and its qcow2 disk closed, capture and ingest the disk and descriptor:

```sh
flow snapshot capture /var/lib/libvirt/images/linux-vm.qcow2 \
  -output /srv/snapshots/linux-vm-2026-09-26.qcow2 \
  -peer /ip4/10.0.0.10/tcp/41001/p2p/<bootstrap-peer-id> \
  -peer /ip4/10.0.0.11/tcp/41001/p2p/<peer-2-id> \
  -peer /ip4/10.0.0.12/tcp/41001/p2p/<peer-3-id> \
  -peer /ip4/10.0.0.13/tcp/41001/p2p/<peer-4-id> \
  -peer /ip4/10.0.0.14/tcp/41001/p2p/<peer-5-id> \
  -peer /ip4/10.0.0.15/tcp/41001/p2p/<peer-6-id> \
  -peer /ip4/10.0.0.16/tcp/41001/p2p/<peer-7-id> \
  -peer /ip4/10.0.0.17/tcp/41001/p2p/<peer-8-id> \
  -peer /ip4/10.0.0.18/tcp/41001/p2p/<peer-9-id> \
  -peer /ip4/10.0.0.19/tcp/41001/p2p/<peer-10-id>
```

The command uploads the disk and descriptor without updating the catalog between them. It publishes both encrypted object manifests to the catalog only after both objects' shards have been stored, read back, and verified. A failed upload can leave unreferenced shard data or a local encrypted manifest, but it does not add the incomplete snapshot to the catalog.

Keep the reported disk object ID and the recovery secret with the snapshot record. The descriptor is also stored as an encrypted FlowStore object; its local `.flowmeta.json` copy is ignored by Git.

## Restore to fresh runner B

Create a clean Linux runner B with `flow` and QEMU installed. It does not need runner A's local files or identity directory. Supply the recovery secret and one reachable bootstrap peer from the storage swarm:

```sh
flow restore /srv/restore \
  -secret-file /run/credentials/flowstore-recovery \
  -peer /ip4/10.0.0.10/tcp/41001/p2p/<bootstrap-peer-id>
```

On Linux, the secret file must be readable only by its owner (mode `0600` or stricter). `-secret-file` keeps the recovery code out of the process argument list. Keep this file outside the restored disk and protect it as recovery metadata. The legacy `-secret` option remains available, but places the code in the process arguments. Restore uses DHT provider discovery for catalog and object shards, then falls back to the specified bootstrap peers. The secret alone does not include a bootstrap address. The storage swarm and its DHT must still be reachable.

Verify the restored image against the descriptor and QEMU's image checker before booting:

```sh
expected=$(jq -r .image_blake3 /srv/restore/linux-vm-2026-09-26.qcow2.flowmeta.json)
actual=$(b3sum /srv/restore/linux-vm-2026-09-26.qcow2 | cut -d ' ' -f 1)
test "$expected" = "$actual"
qemu-img check /srv/restore/linux-vm-2026-09-26.qcow2
```

Boot the disk using the guest's expected firmware and device settings, for example:

```sh
qemu-system-x86_64 -enable-kvm -m 2048 -smp 2 \
  -drive file=/srv/restore/linux-vm-2026-09-26.qcow2,format=qcow2,if=virtio
```

Ubuntu cloud images need UEFI firmware and first-boot cloud-init metadata. Attach a NoCloud seed volume labeled `CIDATA` with an instance ID and DHCP network configuration when testing a cloud image; otherwise `systemd-networkd-wait-online` can keep the first boot from reaching the login prompt.

## Acceptance record

## Local smoke-test record (2026-10-04)

A single-host smoke test was completed under Ubuntu on WSL using QEMU/KVM, the official Ubuntu 24.04 cloud disk, and ten FlowStore peers. The guest was booted, shut down through ACPI, captured, and ingested. A new Flow CLI process, with an isolated output directory and no Runner A keyring/catalog files, restored the encrypted catalog and both snapshot objects using only the recovery secret plus one bootstrap peer address. The restored disk's BLAKE3 matched the descriptor (`6383728104ab85df55baa74a0344170e697e461d5bb5e5c2139ad4cf4e80b70a`), `qemu-img check` passed, and the restored guest reached the Ubuntu login prompt when booted with a NoCloud seed.

A separate clean Ubuntu cloud-image VM then ran as a fresh Linux restore client. It booted from a new overlay, received the FlowStore binary and recovery secret through a NoCloud seed, and restored the encrypted catalog and both files using one bootstrap address. The guest reported `CATALOG RECONSTRUCTION SUCCESS`, `Swarm restoration complete! All files verified and restored.`, and exit status 0. `qemu-img check` passed for the fresh runner's disk overlay and the captured snapshot image. This guest-side run confirms that a fresh Linux VM can perform discovery and restore; the previous host-side restore supplied the direct descriptor hash comparison and boot test of the recovered image.

The CLI regression `TestIngestFailureDoesNotReplaceCommittedManifest` injects a shard-store failure on the second chunk and confirms the prior encrypted-manifest file remains unchanged. A real-process interruption test also sent SIGKILL to `flow ingest -catalog=false` after 8 of 598 one-MiB chunks had been stored (80 shards). The previous encrypted manifest and uploader's local catalog hashes were unchanged. The partial upload left unreferenced shard data on the peers, but it did not enter the catalog. A clean client then used one bootstrap address to reconstruct catalog version 3, discover its two files, and restore the previous snapshot. FlowStore reported all files verified, `qemu-img check` passed, and the restored image's BLAKE3 matched the descriptor. Snapshot capture publishes its catalog only after both disk and descriptor objects finish ingesting.

All ten storage peers ran on the same laptop and reported the same failure domain. Together, these checks prove local capture, encrypted shard storage, one-bootstrap DHT discovery, fresh Linux VM restore, hash check, and guest boot. They do not prove host-failure tolerance or recovery from an independent physical runner. The test peers were stopped after verification, with their local data retained on D:.

## Current paged-manifest qualification (2026-10-04)

The current CLI and catalog code was exercised with a disposable 1 GiB random file, 16 MiB chunks, and `--page-size 2`. Ingest stored 64 data chunks and 32 encrypted metadata-page objects, then committed the encrypted descriptor and isolated encrypted catalog. A clean client configuration containing only the same test recovery secret restored the object both by `flow recover` and by `flow restore`; each command was given only node 1's bootstrap address. Both paths succeeded, and the original, direct-recovery, and catalog-restored files had identical SHA-256 hashes. FlowStore's BLAKE3 verification also passed during recovery.

| Operation | Elapsed | Maximum RSS |
| --- | ---: | ---: |
| `flow ingest` | 1:13.72 | 191,716 KiB |
| `flow recover` | 1:05.38 | 179,980 KiB |
| `flow restore` | 46.24 s | 177,892 KiB |

The encrypted paged descriptor measured 125,014 bytes; the encrypted catalog measured 125,575 bytes. This was a deliberately small page size that creates many references. Treat the values as a runtime smoke-test measurement, not a projection for multi-terabyte objects. All ten storage peers were on the same WSL laptop and shared one failure domain.

The same current path then captured a stopped Alpine Linux 3.23 QCOW2 disk. The captured image was 85,975,552 bytes. A fresh client restored the image and its descriptor from the catalog using one bootstrap address. The restored image's BLAKE3 matched its descriptor (`5f1acefcc937be0d089181526f9dc0706c4a2583a7a35f542bc042dca836d106`), `qemu-img check` reported no errors, and the restored image booted under WSL/KVM to the `localhost login:` prompt. QEMU used a temporary overlay so the hash-verified restored image stayed unchanged. The temporary VM and all ten test peers were stopped after verification.

## Remaining acceptance work

Record the following before calling the multi-host local milestone demonstrated:

1. Keep the storage peers outside the disposable VM runner, remove runner A after the catalog commit, and retain the swarm.
2. Restore on a clean Linux runner on a different physical host using only the recovery secret and one documented storage bootstrap address.
3. Confirm the restored image hash matches its descriptor, `qemu-img check` succeeds, and the guest boots on that host.
4. Interrupt `flow snapshot capture` after the disk object finishes but before the descriptor/catalog commit, then confirm a fresh client still sees only the previous committed snapshot.
