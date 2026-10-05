# FlowStore

FlowStore is an experimental Go prototype for client-encrypted object storage across libp2p peers. The long-term goal is to store machine snapshots and restore them onto a fresh runner.

## Current status

FlowStore is not production-ready. End-to-end recovery after peer restart from a fresh client has not yet been qualified for the current Z: backed shard path. A successful restore test on one laptop would prove recovery behavior, not independent-host availability or continuous 24/7 service.

## Build

Install a current Go toolchain, then build the two command-line programs from the repository root:

```powershell
go build -o flow.exe ./cmd/flow
go build -o flownode.exe ./cmd/flownode
```

These commands build the executables only. They do not configure peers, storage remotes, recovery secrets, or a production deployment.

## Windows build artifacts

The `Windows build artifacts` GitHub Actions workflow builds unsigned Windows x64 `flow.exe` and `flownode.exe` files from the checked-out source. It uploads them as a short-lived workflow artifact with a SHA-256 checksum and build provenance text. There is not yet a public binary release or a SignPath-signed download. FlowStore is experimental; do not entrust it with the only copy of important data.

## Project documents

- [Current FlowStore baseline](docs/FLOWSTORE_BASELINE.md)
- [Sovereign Computer V2 engineering sequence](docs/SOVEREIGN_COMPUTER_V2_PLAN.md)
- [Local Linux VM snapshot acceptance runbook](docs/LOCAL_LINUX_VM_SNAPSHOT.md)
- [Oracle Always Free VM pilot](docs/OCI_FREE_VM_PILOT.md)
- [Swarm protocol draft](protocol/FLOWSTORE_PROTOCOL.md)

The historical `cloud_studio` experiments are excluded from the FlowStore V2 source release. They remain in the local workspace and may contain outdated setup material and personal machine paths.

## Local data and credentials

Do not commit provider configuration, config backups, manifests, recovery secrets, peer keys, shard data, databases, VM images, or built executables. `config/rclone.conf` contains credential-bearing token fields. The root `.gitignore` excludes this configuration, local data, build outputs, and the historical experiments.

Legacy `*.flowmanifest.json` files can contain object paths and per-chunk keys. New `*.flowmanifest.enc` files encrypt those fields, but should still be treated as local recovery metadata. The Flow CLI stores its recovery secret and encrypted catalog under `~/.flowstore` by default. Set `FLOWSTORE_CONFIG_DIR` to use a separate profile, and protect that directory because `recovery.secret` grants access to the associated objects.

## License

FlowStore is released under the MIT License. See [LICENSE](LICENSE).
