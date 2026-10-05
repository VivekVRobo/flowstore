# Experimental rclone-backed shard directory

FlowStore peer metadata and shard payloads no longer have to share one
directory. `flownode --dir` keeps the peer's local SQLite database, while
`flownode --shard-dir` selects where its shard files are stored. With the
Windows rclone mount already configured as Z:, a peer can use a unique
directory on that mount:

```powershell
New-Item -ItemType Directory -Force -Path C:\FlowStore\peer-a | Out-Null
New-Item -ItemType Directory -Force -Path Z:\FlowStorePeers\peer-a | Out-Null
flownode.exe --dir C:\FlowStore\peer-a `
  --shard-dir Z:\FlowStorePeers\peer-a `
  --quota-gb 100 `
  --failure-domain google-drive-pool
```

Start rclone and confirm Z: is mounted before starting the peer. Keep each
peer's shard directory separate; never point two running peers at the same
directory. Leave `--dir` on a local filesystem because the SQLite database
needs local filesystem semantics. The shard directory must remain available
for reads, writes, recovery, quota accounting, and startup reconciliation.

The current Z: mount is an rclone union over two Google Drive remotes. It is a
cloud-backed namespace, not additional local hardware. With rclone VFS disk
caching disabled, shard writes should not require a full-size local staging
copy, though the process, filesystem, and network still use small transient
buffers. The configured union does not make the two Drive accounts independent
failure domains, and a single shard file is placed on one upstream rather than
striped across both. Do not claim peer or provider redundancy from multiple
peer directories on this same pool.

For mounted filesystems where rename is unreliable, `--shard-direct-write`
selects a separate commit path. It writes the final shard file directly and
appends an embedded completion trailer; startup and reads ignore files without
that trailer, and shard reads still verify the payload checksum. The default
mode remains temporary-file, sync, and rename for normal local filesystems.

Both paths are experimental on this rclone union. A disposable upload exposed
read-after-write visibility problems through the Z: mount: a sidecar completion
file was visible through rclone's remote listing but not immediately through
the mounted path. The embedded-trailer mode is in the code, but its end-to-end
qualification is still pending. Do not use Z: as the only copy of important
data until an upload has been read back, survived a peer restart, and recovered
through a fresh FlowStore client. Existing WSL shard data is not moved by this
setting; moving it requires a separate copy, verification, and peer
reconfiguration.
