# Oracle Always Free VM pilot

This pilot uses an Oracle Cloud VM as the first remote Linux computer. Oracle supplies the VM and its CPU/RAM; FlowStore runs on that machine as software. This does not require us to build a hypervisor, and it does not establish that a second VM can run inside the Oracle VM.

## Target shape

- Start with an Always Free `VM.Standard.A1.Flex` instance and an ARM64 Linux image such as Ubuntu or Oracle Linux.
- The current Always Free compute allowance is up to 2 OCPUs and 12 GB RAM in the tenancy's home region. Capacity can be unavailable, and Oracle may reclaim an A1 instance that meets its idle criteria for seven days. This is a trial target, not a 24/7 uptime guarantee.
- Keep all volumes and add-on resources within the Always Free limits shown in the account console. Check the final estimate before creating resources.
- A1 is ARM64. This pilot can run Linux ARM64 binaries; it is not a drop-in host for an x86 Windows image.

## Security boundary

Use SSH only from a trusted source address during initial setup. The FlowStore daemon listens on TCP and UDP port 41001. Keep those ports closed to the public internet until the private VPN path is configured; then allow the FlowStore port only from the VPN subnet. The current storage protocol still needs authorization hardening before being exposed as a public storage service. Do not copy `config/rclone.conf`, its backup, recovery secrets, SSH private keys, or other local credentials to the VM.

## Build and install

From Windows PowerShell in the repository root, build Linux ARM64 binaries:

```powershell
.\scripts\build-linux-arm64.ps1
```

The outputs are placed under the ignored `bin/linux-arm64/` directory. Copy `flow` and `flownode` to the VM over SSH/SCP, then install them:

```sh
sudo useradd --system --home-dir /var/lib/flowstore --create-home --shell /usr/sbin/nologin flowstore
sudo install -o root -g root -m 0755 flow /usr/local/bin/flow
sudo install -o root -g root -m 0755 flownode /usr/local/bin/flownode
sudo install -d -o flowstore -g flowstore -m 0700 /var/lib/flowstore
sudo install -o root -g root -m 0644 flowstore-peer.service /etc/systemd/system/flowstore-peer.service
sudo systemctl daemon-reload
sudo systemctl enable --now flowstore-peer.service
```

The service stores opaque shards and its SQLite index under `/var/lib/flowstore/data`. It creates `/var/lib/flowstore/node.key` with restrictive permissions on first start and reuses that key on later starts, so the peer ID remains stable across daemon restarts. Back up the node key securely if this peer's identity must survive host replacement; it is not the user's FlowStore recovery secret.

The initial quota is 10 GiB to leave room for the OS and recovery tooling on the boot volume. Increase it only after checking the VM's actual free disk capacity. The service is configured to restart after failures and start after network readiness.

## Initial acceptance

1. Confirm the VM is reachable over SSH while the Windows laptop is off.
2. Install the binaries and start the systemd service.
3. Record the peer ID and verify it remains unchanged after a service restart and a VM reboot.
4. Configure a WireGuard tunnel between the VM and the home network; keep port 41001 restricted to the tunnel.
5. Only after the FlowStore peer swarm is reachable and its storage path is verified, ingest a non-sensitive test object, remove the test copy from the client, restore it on a fresh client, and compare its hash.

This pilot does not claim a tested VM snapshot restore. Capturing and booting a guest inside this cloud VM would require a supported nested-virtualization path; the free A1 target is being used here as the cloud VM itself.
