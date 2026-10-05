# FlowStore Privacy Policy

- **Effective date:** 2026-10-05
- **Applies to:** the experimental FlowStore source and binaries in this repository.

## Current service model

FlowStore is an experimental peer-to-peer storage program. The current source has no FlowStore-operated account service, central storage server, analytics pipeline, or telemetry endpoint. The project is not production-ready.

When an operator runs `flow ingest` or `flow snapshot capture`, FlowStore encrypts the selected file data on the client, divides it into erasure-coded shards, and sends those shards to the peer nodes specified by the operator. Recovery uses the user's recovery secret and reachable peer addresses. FlowStore does not send the recovery secret to the storage peers as part of the shard-storage protocol.

## Information visible to network participants

Storage-peer operators and other libp2p network participants may observe network metadata such as IP addresses, peer identifiers, connection times, traffic timing and approximate sizes, and shard-routing identifiers. A peer operator can store the encrypted shard bytes it receives. Client-side encryption protects file contents and private manifest fields, but does not hide network metadata or traffic volume.

FlowStore clients currently enable libp2p AutoNAT and relay-client support by default; the client CLI does not currently expose flags to disable them. The peer binary enables UPnP/NAT-PMP, AutoNAT, and relay-client support by default, while public relay-service mode is off by default. These features can contact other peers, relay operators, or a local router. Peer operators can disable UPnP, AutoNAT, and relay-client support with the corresponding `flownode` flags. Configure and trust only peer operators you intend to use.

## Local information

FlowStore stores the recovery secret, peer identity keys, and encrypted catalog in local configuration directories. These files remain under the control of the machine operator unless that person copies or shares them. Anyone with the recovery secret can derive the keys needed to access the associated FlowStore objects; keep it private and retain a backup.

## Third-party services and retention

FlowStore does not control peer operators, Internet service providers, relays, routers, GitHub, or other third parties. Their own privacy and retention terms apply to information they process. Shard retention depends on the lease and storage policy configured for each peer; operators should verify that policy before uploading data.

## Changes and contact

This policy describes the current experimental implementation and will be updated if FlowStore adds an account service, telemetry, or other data collection. Report privacy questions through the [FlowStore GitHub repository](https://github.com/VivekVRobo/flowstore); do not include recovery secrets, peer private keys, or private file contents in public issues.
