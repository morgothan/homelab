# Secondary DNS

Runtime configuration for the independent AdGuard Home + Unbound resolver that
runs in its own Proxmox LXC on the LAN.

- AdGuard Home listens on TCP/UDP 53 and forwards to local Unbound on
  `127.0.0.1:5335`.
- `adguardhome-sync` runs in the Docker stack and treats the primary AdGuard
  instance as the origin and this instance as a read-only replica.
- DHCP is intentionally not served from this LXC.
- Node Exporter listens on port 9100.

The live AdGuard configuration is synchronized through its API rather than
stored here because it contains an administrator password hash and mutable
runtime state.
