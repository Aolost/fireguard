# FireGuard

A configurable, safety-first firewall policy manager for **Linux (`nftables`)** and **Windows (Windows Defender Firewall)** with both a CLI and a local Web UI.

## Key Features

- **Dry-run by default:** Preview exact native `nftables` or PowerShell `NetSecurity` rules before touching any live system state.
- **Safety & Rollback Guard:** Snapshots previous firewall state before applying changes, warns on rules that block SSH (22), RDP (3389), WinRM (5985/5986), DNS (53), DHCP (67/68/546/547), or loopback, and automatically rolls back if connectivity is not confirmed within a configurable timeout.
- **Consistent Dual-Stack IPv4 & IPv6:** Linux uses a single `table inet fireguard` so IPv6 is never an undocumented bypass.
- **Explicit Baseline Traffic:** Loopback (`127.0.0.0/8`, `::1`) and `established,related` connection handling are visible and configurable.
- **Simple & Advanced Interfaces:**
  - CLI (`fireguard`) for scripting, simulation, import/export, preview, and apply.
  - Local Web UI (`fireguard web`) with a Simple View for common allow/block rules and an Advanced View for defaults, traffic simulation, raw JSON import/export, and audit logs.

## Installation

Requires **Python 3.10+** (zero third-party runtime dependencies).

```bash
python3 -m pip install -e .
```

Or run directly from the repository without installing:

```bash
python3 -m fireguard.cli --help
```

## Quick Start (Dry-Run)

```bash
# 1. Initialize a draft policy (never applied automatically)
python3 -m fireguard.cli policy init

# 2. Or load a sensible starter template
python3 -m fireguard.cli policy starters
python3 -m fireguard.cli policy load-starter server-ssh-web

# 3. Add a rule
python3 -m fireguard.cli rule add \
  --name "Allow WireGuard" \
  --direction inbound \
  --action allow \
  --protocol udp \
  --dst-port 51820

# 4. Simulate a packet against the draft policy
python3 -m fireguard.cli policy simulate \
  --direction inbound \
  --src-ip 203.0.113.10 \
  --dst-ip 192.168.1.50 \
  --protocol tcp \
  --dst-port 22

# 5. Preview the exact native OS rules (dry-run)
python3 -m fireguard.cli preview --backend linux-nftables
python3 -m fireguard.cli preview --backend windows-defender

# 6. Launch the local Web UI
python3 -m fireguard.cli web --host 127.0.0.1 --port 8420
```

## Applying Live Rules & Permissions

Live rule modification is **never** performed without explicit confirmation:

- **Linux (`linux-nftables`):** Requires `CAP_NET_ADMIN` or `root` (`sudo`). Only `table inet fireguard` is managed; unrelated system `nftables` tables are left untouched.
- **Windows (`windows-defender`):** Requires an elevated Administrator PowerShell/terminal session. Only rules in `Group = 'FireGuard'` are managed; existing Windows Firewall rules are preserved.

```bash
sudo python3 -m fireguard.cli apply --backend linux-nftables
```

After applying, you must type `confirm` within `rollback_timeout_seconds` (default `60s`), or FireGuard automatically restores the pre-apply snapshot.

For architecture, precedence rules, and platform limitations, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
