# FireGuard Architecture & Platform Limits

## Separation of Concerns

- `fireguard/models.py`: OS-independent data structures (`Policy`, `Rule`, `SystemDefaults`, `PortRange`, `Schedule`) and `explain_rule()`.
- `fireguard/validation.py`: Input sanitization (no shell-command construction), IPv4/IPv6 consistency checks, port/protocol validation, critical service warnings, and rule conflict/shadowing detection.
- `fireguard/engine.py`: Deterministic first-match-wins evaluation (`evaluate_packet`), effective policy inspection, and starter templates.
- `fireguard/storage.py`: Atomic JSON persistence, strict import validation, and rollback snapshots.
- `fireguard/audit.py`: Structured JSONL audit logging with automatic redaction of sensitive keys.
- `fireguard/backends/`:
  - `linux_nft.py`: Translates policies into an isolated dual-stack `table inet fireguard` and validates syntax with `nft -c -f -`.
  - `windows_fw.py`: Translates policies into PowerShell `NetSecurity` commands scoped to `-Group 'FireGuard'` and exports/imports `.wfw` snapshots via `netsh advfirewall`.

## Rule Precedence & Conflict Resolution

FireGuard uses **deterministic first-match-wins** evaluation:

1. **Explicit Loopback (`allow_loopback`)**: When enabled, `127.0.0.0/8`, `::1`, and `lo`/`lo0` are allowed first.
2. **Explicit Established/Related (`allow_established`)**: When enabled, return packets for established connections are allowed next.
3. **Ordered Rules**: Enabled, non-expired rules are evaluated top-to-bottom:
   - `log` rules record a match and **continue** evaluation.
   - `allow` and `block` rules **terminate** evaluation immediately.
   - Shadowing/conflicts (e.g., a broad earlier rule hiding a narrower later rule) are surfaced as validation warnings.
4. **Default Policy**: Unmatched traffic falls back to `default_inbound` or `default_outbound` for both IPv4 and IPv6.

## Platform Limitations

- **Domain Name Blocking:** Intentionally not implemented as a fake IP-lookup rule. DNS TTLs, round-robin DNS, CDNs, proxies, and encrypted DNS (DoH/DoT) make IP-based domain blocking unreliable.
- **Application/Executable Matching:**
  - Supported on **Windows Defender Firewall** (`-Program`).
  - **Unsupported** natively in **Linux `nftables`** (skipped with a clear warning in preview).
- **Schedules & Expiration:**
  - `expires_at` is checked at render/simulation time, and expired rules are skipped.
  - Recurring time windows are not auto-toggled by the kernel without an external timer/scheduler.
- **Log-only Rules:**
  - Supported on **Linux `nftables`** (`log prefix "..."`).
  - **Unsupported** as standalone rules in **Windows Defender Firewall** `New-NetFirewallRule`.
- **Persistence Across Reboot / Startup:** FireGuard never silently enables itself at startup or persists rules across reboot unless the administrator explicitly configures their OS service/nftables config.
