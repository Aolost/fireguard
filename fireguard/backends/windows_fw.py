"""Windows Defender Firewall backend using PowerShell NetSecurity & netsh snapshots."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Optional

from fireguard.backends.base import (
    ApplyResult,
    BackendCapabilities,
    FirewallBackend,
    PreviewResult,
)
from fireguard.models import Action, Direction, IPVersion, Policy, PortRange, Protocol, Rule
from fireguard.storage import PolicyStore
from fireguard.validation import validate_policy

RULE_GROUP = "FireGuard"


def _ps_quote(value: str) -> str:
    """Safely single-quote a validated string for PowerShell."""
    return "'" + value.replace("'", "''") + "'"


def _win_ports(ports: list[PortRange]) -> str:
    return "@(" + ", ".join(_ps_quote(p.format_str()) for p in ports) + ")"


def _win_ips(cidrs: list[str]) -> str:
    return "@(" + ", ".join(_ps_quote(c) for c in cidrs) + ")"


def _render_win_rule(rule: Rule) -> tuple[Optional[str], list[str]]:
    warnings: list[str] = []
    if rule.action == Action.LOG:
        warnings.append(
            f"Rule '{rule.name}' ({rule.id}) uses action 'log'. Windows Defender Firewall "
            "does not support standalone log-only rules; enable profile audit logging instead."
        )
        return None, warnings

    if rule.schedule:
        if rule.schedule.is_expired(datetime.now(timezone.utc)):
            return f"# Skipped expired rule {rule.id} ({rule.name})", warnings
        if rule.schedule.daily_start or rule.schedule.days:
            warnings.append(
                f"Rule '{rule.name}' ({rule.id}) has a schedule; Windows Defender Firewall "
                "requires Windows Task Scheduler to toggle scheduled rules."
            )

    params = [
        f"-DisplayName {_ps_quote('FireGuard: ' + rule.name)}",
        f"-Name {_ps_quote('FireGuard_' + rule.id)}",
        f"-Group {_ps_quote(RULE_GROUP)}",
        f"-Direction {'Inbound' if rule.direction == Direction.INBOUND else 'Outbound'}",
        f"-Action {'Allow' if rule.action == Action.ALLOW else 'Block'}",
        "-Profile Any",
        "-Enabled True",
    ]

    if rule.protocol != Protocol.ANY:
        proto_map = {
            Protocol.TCP: "TCP",
            Protocol.UDP: "UDP",
            Protocol.ICMP: "ICMPv4",
            Protocol.ICMPV6: "ICMPv6",
            Protocol.GRE: "47",
            Protocol.ESP: "50",
            Protocol.AH: "51",
            Protocol.SCTP: "132",
        }
        params.append(f"-Protocol {_ps_quote(proto_map[rule.protocol])}")

    if rule.source_ips:
        addr_param = "-RemoteAddress" if rule.direction == Direction.INBOUND else "-LocalAddress"
        params.append(f"{addr_param} {_win_ips(rule.source_ips)}")
    if rule.dest_ips:
        addr_param = "-LocalAddress" if rule.direction == Direction.INBOUND else "-RemoteAddress"
        params.append(f"{addr_param} {_win_ips(rule.dest_ips)}")

    if rule.source_ports:
        port_param = "-RemotePort" if rule.direction == Direction.INBOUND else "-LocalPort"
        params.append(f"{port_param} {_win_ports(rule.source_ports)}")
    if rule.dest_ports:
        port_param = "-LocalPort" if rule.direction == Direction.INBOUND else "-RemotePort"
        params.append(f"{port_param} {_win_ports(rule.dest_ports)}")

    if rule.interface:
        params.append(f"-InterfaceAlias {_ps_quote(rule.interface)}")
    if rule.application:
        params.append(f"-Program {_ps_quote(rule.application)}")

    if rule.ip_version != IPVersion.ANY and not rule.source_ips and not rule.dest_ips:
        warnings.append(
            f"Rule '{rule.name}' ({rule.id}) targets {rule.ip_version.value} without explicit CIDRs; "
            "Windows NetFirewallRule applies to both IPv4/IPv6 unless scoped by address."
        )

    return "New-NetFirewallRule " + " ".join(params), warnings


class WindowsDefenderBackend(FirewallBackend):
    """Manages isolated rules in Windows Defender Firewall (`Group = 'FireGuard'`)."""

    name = "windows-defender"
    platform_name = "Windows (Windows Defender Firewall)"

    def capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            supports_application_match=True,
            supports_schedule=False,
            supports_log_action=False,
            supports_rollback=True,
            requires_elevation=True,
            elevation_reason=(
                "Modifying Windows Defender Firewall rules requires an elevated Administrator session."
            ),
            limitations=[
                "Standalone 'log'-only rules are not supported by New-NetFirewallRule.",
                "Schedules require Windows Task Scheduler or periodic re-evaluation.",
                "Manages only rules in group 'FireGuard'; existing Windows rules are preserved.",
            ],
        )

    def check_availability(self) -> tuple[bool, str]:
        if os.name != "nt":
            return (
                False,
                "Windows Defender backend live execution is only available on Windows (preview still works).",
            )
        ps = shutil.which("powershell") or shutil.which("pwsh")
        if not ps:
            return False, "PowerShell not found in PATH."
        return True, f"Available ({ps})"

    def is_elevated(self) -> bool:
        if os.name != "nt":
            return False
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def capture_state(self) -> str:
        avail, reason = self.check_availability()
        if not avail:
            return f"# unavailable: {reason}\n"
        with tempfile.NamedTemporaryFile(suffix=".wfw", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            proc = subprocess.run(
                ["netsh", "advfirewall", "export", tmp_path],
                capture_output=True,
                text=True,
                shell=False,
            )
            if proc.returncode != 0:
                return f"# export_failed: {proc.stderr.strip()}\n"
            return Path(tmp_path).read_bytes().hex()
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def render_preview(self, policy: Policy) -> PreviewResult:
        validation = validate_policy(policy)
        warnings = [w.message for w in validation.warnings]
        unsupported: list[dict[str, str]] = []
        summary = [
            "Target: Windows Defender Firewall (PowerShell NetSecurity, Group='FireGuard').",
            f"Default inbound: {policy.defaults.default_inbound.value}, "
            f"Default outbound: {policy.defaults.default_outbound.value}.",
            "Existing non-FireGuard Windows Firewall rules will NOT be flushed.",
        ]

        lines = [
            f"Remove-NetFirewallRule -Group {_ps_quote(RULE_GROUP)} -ErrorAction SilentlyContinue",
            (
                "Set-NetFirewallProfile -Profile Domain,Public,Private "
                f"-DefaultInboundAction {'Allow' if policy.defaults.default_inbound == Action.ALLOW else 'Block'} "
                f"-DefaultOutboundAction {'Allow' if policy.defaults.default_outbound == Action.ALLOW else 'Block'}"
            ),
        ]

        for rule in policy.rules:
            if not rule.enabled:
                continue
            cmd, r_warn = _render_win_rule(rule)
            warnings.extend(r_warn)
            if cmd is None:
                unsupported.append(
                    {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "reason": "Standalone 'log' action is unsupported in Windows Defender rules.",
                    }
                )
                continue
            lines.append(cmd)

        return PreviewResult(
            backend_name=self.name,
            platform_name=self.platform_name,
            dry_run=True,
            summary=summary,
            warnings=warnings,
            unsupported_rules=unsupported,
            rendered_script="\n".join(lines) + "\n",
            syntax_checked=False,
        )

    def apply_live(
        self,
        policy: Policy,
        store: PolicyStore,
        confirm_callback: Optional[Callable[[int], bool]] = None,
        previous_policy: Optional[Policy] = None,
    ) -> ApplyResult:
        avail, reason = self.check_availability()
        if not avail:
            return ApplyResult(False, False, self.name, f"Backend unavailable: {reason}")
        if not self.is_elevated():
            return ApplyResult(
                False,
                False,
                self.name,
                "Administrator privileges required to modify Windows Defender Firewall.",
            )

        validation = validate_policy(policy)
        if not validation.is_valid:
            return ApplyResult(
                False,
                False,
                self.name,
                "Policy has validation errors: " + "; ".join(e.message for e in validation.errors),
            )

        preview = self.render_preview(policy)
        prev_state = self.capture_state()
        snap_path = store.save_snapshot(self.name, prev_state, previous_policy)

        ps = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
        proc = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-Command", preview.rendered_script],
            capture_output=True,
            text=True,
            shell=False,
        )
        if proc.returncode != 0:
            return ApplyResult(
                False,
                False,
                self.name,
                f"Windows Firewall apply failed: {proc.stderr.strip()}",
                snapshot_path=str(snap_path),
            )

        timeout = policy.defaults.rollback_timeout_seconds
        if confirm_callback is not None and not confirm_callback(timeout):
            snap_data = store.load_snapshot(snap_path)
            rb_ok, rb_msg = self.rollback(snap_data)
            return ApplyResult(
                False,
                False,
                self.name,
                f"Connectivity not confirmed within {timeout}s; rolled back ({rb_msg}).",
                snapshot_path=str(snap_path),
                rolled_back=rb_ok,
            )

        return ApplyResult(
            True,
            False,
            self.name,
            "Applied policy to Windows Defender Firewall (Group='FireGuard').",
            snapshot_path=str(snap_path),
            pending_confirmation=(confirm_callback is None),
        )

    def rollback(self, snapshot_data: dict[str, Any]) -> tuple[bool, str]:
        avail, reason = self.check_availability()
        if not avail:
            return False, reason
        if not self.is_elevated():
            return False, "Administrator privileges required to roll back Windows Firewall."
        hex_blob = snapshot_data.get("previous_system_state", "")
        if not hex_blob or hex_blob.startswith("#"):
            return False, "Snapshot does not contain a valid .wfw export."
        with tempfile.NamedTemporaryFile(suffix=".wfw", delete=False) as tmp:
            tmp.write(bytes.fromhex(hex_blob))
            tmp_path = tmp.name
        try:
            proc = subprocess.run(
                ["netsh", "advfirewall", "import", tmp_path],
                capture_output=True,
                text=True,
                shell=False,
            )
            if proc.returncode != 0:
                return False, proc.stderr.strip()
            return True, "Restored Windows Defender Firewall policy from .wfw snapshot."
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
