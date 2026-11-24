"""Linux nftables backend using an isolated dual-stack `table inet fireguard`."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import os
import shutil
import subprocess
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

TABLE_NAME = "fireguard"


def _nft_ports(ports: list[PortRange]) -> str:
    if len(ports) == 1:
        p = ports[0]
        return str(p.start) if p.start == p.end else f"{p.start}-{p.end}"
    items = [str(p.start) if p.start == p.end else f"{p.start}-{p.end}" for p in ports]
    return "{ " + ", ".join(items) + " }"


def _split_cidrs_by_family(cidrs: list[str]) -> tuple[list[str], list[str]]:
    v4: list[str] = []
    v6: list[str] = []
    for raw in cidrs:
        net = ipaddress.ip_network(raw, strict=False)
        if net.version == 4:
            v4.append(str(net))
        else:
            v6.append(str(net))
    return v4, v6


def _nft_ip_set(cidrs: list[str]) -> str:
    if len(cidrs) == 1:
        return cidrs[0]
    return "{ " + ", ".join(cidrs) + " }"


def _nft_verdict(rule: Rule) -> str:
    if rule.action == Action.ALLOW:
        return "accept"
    if rule.action == Action.BLOCK:
        return "drop"
    prefix = (rule.log_prefix or f"FIREGUARD-{rule.id}").replace('"', "")
    return f'log prefix "{prefix}: "'


def _render_rule_lines(rule: Rule) -> tuple[list[str], list[str]]:
    """Render a single Rule into nftables statements + any warnings."""
    warnings: list[str] = []
    if rule.application:
        warnings.append(
            f"Rule '{rule.name}' ({rule.id}) specifies application '{rule.application}', "
            "which Linux nftables cannot reliably match by executable path. Rule skipped on Linux."
        )
        return [], warnings

    if rule.schedule:
        if rule.schedule.is_expired(datetime.now(timezone.utc)):
            return [f"# Skipped expired rule {rule.id} ({rule.name})"], warnings
        if rule.schedule.daily_start or rule.schedule.days:
            warnings.append(
                f"Rule '{rule.name}' ({rule.id}) has a recurring schedule; nftables does not "
                "auto-expire or toggle rules without re-applying via a timer."
            )

    # Determine which IP families to emit for this rule
    src_v4, src_v6 = _split_cidrs_by_family(rule.source_ips)
    dst_v4, dst_v6 = _split_cidrs_by_family(rule.dest_ips)

    families: list[Optional[int]]
    if rule.ip_version == IPVersion.IPV4:
        families = [4]
    elif rule.ip_version == IPVersion.IPV6:
        families = [6]
    elif rule.source_ips or rule.dest_ips:
        families = []
        if (not rule.source_ips or src_v4) and (not rule.dest_ips or dst_v4):
            families.append(4)
        if (not rule.source_ips or src_v6) and (not rule.dest_ips or dst_v6):
            families.append(6)
        if not families:
            warnings.append(
                f"Rule '{rule.name}' ({rule.id}) mixes IPv4 and IPv6 in source_ips/dest_ips "
                "with no matching single-family pair."
            )
            return [], warnings
    else:
        families = [None]  # Single dual-stack inet rule

    lines: list[str] = []
    for fam in families:
        clauses: list[str] = []
        if rule.interface:
            iface_kw = "iifname" if rule.direction == Direction.INBOUND else "oifname"
            clauses.append(f'{iface_kw} "{rule.interface}"')

        if fam == 4:
            if src_v4:
                clauses.append(f"ip saddr {_nft_ip_set(src_v4)}")
            if dst_v4:
                clauses.append(f"ip daddr {_nft_ip_set(dst_v4)}")
            if not src_v4 and not dst_v4 and rule.ip_version == IPVersion.IPV4:
                clauses.append("meta nfproto ipv4")
        elif fam == 6:
            if src_v6:
                clauses.append(f"ip6 saddr {_nft_ip_set(src_v6)}")
            if dst_v6:
                clauses.append(f"ip6 daddr {_nft_ip_set(dst_v6)}")
            if not src_v6 and not dst_v6 and rule.ip_version == IPVersion.IPV6:
                clauses.append("meta nfproto ipv6")

        if rule.protocol != Protocol.ANY:
            proto_str = rule.protocol.value
            if rule.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
                if rule.source_ports:
                    clauses.append(f"{proto_str} sport {_nft_ports(rule.source_ports)}")
                if rule.dest_ports:
                    clauses.append(f"{proto_str} dport {_nft_ports(rule.dest_ports)}")
                if not rule.source_ports and not rule.dest_ports:
                    clauses.append(f"meta l4proto {proto_str}")
            elif rule.protocol == Protocol.ICMP:
                clauses.append("meta l4proto icmp")
            elif rule.protocol == Protocol.ICMPV6:
                clauses.append("meta l4proto icmpv6")
            else:
                clauses.append(f"meta l4proto {proto_str}")

        clauses.append(_nft_verdict(rule))
        clauses.append(f'comment "fireguard:{rule.id}"')
        lines.append("        " + " ".join(clauses))

    return lines, warnings


class LinuxNftablesBackend(FirewallBackend):
    """Manages an isolated `table inet fireguard` in Linux nftables."""

    name = "linux-nftables"
    platform_name = "Linux (nftables)"

    def capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            supports_application_match=False,
            supports_schedule=False,
            supports_log_action=True,
            supports_rollback=True,
            requires_elevation=True,
            elevation_reason=(
                "Modifying kernel nftables rules requires root privileges (CAP_NET_ADMIN / sudo)."
            ),
            limitations=[
                "Executable/application path matching is not supported natively in nftables.",
                "Rule schedules/expirations are not auto-enforced by the kernel without a timer.",
                "Manages only `table inet fireguard`; unrelated system tables are left untouched.",
            ],
        )

    def check_availability(self) -> tuple[bool, str]:
        if os.name != "posix" or os.uname().sysname.lower() != "linux":
            return False, "Linux nftables backend is only available on Linux."
        nft_path = shutil.which("nft")
        if not nft_path:
            return False, "`nft` binary not found in PATH."
        return True, f"Available ({nft_path})"

    def is_elevated(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def capture_state(self) -> str:
        avail, reason = self.check_availability()
        if not avail:
            return f"# unavailable: {reason}\n"
        proc = subprocess.run(
            ["nft", "list", "table", "inet", TABLE_NAME],
            capture_output=True,
            text=True,
            shell=False,
        )
        if proc.returncode != 0:
            return "# table_absent\n"
        return proc.stdout

    def render_preview(self, policy: Policy) -> PreviewResult:
        validation = validate_policy(policy)
        warnings = [w.message for w in validation.warnings]
        unsupported: list[dict[str, str]] = []
        summary: list[str] = [
            f"Target: Linux nftables `table inet {TABLE_NAME}` (dual-stack IPv4 + IPv6).",
            f"Default inbound: {policy.defaults.default_inbound.value}, "
            f"Default outbound: {policy.defaults.default_outbound.value}.",
            f"Explicit loopback allow: {policy.defaults.allow_loopback}, "
            f"Explicit established/related allow: {policy.defaults.allow_established}.",
            "Existing non-FireGuard nftables tables will NOT be flushed or modified.",
        ]

        in_lines: list[str] = []
        out_lines: list[str] = []

        if policy.defaults.allow_loopback:
            in_lines.append('        iifname "lo" accept comment "fireguard:loopback"')
            out_lines.append('        oifname "lo" accept comment "fireguard:loopback"')

        if policy.defaults.allow_established:
            in_lines.append('        ct state established,related accept comment "fireguard:established"')
            out_lines.append('        ct state established,related accept comment "fireguard:established"')

        for rule in policy.rules:
            if not rule.enabled:
                continue
            rendered, rule_warnings = _render_rule_lines(rule)
            warnings.extend(rule_warnings)
            if rule.application:
                unsupported.append(
                    {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "reason": "Executable path matching is unsupported in native nftables.",
                    }
                )
                continue
            if rule.direction == Direction.INBOUND:
                in_lines.extend(rendered)
            else:
                out_lines.extend(rendered)

        in_policy = "accept" if policy.defaults.default_inbound == Action.ALLOW else "drop"
        out_policy = "accept" if policy.defaults.default_outbound == Action.ALLOW else "drop"

        script_lines = [
            f"add table inet {TABLE_NAME}",
            f"delete table inet {TABLE_NAME}",
            f"table inet {TABLE_NAME} {{",
            "    chain input {",
            f"        type filter hook input priority 0; policy {in_policy};",
            *in_lines,
            "    }",
            "    chain output {",
            f"        type filter hook output priority 0; policy {out_policy};",
            *out_lines,
            "    }",
            "}",
            "",
        ]
        script = "\n".join(script_lines)

        syntax_checked = False
        syntax_valid: Optional[bool] = None
        syntax_message: Optional[str] = None
        avail, _ = self.check_availability()
        if avail:
            proc = subprocess.run(
                ["nft", "-c", "-f", "-"],
                input=script,
                capture_output=True,
                text=True,
                shell=False,
            )
            syntax_checked = True
            syntax_valid = proc.returncode == 0
            syntax_message = proc.stderr.strip() or "nft syntax check passed"

        return PreviewResult(
            backend_name=self.name,
            platform_name=self.platform_name,
            dry_run=True,
            summary=summary,
            warnings=warnings,
            unsupported_rules=unsupported,
            rendered_script=script,
            syntax_checked=syntax_checked,
            syntax_valid=syntax_valid,
            syntax_message=syntax_message,
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
                "Elevation required: run with root/CAP_NET_ADMIN privileges (e.g. sudo) to apply live nftables rules.",
            )

        validation = validate_policy(policy)
        if not validation.is_valid:
            return ApplyResult(
                False,
                False,
                self.name,
                "Policy has validation errors and cannot be applied: "
                + "; ".join(e.message for e in validation.errors),
            )

        preview = self.render_preview(policy)
        prev_state = self.capture_state()
        snap_path = store.save_snapshot(self.name, prev_state, previous_policy)

        proc = subprocess.run(
            ["nft", "-f", "-"],
            input=preview.rendered_script,
            capture_output=True,
            text=True,
            shell=False,
        )
        if proc.returncode != 0:
            return ApplyResult(
                False,
                False,
                self.name,
                f"nftables apply failed: {proc.stderr.strip()}",
                snapshot_path=str(snap_path),
            )

        timeout = policy.defaults.rollback_timeout_seconds
        if confirm_callback is not None:
            confirmed = confirm_callback(timeout)
            if not confirmed:
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
            "Applied policy to `table inet fireguard`.",
            snapshot_path=str(snap_path),
            pending_confirmation=(confirm_callback is None),
        )

    def rollback(self, snapshot_data: dict[str, Any]) -> tuple[bool, str]:
        avail, reason = self.check_availability()
        if not avail:
            return False, reason
        if not self.is_elevated():
            return False, "Elevation required to roll back live nftables rules."

        prev = snapshot_data.get("previous_system_state", "")
        if prev.strip() == "# table_absent":
            proc = subprocess.run(
                ["nft", "delete", "table", "inet", TABLE_NAME],
                capture_output=True,
                text=True,
                shell=False,
            )
            if proc.returncode == 0 or "No such file or directory" in proc.stderr:
                return True, f"Removed `table inet {TABLE_NAME}` (did not exist previously)."
            return False, proc.stderr.strip()

        restore_script = f"add table inet {TABLE_NAME}\ndelete table inet {TABLE_NAME}\n{prev}\n"
        proc = subprocess.run(
            ["nft", "-f", "-"],
            input=restore_script,
            capture_output=True,
            text=True,
            shell=False,
        )
        if proc.returncode != 0:
            return False, f"Rollback failed: {proc.stderr.strip()}"
        return True, f"Restored previous `table inet {TABLE_NAME}` state."
