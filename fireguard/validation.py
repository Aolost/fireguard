"""Strict validation, conflict detection, and safety analysis for firewall policies."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import re
from typing import Optional

from fireguard.models import (
    Action,
    Direction,
    IPVersion,
    PORTS_PROTOCOLS,
    Policy,
    PortRange,
    Protocol,
    Rule,
    is_block_all_rule,
)

INTERFACE_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,32}$")
RULE_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
TIME_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
VALID_DAYS = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
LOG_PREFIX_RE = re.compile(r"^[a-zA-Z0-9 _.:/-]{1,48}$")

# Ports whose blocking can sever remote management or essential network services.
CRITICAL_PORTS: dict[int, str] = {
    22: "SSH remote management",
    53: "DNS name resolution",
    67: "DHCP server/client",
    68: "DHCP client",
    546: "DHCPv6 client",
    547: "DHCPv6 server",
    3389: "RDP remote desktop",
    5985: "WinRM HTTP remote management",
    5986: "WinRM HTTPS remote management",
}


@dataclass
class ValidationIssue:
    level: str  # "error" | "warning"
    code: str
    message: str
    rule_id: Optional[str] = None

    def to_dict(self) -> dict[str, Optional[str]]:
        return {
            "level": self.level,
            "code": self.code,
            "message": self.message,
            "rule_id": self.rule_id,
        }


@dataclass
class ValidationResult:
    errors: list[ValidationIssue] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def to_dict(self) -> dict[str, object]:
        return {
            "is_valid": self.is_valid,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": [w.to_dict() for w in self.warnings],
        }


def _validate_ip_list(
    ips: list[str], ip_version: IPVersion, field_name: str, rule_id: str
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for raw in ips:
        if not isinstance(raw, str) or not raw.strip():
            issues.append(
                ValidationIssue(
                    "error",
                    "invalid_ip",
                    f"{field_name} contains an empty or non-string IP/CIDR entry.",
                    rule_id,
                )
            )
            continue
        try:
            net = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError as exc:
            issues.append(
                ValidationIssue(
                    "error",
                    "invalid_ip",
                    f"Invalid {field_name} '{raw}': {exc}",
                    rule_id,
                )
            )
            continue

        if ip_version == IPVersion.IPV4 and net.version != 4:
            issues.append(
                ValidationIssue(
                    "error",
                    "ip_version_mismatch",
                    f"{field_name} '{raw}' is IPv6, but rule ip_version is 'ipv4'.",
                    rule_id,
                )
            )
        elif ip_version == IPVersion.IPV6 and net.version != 6:
            issues.append(
                ValidationIssue(
                    "error",
                    "ip_version_mismatch",
                    f"{field_name} '{raw}' is IPv4, but rule ip_version is 'ipv6'.",
                    rule_id,
                )
            )
    return issues


def _validate_ports(
    ports: list[PortRange], protocol: Protocol, field_name: str, rule_id: str
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if ports and protocol not in PORTS_PROTOCOLS:
        issues.append(
            ValidationIssue(
                "error",
                "ports_require_transport_protocol",
                f"{field_name} cannot be specified for protocol '{protocol.value}'. "
                "Use tcp, udp, or sctp.",
                rule_id,
            )
        )
    for pr in ports:
        if pr.start < 1 or pr.start > 65535 or pr.end < 1 or pr.end > 65535:
            issues.append(
                ValidationIssue(
                    "error",
                    "invalid_port",
                    f"{field_name} '{pr.format_str()}' must be between 1 and 65535.",
                    rule_id,
                )
            )
        elif pr.start > pr.end:
            issues.append(
                ValidationIssue(
                    "error",
                    "invalid_port_range",
                    f"{field_name} '{pr.format_str()}' has start > end.",
                    rule_id,
                )
            )
    return issues


def validate_rule(rule: Rule) -> ValidationResult:
    """Validate a single rule for syntax, semantics, and safety warnings."""
    result = ValidationResult()

    if not RULE_ID_RE.match(rule.id):
        result.errors.append(
            ValidationIssue(
                "error",
                "invalid_rule_id",
                f"Rule id '{rule.id}' must match {RULE_ID_RE.pattern}.",
                rule.id,
            )
        )
    if not rule.name.strip():
        result.errors.append(
            ValidationIssue("error", "missing_rule_name", "Rule name is required.", rule.id)
        )
    if any(ch in rule.name for ch in ("\n", "\r", "\x00")):
        result.errors.append(
            ValidationIssue(
                "error",
                "invalid_rule_name",
                "Rule name must not contain control characters.",
                rule.id,
            )
        )

    if rule.protocol == Protocol.ICMP and rule.ip_version == IPVersion.IPV6:
        result.errors.append(
            ValidationIssue(
                "error",
                "icmp_ip_version_mismatch",
                "Use protocol 'icmpv6' for IPv6 rules instead of 'icmp'.",
                rule.id,
            )
        )
    if rule.protocol == Protocol.ICMPV6 and rule.ip_version == IPVersion.IPV4:
        result.errors.append(
            ValidationIssue(
                "error",
                "icmpv6_ip_version_mismatch",
                "Protocol 'icmpv6' cannot be used with ip_version 'ipv4'.",
                rule.id,
            )
        )

    result.errors.extend(_validate_ip_list(rule.source_ips, rule.ip_version, "source_ips", rule.id))
    result.errors.extend(_validate_ip_list(rule.dest_ips, rule.ip_version, "dest_ips", rule.id))
    result.errors.extend(_validate_ports(rule.source_ports, rule.protocol, "source_ports", rule.id))
    result.errors.extend(_validate_ports(rule.dest_ports, rule.protocol, "dest_ports", rule.id))

    if rule.interface is not None and not INTERFACE_RE.match(rule.interface):
        result.errors.append(
            ValidationIssue(
                "error",
                "invalid_interface",
                f"Interface '{rule.interface}' contains invalid characters.",
                rule.id,
            )
        )

    if rule.application is not None:
        if any(ch in rule.application for ch in ("\n", "\r", "\x00", ";", "|", "&", "`", "$")):
            result.errors.append(
                ValidationIssue(
                    "error",
                    "invalid_application_path",
                    "Application path contains disallowed control or shell metacharacters.",
                    rule.id,
                )
            )

    if rule.log_prefix is not None and not LOG_PREFIX_RE.match(rule.log_prefix):
        result.errors.append(
            ValidationIssue(
                "error",
                "invalid_log_prefix",
                "log_prefix may only contain alphanumerics, spaces, and _.:/- (max 48 chars).",
                rule.id,
            )
        )

    if rule.schedule is not None:
        if rule.schedule.expires_at:
            try:
                datetime.fromisoformat(rule.schedule.expires_at.replace("Z", "+00:00"))
            except ValueError:
                result.errors.append(
                    ValidationIssue(
                        "error",
                        "invalid_expiration",
                        f"Invalid ISO-8601 expires_at timestamp: {rule.schedule.expires_at!r}.",
                        rule.id,
                    )
                )
        for fld, val in (
            ("daily_start", rule.schedule.daily_start),
            ("daily_end", rule.schedule.daily_end),
        ):
            if val is not None and not TIME_HHMM_RE.match(val):
                result.errors.append(
                    ValidationIssue(
                        "error",
                        "invalid_schedule_time",
                        f"Schedule {fld} '{val}' must be HH:MM (24-hour).",
                        rule.id,
                    )
                )
        if (rule.schedule.daily_start is None) != (rule.schedule.daily_end is None):
            result.errors.append(
                ValidationIssue(
                    "error",
                    "incomplete_schedule_window",
                    "Both daily_start and daily_end must be set together.",
                    rule.id,
                )
            )
        for d in rule.schedule.days:
            if d.lower() not in VALID_DAYS:
                result.errors.append(
                    ValidationIssue(
                        "error",
                        "invalid_schedule_day",
                        f"Invalid schedule day '{d}'. Must be one of {sorted(VALID_DAYS)}.",
                        rule.id,
                    )
                )

    # Safety warnings for enabled block rules
    if rule.enabled and rule.action == Action.BLOCK:
        if is_block_all_rule(rule):
            result.warnings.append(
                ValidationIssue(
                    "warning",
                    "block_all_traffic",
                    f"Rule '{rule.name}' blocks ALL {rule.direction.value} traffic. "
                    "This may interrupt SSH/RDP, DNS, DHCP, or essential connectivity.",
                    rule.id,
                )
            )
        for port_range in rule.dest_ports + rule.source_ports:
            for cport, desc in CRITICAL_PORTS.items():
                if port_range.contains(cport):
                    result.warnings.append(
                        ValidationIssue(
                            "warning",
                            "blocks_critical_service",
                            f"Rule '{rule.name}' blocks port {cport} ({desc}).",
                            rule.id,
                        )
                    )
        for raw_ip in rule.source_ips + rule.dest_ips:
            try:
                net = ipaddress.ip_network(raw_ip, strict=False)
                if net.is_loopback:
                    result.warnings.append(
                        ValidationIssue(
                            "warning",
                            "blocks_loopback",
                            f"Rule '{rule.name}' targets loopback address {raw_ip}.",
                            rule.id,
                        )
                    )
            except ValueError:
                pass
        if rule.interface and rule.interface in ("lo", "lo0", "Loopback"):
            result.warnings.append(
                ValidationIssue(
                    "warning",
                    "blocks_loopback_interface",
                    f"Rule '{rule.name}' blocks traffic on loopback interface '{rule.interface}'.",
                    rule.id,
                )
            )

    if rule.enabled and rule.schedule and rule.schedule.is_expired():
        result.warnings.append(
            ValidationIssue(
                "warning",
                "rule_expired",
                f"Rule '{rule.name}' has already expired ({rule.schedule.expires_at}) "
                "and will not be enforced.",
                rule.id,
            )
        )

    return result


def _ips_overlap(a: list[str], b: list[str]) -> bool:
    if not a or not b:
        return True
    for raw_a in a:
        try:
            net_a = ipaddress.ip_network(raw_a, strict=False)
        except ValueError:
            continue
        for raw_b in b:
            try:
                net_b = ipaddress.ip_network(raw_b, strict=False)
            except ValueError:
                continue
            if net_a.version == net_b.version and net_a.overlaps(net_b):
                return True
    return False


def _ports_overlap(a: list[PortRange], b: list[PortRange]) -> bool:
    if not a or not b:
        return True
    return any(pa.overlaps(pb) for pa in a for pb in b)


def _rule_subsumes(earlier: Rule, later: Rule) -> bool:
    """Return True if `earlier` matches a superset (or identical set) of `later`'s traffic."""
    if earlier.direction != later.direction:
        return False
    if earlier.ip_version != IPVersion.ANY and earlier.ip_version != later.ip_version:
        return False
    if earlier.protocol != Protocol.ANY and earlier.protocol != later.protocol:
        return False
    if earlier.interface and earlier.interface != later.interface:
        return False
    if earlier.application and earlier.application != later.application:
        return False
    if earlier.source_ips and not _ips_overlap(earlier.source_ips, later.source_ips):
        return False
    if earlier.dest_ips and not _ips_overlap(earlier.dest_ips, later.dest_ips):
        return False
    if earlier.source_ports and not _ports_overlap(earlier.source_ports, later.source_ports):
        return False
    if earlier.dest_ports and not _ports_overlap(earlier.dest_ports, later.dest_ports):
        return False
    # If earlier specifies an IP/port filter and later does NOT, earlier is narrower, not a superset.
    if earlier.source_ips and not later.source_ips:
        return False
    if earlier.dest_ips and not later.dest_ips:
        return False
    if earlier.source_ports and not later.source_ports:
        return False
    if earlier.dest_ports and not later.dest_ports:
        return False
    return True


def validate_policy(policy: Policy) -> ValidationResult:
    """Validate an entire policy, including duplicate IDs, defaults, and rule conflicts."""
    result = ValidationResult()

    if policy.version != 1:
        result.errors.append(
            ValidationIssue(
                "error",
                "unsupported_policy_version",
                f"Unsupported policy version {policy.version}; expected 1.",
            )
        )
    if policy.defaults.default_inbound == Action.LOG or policy.defaults.default_outbound == Action.LOG:
        result.errors.append(
            ValidationIssue(
                "error",
                "invalid_default_action",
                "Default inbound/outbound policy must be 'allow' or 'block', not 'log'.",
            )
        )
    if policy.defaults.rollback_timeout_seconds < 5 or policy.defaults.rollback_timeout_seconds > 600:
        result.errors.append(
            ValidationIssue(
                "error",
                "invalid_rollback_timeout",
                "rollback_timeout_seconds must be between 5 and 600 seconds.",
            )
        )

    if not policy.defaults.allow_loopback:
        result.warnings.append(
            ValidationIssue(
                "warning",
                "loopback_disabled",
                "allow_loopback is disabled. Local IPC and services using 127.0.0.1/::1 may break.",
            )
        )
    if not policy.defaults.allow_established:
        result.warnings.append(
            ValidationIssue(
                "warning",
                "established_disabled",
                "allow_established is disabled. Return traffic for active connections may be dropped.",
            )
        )
    if not policy.defaults.handle_ipv6_consistently:
        result.warnings.append(
            ValidationIssue(
                "warning",
                "ipv6_inconsistent",
                "handle_ipv6_consistently is disabled; IPv6 traffic may bypass IPv4-only restrictions.",
            )
        )

    seen_ids: set[str] = set()
    enabled_rules: list[Rule] = []
    for rule in policy.rules:
        if rule.id in seen_ids:
            result.errors.append(
                ValidationIssue(
                    "error",
                    "duplicate_rule_id",
                    f"Duplicate rule ID '{rule.id}'.",
                    rule.id,
                )
            )
        seen_ids.add(rule.id)

        r_res = validate_rule(rule)
        result.errors.extend(r_res.errors)
        result.warnings.extend(r_res.warnings)

        if rule.enabled:
            enabled_rules.append(rule)

    # Check precedence & shadowing among enabled rules
    for idx, earlier in enumerate(enabled_rules):
        if earlier.action == Action.LOG:
            continue  # LOG rules are non-terminating and do not shadow subsequent rules
        for later in enabled_rules[idx + 1 :]:
            if _rule_subsumes(earlier, later):
                conflict_note = (
                    " (conflicting action!)" if earlier.action != later.action else ""
                )
                result.warnings.append(
                    ValidationIssue(
                        "warning",
                        "rule_shadowed",
                        f"Rule '{later.name}' ({later.id}) may be shadowed by earlier rule "
                        f"'{earlier.name}' ({earlier.id}){conflict_note}. "
                        "First-match-wins precedence applies.",
                        later.id,
                    )
                )

    return result
