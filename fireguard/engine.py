"""OS-independent policy engine: precedence, simulation, and starter policies."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
from typing import Any, Optional

from fireguard.models import (
    Action,
    Direction,
    IPVersion,
    Policy,
    PortRange,
    Protocol,
    Rule,
    SystemDefaults,
    explain_rule,
)
from fireguard.validation import ValidationResult, validate_policy


@dataclass
class PacketQuery:
    """Hypothetical packet/flow for dry-run policy simulation."""

    direction: Direction
    source_ip: str
    dest_ip: str
    protocol: Protocol = Protocol.TCP
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    interface: Optional[str] = None
    application: Optional[str] = None
    established: bool = False


@dataclass
class SimulationResult:
    verdict: Action
    matched_by: str  # e.g. "rule:<id>", "system:loopback", "system:established", "default:inbound"
    matched_rule_name: str
    logged_by: list[str] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "matched_by": self.matched_by,
            "matched_rule_name": self.matched_rule_name,
            "logged_by": list(self.logged_by),
            "trace": list(self.trace),
        }


def _ip_matches(ip_str: str, cidrs: list[str], ip_version: IPVersion) -> bool:
    addr = ipaddress.ip_address(ip_str)
    if ip_version == IPVersion.IPV4 and addr.version != 4:
        return False
    if ip_version == IPVersion.IPV6 and addr.version != 6:
        return False
    if not cidrs:
        return True
    for raw in cidrs:
        net = ipaddress.ip_network(raw, strict=False)
        if addr.version == net.version and addr in net:
            return True
    return False


def _port_matches(port: Optional[int], ranges: list[PortRange]) -> bool:
    if not ranges:
        return True
    if port is None:
        return False
    return any(r.contains(port) for r in ranges)


def _schedule_active(rule: Rule, now: datetime) -> bool:
    if rule.schedule is None:
        return True
    if rule.schedule.is_expired(now):
        return False
    if rule.schedule.days:
        day_name = now.strftime("%a").lower()[:3]
        if day_name not in {d.lower() for d in rule.schedule.days}:
            return False
    if rule.schedule.daily_start and rule.schedule.daily_end:
        hhmm = now.strftime("%H:%M")
        start, end = rule.schedule.daily_start, rule.schedule.daily_end
        if start <= end:
            if not (start <= hhmm <= end):
                return False
        else:  # Overnight window e.g. 22:00 -> 06:00
            if not (hhmm >= start or hhmm <= end):
                return False
    return True


def evaluate_packet(
    policy: Policy, query: PacketQuery, now: Optional[datetime] = None
) -> SimulationResult:
    """Evaluate a packet against the policy using deterministic first-match-wins precedence.

    Precedence order:
    1. Explicit loopback allow (when defaults.allow_loopback is True)
    2. Explicit established/related allow (when defaults.allow_established is True)
    3. Enabled, active rules in listed order (LOG rules record & continue; ALLOW/BLOCK terminate)
    4. Default direction policy (defaults.default_inbound / defaults.default_outbound)
    """
    current = now or datetime.now(timezone.utc)
    trace: list[str] = []
    logged_by: list[str] = []

    src_addr = ipaddress.ip_address(query.source_ip)
    dst_addr = ipaddress.ip_address(query.dest_ip)

    if policy.defaults.allow_loopback and (
        src_addr.is_loopback or dst_addr.is_loopback or query.interface in ("lo", "lo0")
    ):
        trace.append("Matched explicit baseline rule: allow_loopback=True")
        return SimulationResult(
            verdict=Action.ALLOW,
            matched_by="system:loopback",
            matched_rule_name="Allow Loopback",
            logged_by=logged_by,
            trace=trace,
        )

    if policy.defaults.allow_established and query.established:
        trace.append("Matched explicit baseline rule: allow_established=True")
        return SimulationResult(
            verdict=Action.ALLOW,
            matched_by="system:established",
            matched_rule_name="Allow Established/Related",
            logged_by=logged_by,
            trace=trace,
        )

    for idx, rule in enumerate(policy.rules, start=1):
        if not rule.enabled:
            trace.append(f"#{idx} {rule.id} ({rule.name}): skipped (disabled)")
            continue
        if not _schedule_active(rule, current):
            trace.append(f"#{idx} {rule.id} ({rule.name}): skipped (expired/outside schedule)")
            continue
        if rule.direction != query.direction:
            continue
        if rule.protocol != Protocol.ANY and rule.protocol != query.protocol:
            continue
        if not _ip_matches(query.source_ip, rule.source_ips, rule.ip_version):
            continue
        if not _ip_matches(query.dest_ip, rule.dest_ips, rule.ip_version):
            continue
        if not _port_matches(query.source_port, rule.source_ports):
            continue
        if not _port_matches(query.dest_port, rule.dest_ports):
            continue
        if rule.interface and rule.interface != query.interface:
            continue
        if rule.application and rule.application != query.application:
            continue

        if rule.action == Action.LOG:
            logged_by.append(rule.id)
            trace.append(f"#{idx} {rule.id} ({rule.name}): LOG matched, continuing evaluation")
            continue

        trace.append(f"#{idx} {rule.id} ({rule.name}): {rule.action.value.upper()} matched (terminal)")
        return SimulationResult(
            verdict=rule.action,
            matched_by=f"rule:{rule.id}",
            matched_rule_name=rule.name,
            logged_by=logged_by,
            trace=trace,
        )

    default_action = (
        policy.defaults.default_inbound
        if query.direction == Direction.INBOUND
        else policy.defaults.default_outbound
    )
    trace.append(f"No explicit rule matched; applying default_{query.direction.value}={default_action.value}")
    return SimulationResult(
        verdict=default_action,
        matched_by=f"default:{query.direction.value}",
        matched_rule_name=f"Default {query.direction.value.capitalize()} Policy",
        logged_by=logged_by,
        trace=trace,
    )


def inspect_effective_policy(policy: Policy) -> dict[str, Any]:
    """Return a structured, human-readable inspection of effective evaluation order."""
    validation: ValidationResult = validate_policy(policy)
    effective_steps: list[dict[str, Any]] = []

    order = 1
    if policy.defaults.allow_loopback:
        effective_steps.append(
            {
                "order": order,
                "source": "system:loopback",
                "name": "Explicit Loopback Allow",
                "action": "allow",
                "direction": "inbound & outbound",
                "explanation": "Allows 127.0.0.0/8, ::1, and loopback interface traffic.",
            }
        )
        order += 1

    if policy.defaults.allow_established:
        effective_steps.append(
            {
                "order": order,
                "source": "system:established",
                "name": "Explicit Established/Related Allow",
                "action": "allow",
                "direction": "inbound & outbound",
                "explanation": "Allows return packets for already-established connections.",
            }
        )
        order += 1

    for rule in policy.rules:
        effective_steps.append(
            {
                "order": order if rule.enabled else None,
                "source": f"rule:{rule.id}",
                "name": rule.name,
                "enabled": rule.enabled,
                "action": rule.action.value,
                "direction": rule.direction.value,
                "ip_version": rule.ip_version.value,
                "explanation": explain_rule(rule),
            }
        )
        if rule.enabled:
            order += 1

    effective_steps.append(
        {
            "order": order,
            "source": "default:inbound",
            "name": "Default Inbound Policy",
            "action": policy.defaults.default_inbound.value,
            "direction": "inbound",
            "explanation": f"Fallback for unmatched inbound IPv4/IPv6 traffic: {policy.defaults.default_inbound.value}.",
        }
    )
    effective_steps.append(
        {
            "order": order + 1,
            "source": "default:outbound",
            "name": "Default Outbound Policy",
            "action": policy.defaults.default_outbound.value,
            "direction": "outbound",
            "explanation": f"Fallback for unmatched outbound IPv4/IPv6 traffic: {policy.defaults.default_outbound.value}.",
        }
    )

    return {
        "policy_name": policy.name,
        "precedence_model": "first-match-wins (explicit baseline -> ordered rules -> default policy)",
        "ipv6_consistent": policy.defaults.handle_ipv6_consistently,
        "validation": validation.to_dict(),
        "effective_steps": effective_steps,
    }


def starter_policies() -> dict[str, Policy]:
    """Return sensible starter policy templates (never auto-applied)."""
    return {
        "workstation-strict": Policy(
            name="workstation-strict",
            description="Blocks unsolicited inbound connections, allows outbound, protects loopback & established.",
            defaults=SystemDefaults(
                default_inbound=Action.BLOCK,
                default_outbound=Action.ALLOW,
                allow_loopback=True,
                allow_established=True,
                handle_ipv6_consistently=True,
                rollback_timeout_seconds=60,
            ),
            rules=[
                Rule(
                    id="allow-dhcpv6-client",
                    name="Allow DHCPv6 Client",
                    description="Allows inbound DHCPv6 responses on UDP 546.",
                    direction=Direction.INBOUND,
                    action=Action.ALLOW,
                    ip_version=IPVersion.IPV6,
                    protocol=Protocol.UDP,
                    dest_ports=[PortRange(546, 546)],
                ),
                Rule(
                    id="allow-icmpv6-ndp",
                    name="Allow ICMPv6",
                    description="Allows IPv6 neighbor discovery and essential ICMPv6.",
                    direction=Direction.INBOUND,
                    action=Action.ALLOW,
                    ip_version=IPVersion.IPV6,
                    protocol=Protocol.ICMPV6,
                ),
            ],
        ),
        "server-ssh-web": Policy(
            name="server-ssh-web",
            description="Server baseline: blocks unsolicited inbound except SSH (22) and HTTPS (443).",
            defaults=SystemDefaults(
                default_inbound=Action.BLOCK,
                default_outbound=Action.ALLOW,
                allow_loopback=True,
                allow_established=True,
                handle_ipv6_consistently=True,
                rollback_timeout_seconds=60,
            ),
            rules=[
                Rule(
                    id="allow-ssh",
                    name="Allow SSH Management",
                    description="Allows inbound SSH on TCP port 22 (IPv4 & IPv6).",
                    direction=Direction.INBOUND,
                    action=Action.ALLOW,
                    ip_version=IPVersion.ANY,
                    protocol=Protocol.TCP,
                    dest_ports=[PortRange(22, 22)],
                ),
                Rule(
                    id="allow-https",
                    name="Allow HTTPS",
                    description="Allows inbound HTTPS on TCP port 443 (IPv4 & IPv6).",
                    direction=Direction.INBOUND,
                    action=Action.ALLOW,
                    ip_version=IPVersion.ANY,
                    protocol=Protocol.TCP,
                    dest_ports=[PortRange(443, 443)],
                ),
            ],
        ),
        "empty-audit-only": Policy(
            name="empty-audit-only",
            description="Permissive starter policy that allows traffic and logs SSH attempts for testing.",
            defaults=SystemDefaults(
                default_inbound=Action.ALLOW,
                default_outbound=Action.ALLOW,
                allow_loopback=True,
                allow_established=True,
                handle_ipv6_consistently=True,
                rollback_timeout_seconds=60,
            ),
            rules=[
                Rule(
                    id="log-inbound-ssh",
                    name="Log Inbound SSH",
                    description="Logs inbound TCP port 22 connections without blocking.",
                    direction=Direction.INBOUND,
                    action=Action.LOG,
                    ip_version=IPVersion.ANY,
                    protocol=Protocol.TCP,
                    dest_ports=[PortRange(22, 22)],
                    log_prefix="FIREGUARD-SSH",
                ),
            ],
        ),
    }
