"""Core data models for FireGuard firewall policies and rules."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import uuid


class Direction(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class Action(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    LOG = "log"


class IPVersion(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    ANY = "any"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    GRE = "gre"
    ESP = "esp"
    AH = "ah"
    SCTP = "sctp"
    ANY = "any"


PORTS_PROTOCOLS = {Protocol.TCP, Protocol.UDP, Protocol.SCTP}


@dataclass(frozen=True)
class PortRange:
    """Represents a single port (start == end) or an inclusive port range."""

    start: int
    end: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "start", int(self.start))
        object.__setattr__(self, "end", int(self.end))

    @classmethod
    def parse(cls, value: Any) -> "PortRange":
        if isinstance(value, PortRange):
            return value
        if isinstance(value, int):
            return cls(value, value)
        if isinstance(value, dict):
            return cls(int(value["start"]), int(value["end"]))
        if isinstance(value, str):
            text = value.strip()
            if "-" in text:
                parts = text.split("-", 1)
                return cls(int(parts[0].strip()), int(parts[1].strip()))
            port = int(text)
            return cls(port, port)
        raise ValueError(f"Invalid port specification: {value!r}")

    def to_dict(self) -> dict[str, int]:
        return {"start": self.start, "end": self.end}

    def format_str(self) -> str:
        return str(self.start) if self.start == self.end else f"{self.start}-{self.end}"

    def contains(self, port: int) -> bool:
        return self.start <= port <= self.end

    def overlaps(self, other: "PortRange") -> bool:
        return self.start <= other.end and other.start <= self.end


@dataclass
class Schedule:
    """Optional schedule or expiration for a rule.

    Note: Neither Linux nftables nor Windows Defender Firewall natively
    evaluates arbitrary recurring time windows inside kernel packet filters
    without external re-evaluation or OS task schedulers.
    """

    expires_at: Optional[str] = None  # ISO-8601 UTC timestamp
    daily_start: Optional[str] = None  # HH:MM (24h UTC)
    daily_end: Optional[str] = None    # HH:MM (24h UTC)
    days: list[str] = field(default_factory=list)  # e.g. ["mon", "tue"]

    @classmethod
    def from_dict(cls, data: Optional[dict[str, Any]]) -> Optional["Schedule"]:
        if not data:
            return None
        return cls(
            expires_at=data.get("expires_at"),
            daily_start=data.get("daily_start"),
            daily_end=data.get("daily_end"),
            days=list(data.get("days") or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "expires_at": self.expires_at,
            "daily_start": self.daily_start,
            "daily_end": self.daily_end,
            "days": list(self.days),
        }

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if not self.expires_at:
            return False
        current = now or datetime.now(timezone.utc)
        exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return current >= exp


@dataclass
class Rule:
    """Single firewall rule in an ordered policy."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""
    enabled: bool = True
    direction: Direction = Direction.INBOUND
    action: Action = Action.BLOCK
    ip_version: IPVersion = IPVersion.ANY
    source_ips: list[str] = field(default_factory=list)
    dest_ips: list[str] = field(default_factory=list)
    protocol: Protocol = Protocol.ANY
    source_ports: list[PortRange] = field(default_factory=list)
    dest_ports: list[PortRange] = field(default_factory=list)
    interface: Optional[str] = None
    application: Optional[str] = None
    schedule: Optional[Schedule] = None
    log_prefix: Optional[str] = None
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        return cls(
            id=str(data.get("id") or str(uuid.uuid4())[:8]),
            name=str(data.get("name") or ""),
            description=str(data.get("description") or ""),
            enabled=bool(data.get("enabled", True)),
            direction=Direction(data.get("direction", "inbound")),
            action=Action(data.get("action", "block")),
            ip_version=IPVersion(data.get("ip_version", "any")),
            source_ips=list(data.get("source_ips") or []),
            dest_ips=list(data.get("dest_ips") or []),
            protocol=Protocol(data.get("protocol", "any")),
            source_ports=[PortRange.parse(p) for p in (data.get("source_ports") or [])],
            dest_ports=[PortRange.parse(p) for p in (data.get("dest_ports") or [])],
            interface=data.get("interface") or None,
            application=data.get("application") or None,
            schedule=Schedule.from_dict(data.get("schedule")),
            log_prefix=data.get("log_prefix") or None,
            tags=list(data.get("tags") or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "direction": self.direction.value,
            "action": self.action.value,
            "ip_version": self.ip_version.value,
            "source_ips": list(self.source_ips),
            "dest_ips": list(self.dest_ips),
            "protocol": self.protocol.value,
            "source_ports": [p.to_dict() for p in self.source_ports],
            "dest_ports": [p.to_dict() for p in self.dest_ports],
            "interface": self.interface,
            "application": self.application,
            "schedule": self.schedule.to_dict() if self.schedule else None,
            "log_prefix": self.log_prefix,
            "tags": list(self.tags),
        }


@dataclass
class SystemDefaults:
    """Explicit handling for baseline traffic and default policy verdicts."""

    default_inbound: Action = Action.BLOCK
    default_outbound: Action = Action.ALLOW
    allow_loopback: bool = True
    allow_established: bool = True
    handle_ipv6_consistently: bool = True
    rollback_timeout_seconds: int = 60

    @classmethod
    def from_dict(cls, data: Optional[dict[str, Any]]) -> "SystemDefaults":
        if not data:
            return cls()
        return cls(
            default_inbound=Action(data.get("default_inbound", "block")),
            default_outbound=Action(data.get("default_outbound", "allow")),
            allow_loopback=bool(data.get("allow_loopback", True)),
            allow_established=bool(data.get("allow_established", True)),
            handle_ipv6_consistently=bool(data.get("handle_ipv6_consistently", True)),
            rollback_timeout_seconds=int(data.get("rollback_timeout_seconds", 60)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "default_inbound": self.default_inbound.value,
            "default_outbound": self.default_outbound.value,
            "allow_loopback": self.allow_loopback,
            "allow_established": self.allow_established,
            "handle_ipv6_consistently": self.handle_ipv6_consistently,
            "rollback_timeout_seconds": self.rollback_timeout_seconds,
        }


@dataclass
class Policy:
    """Complete firewall policy document."""

    version: int = 1
    name: str = "default-policy"
    description: str = "Configurable host firewall policy"
    defaults: SystemDefaults = field(default_factory=SystemDefaults)
    rules: list[Rule] = field(default_factory=list)
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        return cls(
            version=int(data.get("version", 1)),
            name=str(data.get("name") or "default-policy"),
            description=str(data.get("description") or ""),
            defaults=SystemDefaults.from_dict(data.get("defaults")),
            rules=[Rule.from_dict(r) for r in (data.get("rules") or [])],
            updated_at=str(
                data.get("updated_at") or datetime.now(timezone.utc).isoformat()
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "defaults": self.defaults.to_dict(),
            "rules": [r.to_dict() for r in self.rules],
            "updated_at": self.updated_at,
        }


def is_block_all_rule(rule: Rule) -> bool:
    """Return True if the rule blocks all traffic for its direction (and IP version)."""
    return (
        rule.action == Action.BLOCK
        and rule.protocol == Protocol.ANY
        and not rule.source_ips
        and not rule.dest_ips
        and not rule.source_ports
        and not rule.dest_ports
        and not rule.interface
        and not rule.application
    )


def explain_rule(rule: Rule) -> str:
    """Return a clear, plain-English explanation of what a rule matches and its impact."""
    status = "ENABLED" if rule.enabled else "DISABLED"
    verdict = {
        Action.ALLOW: "Allows",
        Action.BLOCK: "Blocks",
        Action.LOG: "Logs (without dropping or allowing)",
    }[rule.action]

    ip_scope = {
        IPVersion.ANY: "IPv4 and IPv6",
        IPVersion.IPV4: "IPv4 only",
        IPVersion.IPV6: "IPv6 only",
    }[rule.ip_version]

    proto = "all protocols" if rule.protocol == Protocol.ANY else rule.protocol.value.upper()
    src_ip = ", ".join(rule.source_ips) if rule.source_ips else "any source IP"
    dst_ip = ", ".join(rule.dest_ips) if rule.dest_ips else "any destination IP"

    parts = [
        f"[{status}] {verdict} {rule.direction.value} {ip_scope} {proto} traffic",
        f"from {src_ip} to {dst_ip}",
    ]

    if rule.source_ports:
        parts.append(
            "source port(s) " + ", ".join(p.format_str() for p in rule.source_ports)
        )
    if rule.dest_ports:
        parts.append(
            "destination port(s) " + ", ".join(p.format_str() for p in rule.dest_ports)
        )
    if rule.interface:
        parts.append(f"on interface '{rule.interface}'")
    if rule.application:
        parts.append(f"for application '{rule.application}'")
    if rule.schedule and rule.schedule.expires_at:
        parts.append(f"(expires at {rule.schedule.expires_at})")

    explanation = " ".join(parts) + "."

    if is_block_all_rule(rule):
        explanation += (
            " WARNING: This is a broad 'block all' rule for "
            f"{rule.direction.value} traffic and may interrupt remote access "
            "(SSH/RDP), DNS, DHCP, or other essential services unless earlier "
            "explicit allow rules or loopback/established rules permit them."
        )
    return explanation
