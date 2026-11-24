"""Structured, auditable policy storage, import/export, and rollback snapshots."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Optional

from fireguard.models import Policy
from fireguard.validation import ValidationResult, validate_policy

ALLOWED_POLICY_KEYS = {"version", "name", "description", "defaults", "rules", "updated_at"}
ALLOWED_DEFAULT_KEYS = {
    "default_inbound",
    "default_outbound",
    "allow_loopback",
    "allow_established",
    "handle_ipv6_consistently",
    "rollback_timeout_seconds",
}
ALLOWED_RULE_KEYS = {
    "id",
    "name",
    "description",
    "enabled",
    "direction",
    "action",
    "ip_version",
    "source_ips",
    "dest_ips",
    "protocol",
    "source_ports",
    "dest_ports",
    "interface",
    "application",
    "schedule",
    "log_prefix",
    "tags",
}


class PolicyImportError(ValueError):
    """Raised when an imported policy fails structural or semantic validation."""

    def __init__(self, message: str, details: Optional[list[str]] = None) -> None:
        super().__init__(message)
        self.details = details or []


def default_data_dir() -> Path:
    env_dir = os.environ.get("FIREGUARD_DATA_DIR")
    if env_dir:
        return Path(env_dir)
    return Path.home() / ".config" / "fireguard"


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def parse_and_validate_import(raw_json: str) -> tuple[Policy, ValidationResult]:
    """Parse JSON text strictly, rejecting unknown keys or invalid rules."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise PolicyImportError(f"Malformed JSON at line {exc.lineno}, col {exc.colno}: {exc.msg}") from exc

    if not isinstance(data, dict):
        raise PolicyImportError("Policy JSON root must be an object.")

    unknown_top = set(data.keys()) - ALLOWED_POLICY_KEYS
    if unknown_top:
        raise PolicyImportError(f"Unknown top-level policy field(s): {sorted(unknown_top)}")

    defaults_data = data.get("defaults")
    if defaults_data is not None:
        if not isinstance(defaults_data, dict):
            raise PolicyImportError("'defaults' must be an object.")
        unknown_def = set(defaults_data.keys()) - ALLOWED_DEFAULT_KEYS
        if unknown_def:
            raise PolicyImportError(f"Unknown defaults field(s): {sorted(unknown_def)}")

    rules_data = data.get("rules")
    if rules_data is not None:
        if not isinstance(rules_data, list):
            raise PolicyImportError("'rules' must be a list.")
        for idx, item in enumerate(rules_data):
            if not isinstance(item, dict):
                raise PolicyImportError(f"Rule at index {idx} must be an object.")
            unknown_rule = set(item.keys()) - ALLOWED_RULE_KEYS
            if unknown_rule:
                raise PolicyImportError(
                    f"Rule at index {idx} has unknown field(s): {sorted(unknown_rule)}"
                )

    try:
        policy = Policy.from_dict(data)
    except (ValueError, TypeError, KeyError) as exc:
        raise PolicyImportError(f"Invalid policy field value: {exc}") from exc

    validation = validate_policy(policy)
    if not validation.is_valid:
        raise PolicyImportError(
            "Policy failed validation.",
            details=[f"[{e.code}] {e.message}" for e in validation.errors],
        )
    return policy, validation


class PolicyStore:
    """Manages persistent policy JSON and rollback snapshots."""

    def __init__(self, data_dir: Optional[Path] = None) -> None:
        self.data_dir = Path(data_dir) if data_dir else default_data_dir()
        self.policy_path = self.data_dir / "policy.json"
        self.snapshots_dir = self.data_dir / "snapshots"

    def exists(self) -> bool:
        return self.policy_path.exists()

    def load(self) -> Policy:
        if not self.policy_path.exists():
            return Policy()
        raw = self.policy_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        return Policy.from_dict(data)

    def save(self, policy: Policy) -> None:
        policy.updated_at = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(policy.to_dict(), indent=2) + "\n"
        atomic_write_text(self.policy_path, payload)

    def export_json(self, policy: Policy) -> str:
        return json.dumps(policy.to_dict(), indent=2) + "\n"

    def save_snapshot(
        self,
        backend_name: str,
        previous_system_state: str,
        previous_policy: Optional[Policy] = None,
    ) -> Path:
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        snap_path = self.snapshots_dir / f"snapshot-{backend_name}-{ts}.json"
        payload: dict[str, Any] = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "backend": backend_name,
            "previous_system_state": previous_system_state,
            "previous_policy": previous_policy.to_dict() if previous_policy else None,
        }
        atomic_write_text(snap_path, json.dumps(payload, indent=2) + "\n")
        return snap_path

    def list_snapshots(self) -> list[Path]:
        if not self.snapshots_dir.exists():
            return []
        return sorted(self.snapshots_dir.glob("snapshot-*.json"), reverse=True)

    def load_snapshot(self, path: Optional[Path] = None) -> dict[str, Any]:
        target = path
        if target is None:
            snaps = self.list_snapshots()
            if not snaps:
                raise FileNotFoundError("No rollback snapshots found.")
            target = snaps[0]
        return json.loads(Path(target).read_text(encoding="utf-8"))
