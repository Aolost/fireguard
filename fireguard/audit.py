"""Structured, non-sensitive JSONL audit logging for FireGuard."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Optional

from fireguard.storage import default_data_dir

REDACTED_KEYS = {"token", "password", "secret", "credential", "authorization", "api_key"}


def _sanitize_details(details: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not details:
        return {}
    clean: dict[str, Any] = {}
    for k, v in details.items():
        if any(rk in k.lower() for rk in REDACTED_KEYS):
            clean[k] = "[REDACTED]"
        elif isinstance(v, dict):
            clean[k] = _sanitize_details(v)
        else:
            clean[k] = v
    return clean


class AuditLogger:
    """Append-only JSONL audit log for policy & firewall state events."""

    def __init__(self, data_dir: Optional[Path] = None) -> None:
        base = Path(data_dir) if data_dir else default_data_dir()
        self.log_path = base / "audit.jsonl"

    def log(
        self,
        event: str,
        outcome: str = "success",
        actor: str = "local-admin",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "outcome": outcome,
            "actor": actor,
            "details": _sanitize_details(details),
        }
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")

    def read_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        recent = lines[-limit:] if limit > 0 else lines
        records: list[dict[str, Any]] = []
        for line in reversed(recent):
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records
