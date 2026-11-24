"""Abstract base classes and result types for OS firewall backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from fireguard.models import Policy
from fireguard.storage import PolicyStore


@dataclass
class BackendCapabilities:
    supports_application_match: bool
    supports_schedule: bool
    supports_log_action: bool
    supports_rollback: bool
    requires_elevation: bool
    elevation_reason: str
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "supports_application_match": self.supports_application_match,
            "supports_schedule": self.supports_schedule,
            "supports_log_action": self.supports_log_action,
            "supports_rollback": self.supports_rollback,
            "requires_elevation": self.requires_elevation,
            "elevation_reason": self.elevation_reason,
            "limitations": list(self.limitations),
        }


@dataclass
class PreviewResult:
    backend_name: str
    platform_name: str
    dry_run: bool
    summary: list[str]
    warnings: list[str]
    unsupported_rules: list[dict[str, str]]
    rendered_script: str
    syntax_checked: bool = False
    syntax_valid: Optional[bool] = None
    syntax_message: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend_name": self.backend_name,
            "platform_name": self.platform_name,
            "dry_run": self.dry_run,
            "summary": list(self.summary),
            "warnings": list(self.warnings),
            "unsupported_rules": list(self.unsupported_rules),
            "rendered_script": self.rendered_script,
            "syntax_checked": self.syntax_checked,
            "syntax_valid": self.syntax_valid,
            "syntax_message": self.syntax_message,
        }


@dataclass
class ApplyResult:
    success: bool
    dry_run: bool
    backend_name: str
    message: str
    snapshot_path: Optional[str] = None
    rolled_back: bool = False
    pending_confirmation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "dry_run": self.dry_run,
            "backend_name": self.backend_name,
            "message": self.message,
            "snapshot_path": self.snapshot_path,
            "rolled_back": self.rolled_back,
            "pending_confirmation": self.pending_confirmation,
        }


class FirewallBackend(ABC):
    """Interface for OS-specific firewall rule translation and application."""

    name: str
    platform_name: str

    @abstractmethod
    def capabilities(self) -> BackendCapabilities:
        """Describe what this backend supports and its platform limitations."""

    @abstractmethod
    def check_availability(self) -> tuple[bool, str]:
        """Return (is_available, reason) on the current host."""

    @abstractmethod
    def is_elevated(self) -> bool:
        """Return True if the current process has privileges to modify live rules."""

    @abstractmethod
    def capture_state(self) -> str:
        """Capture current firewall state for rollback."""

    @abstractmethod
    def render_preview(self, policy: Policy) -> PreviewResult:
        """Translate policy into native rules/commands without touching live state."""

    @abstractmethod
    def apply_live(
        self,
        policy: Policy,
        store: PolicyStore,
        confirm_callback: Optional[Callable[[int], bool]] = None,
        previous_policy: Optional[Policy] = None,
    ) -> ApplyResult:
        """Save snapshot, apply policy, and roll back if confirmation fails."""

    @abstractmethod
    def rollback(self, snapshot_data: dict[str, Any]) -> tuple[bool, str]:
        """Restore firewall state from a previously saved snapshot."""
