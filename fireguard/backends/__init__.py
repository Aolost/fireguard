"""OS-specific firewall backend implementations."""

from fireguard.backends.base import (
    ApplyResult,
    BackendCapabilities,
    FirewallBackend,
    PreviewResult,
)
from fireguard.backends.registry import get_backend, list_backends

__all__ = [
    "ApplyResult",
    "BackendCapabilities",
    "FirewallBackend",
    "PreviewResult",
    "get_backend",
    "list_backends",
]
