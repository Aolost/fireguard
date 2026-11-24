"""Backend discovery and selection."""

from __future__ import annotations

import os
from typing import Optional

from fireguard.backends.base import FirewallBackend
from fireguard.backends.linux_nft import LinuxNftablesBackend
from fireguard.backends.windows_fw import WindowsDefenderBackend

_BACKENDS: dict[str, type[FirewallBackend]] = {
    LinuxNftablesBackend.name: LinuxNftablesBackend,
    WindowsDefenderBackend.name: WindowsDefenderBackend,
}


def list_backends() -> list[FirewallBackend]:
    return [cls() for cls in _BACKENDS.values()]


def get_backend(name: Optional[str] = None) -> FirewallBackend:
    if name is None or name == "auto":
        if os.name == "nt":
            return WindowsDefenderBackend()
        return LinuxNftablesBackend()
    if name not in _BACKENDS:
        raise ValueError(f"Unknown backend '{name}'. Available: {sorted(_BACKENDS.keys())}")
    return _BACKENDS[name]()
