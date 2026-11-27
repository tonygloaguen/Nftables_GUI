from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class Settings:
    backend: Literal["mock", "file", "live"] = "file"
    data_dir: Path = field(default_factory=lambda: Path.home() / ".local/share/nft-gui")
    host: str = "127.0.0.1"
    port: int = 8420
    api_token: str | None = None
    nft_binary: str = "/usr/sbin/nft"
    sudo_binary: str = "/usr/bin/sudo"
    privilege: Literal["sudo", "pkexec"] = "sudo"
    pkexec_binary: str = "/usr/bin/pkexec"
    unshare_binary: str = "/usr/bin/unshare"
    timeout: int = 10
    default_confirm_seconds: int = 60

    def __post_init__(self) -> None:
        if self.backend not in {"mock", "file", "live"}:
            raise ValueError("Backend must be mock, file or live")
        if self.privilege not in {"sudo", "pkexec"}:
            raise ValueError("Privilege backend must be sudo or pkexec")
        if self.timeout != 10:
            raise ValueError("System command timeout must be 10 seconds")
        if not 1 <= self.port <= 65535:
            raise ValueError("Invalid port")
        if not 15 <= self.default_confirm_seconds <= 300:
            raise ValueError("Confirmation deadline must be between 15 and 300 seconds")
        if not self.data_dir.is_absolute():
            raise ValueError("Data directory must be absolute")
        for binary in (self.nft_binary, self.sudo_binary, self.pkexec_binary, self.unshare_binary):
            if not Path(binary).is_absolute():
                raise ValueError("Executable paths must be absolute")
        try:
            local = ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            local = self.host == "localhost"
        if self.api_token is not None and len(self.api_token) < 32:
            raise ValueError("API token must contain at least 32 characters")
        if (not local or self.backend == "live") and not self.api_token:
            raise ValueError("An API token is required for live mode or non-loopback binding")

    @classmethod
    def from_env(cls) -> Settings:
        backend = os.getenv("NFT_GUI_BACKEND", "file")
        privilege = os.getenv("NFT_GUI_PRIVILEGE", "sudo")
        if backend not in {"mock", "file", "live"} or privilege not in {"sudo", "pkexec"}:
            raise ValueError("Invalid NFT_GUI_BACKEND or NFT_GUI_PRIVILEGE")
        from typing import cast
        return cls(
            backend=cast(Literal["mock", "file", "live"], backend),
            data_dir=Path(os.getenv("NFT_GUI_DATA_DIR", str(Path.home() / ".local/share/nft-gui"))),
            host=os.getenv("NFT_GUI_HOST", "127.0.0.1"),
            port=int(os.getenv("NFT_GUI_PORT", "8420")),
            api_token=os.getenv("NFT_GUI_API_TOKEN") or None,
            privilege=cast(Literal["sudo", "pkexec"], privilege),
        )
