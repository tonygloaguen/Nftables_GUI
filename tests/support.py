from __future__ import annotations

import json
import stat
import subprocess
from pathlib import Path
from typing import Any

from nft_gui.config import Settings
from nft_gui.executor import NftExecutor
from nft_gui.transactions import TransactionManager

SOURCE = 'table inet "filter" { chain "forward" { type filter hook forward priority 0; policy drop; } }\n'


class FakeNft:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None, dict[str, Any]]] = []
        self.json: dict[str, Any] = {"nftables": []}
        self.fail_check = False
        self.fail_apply = False
        self.timeout = False

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        source = None
        if "-f" in args:
            path = Path(args[-1])
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            source = path.read_text()
        self.calls.append((args, source, kwargs))
        if self.timeout:
            raise subprocess.TimeoutExpired(args, 10, stderr=b"timed out")
        if "-c" in args and (self.fail_check or (source and "REJECT" in source)):
            raise subprocess.CalledProcessError(1, args, stderr=f"{args[-1]}:4:7-11: Error: invalid rule\n")
        if "-f" in args and "-c" not in args and self.fail_apply:
            self.fail_apply = False
            raise subprocess.TimeoutExpired(args, 10)
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(self.json) if "-j" in args else "", stderr="")


def setup(directory: Path, *, live: bool = False) -> tuple[NftExecutor, TransactionManager, FakeNft, list[float]]:
    clock = [1000.0]
    runner = FakeNft()
    settings = Settings(data_dir=directory, backend="live" if live else "file",
                        api_token="x" * 32 if live else None)
    executor = NftExecutor(settings, runner=runner)
    manager = TransactionManager(executor, watchdog=lambda _: None,
                                 clock=lambda: clock[0], monotonic=lambda: clock[0])
    return executor, manager, runner, clock
