from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from nft_gui.config import Settings
from nft_gui.errors import NftError
from nft_gui.executor import NftExecutor
from nft_gui.storage import atomic_write
from nft_gui.transactions import TransactionManager
from tests.support import SOURCE


def isolated_mock_helper(directory: Path) -> Path:
    # Test-only executable: never invokes nft, sudo or unshare.
    path = directory / "mock-validator"
    path.write_text(f"#!{sys.executable}\nimport sys\nsys.exit(0)\n")
    path.chmod(0o700)
    return path


def await_status(path: Path, expected: str, seconds: float = 5) -> dict[str, object]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        state = json.loads(path.read_text())
        if state["status"] == expected:
            return state
        time.sleep(0.025)
    raise AssertionError(f"Guardian did not reach {expected}: {state}")


def test_real_guardian_process_restores_without_api_timer(tmp_path: Path) -> None:
    helper = isolated_mock_helper(tmp_path)
    executor = NftExecutor(Settings(data_dir=tmp_path / "data", unshare_binary=str(helper)))
    manager = TransactionManager(executor)
    transaction = manager.apply(SOURCE)
    # Shorten a persisted deadline without waiting 15 seconds in a unit test.
    from nft_gui.storage import file_lock
    with file_lock(manager.lock_file):
        transaction.expires_at = time.time() - 1
        manager._save(transaction)
    await_status(manager.state_file, "rolled_back")
    assert executor.read_source() == "flush ruleset\n"


def test_guardian_survives_app_process_exit(tmp_path: Path) -> None:
    helper = isolated_mock_helper(tmp_path)
    directory = tmp_path / "data"
    script = '''
import os, sys, time
from pathlib import Path
from nft_gui.config import Settings
from nft_gui.executor import NftExecutor
from nft_gui.transactions import TransactionManager
from nft_gui.storage import file_lock
executor = NftExecutor(Settings(data_dir=Path(sys.argv[1]), unshare_binary=sys.argv[2]))
manager = TransactionManager(executor)
transaction = manager.apply('table inet test {}\\n')
with file_lock(manager.lock_file):
    transaction.expires_at = time.time() + 0.5
    manager._save(transaction)
os._exit(0)
'''
    result = subprocess.run([sys.executable, "-c", script, str(directory), str(helper)],
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
    await_status(directory / "pending.json", "rolled_back")
    assert (directory / "sandbox.nft").read_text() == "flush ruleset\n"


def test_stale_readiness_marker_cannot_arm_apply(tmp_path: Path) -> None:
    executor = NftExecutor(Settings(data_dir=tmp_path))
    identifier = "a" * 32
    atomic_write(tmp_path / "transactions" / f"{identifier}.ready", identifier)
    # No guardian.json: a new guardian cannot initialize. The old marker is stale.
    with pytest.raises(NftError) as error:
        executor.start_watchdog(identifier)
    assert error.value.code == "watchdog_unavailable"
    assert not executor.sandbox.exists()
