from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from nft_gui.errors import ConflictError, NftError
from nft_gui.storage import atomic_write
from nft_gui.transactions import TransactionManager
from tests.support import SOURCE, setup


def test_snapshot_created_before_apply_and_confirm_is_idempotent(tmp_path: Path) -> None:
    executor, manager, _, clock = setup(tmp_path)
    original = executor.read_source()
    def guardian_ready(identifier: str) -> None:
        state = json.loads(manager.state_file.read_text())
        assert state["id"] == identifier and state["status"] == "prepared"
        assert executor.read_source() == original
        assert (manager.snapshots / f"{state['snapshot_id']}.nft").read_text() == original
        assert (manager.snapshots / f"{state['snapshot_id']}.json").exists()
    manager.watchdog = guardian_ready
    tx = manager.apply(SOURCE, confirm_seconds=30)
    assert tx.status == "pending"
    assert manager.confirm(tx.id).status == "confirmed"
    assert manager.confirm(tx.id).status == "confirmed"
    clock[0] += 100
    manager.expire()
    assert executor.read_source().endswith(SOURCE)


@pytest.mark.parametrize("reason", ["manual", "timeout", "late_confirm", "reboot"])
def test_restore_original_ruleset(tmp_path: Path, reason: str) -> None:
    executor, manager, _, clock = setup(tmp_path)
    original = executor.apply('table inet "original" {}\n')
    tx = manager.apply(SOURCE, confirm_seconds=15)
    if reason == "manual":
        assert manager.rollback(tx.id).status == "rolled_back"
        assert manager.rollback(tx.id).status == "rolled_back"
    else:
        if reason == "reboot":
            tx.boot = "a-different-boot-id"
            manager._save(tx)
        else:
            clock[0] += 15
        if reason == "late_confirm":
            with pytest.raises(ConflictError):
                manager.confirm(tx.id)
        else:
            manager.expire()
    assert executor.read_source() == original
    assert manager.get(tx.id).status == "rolled_back"


def test_recover_persisted_pending_transaction(tmp_path: Path) -> None:
    executor, manager, _, clock = setup(tmp_path)
    tx = manager.apply(SOURCE)
    started: list[str] = []
    restarted = TransactionManager(executor, watchdog=started.append,
                                   clock=lambda: clock[0], monotonic=lambda: clock[0])
    restarted.recover()
    assert started == [tx.id]
    clock[0] += 100
    restarted.recover()
    assert executor.read_source() == "flush ruleset\n"


def test_new_apply_blocked_until_previous_is_closed(tmp_path: Path) -> None:
    _, manager, _, _ = setup(tmp_path)
    def apply() -> str:
        try:
            return manager.apply(SOURCE).status
        except ConflictError:
            return "conflict"
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda _: apply(), range(2)))
    assert sorted(results) == ["conflict", "pending"]


def test_guardian_failure_aborts_without_modification(tmp_path: Path) -> None:
    executor, manager, _, _ = setup(tmp_path)
    def unavailable(_: str) -> None:
        raise NftError("No guardian")
    manager.watchdog = unavailable
    with pytest.raises(NftError):
        manager.apply(SOURCE)
    assert not executor.sandbox.exists()
    assert json.loads(manager.state_file.read_text())["status"] == "aborted"


def test_invalid_candidate_has_no_transaction_or_snapshot(tmp_path: Path) -> None:
    executor, manager, runner, _ = setup(tmp_path)
    runner.fail_check = True
    with pytest.raises(NftError):
        manager.apply(SOURCE)
    assert not manager.state_file.exists()
    assert not list(manager.snapshots.iterdir())
    assert not executor.sandbox.exists()


def test_snapshot_tampering_fails_closed(tmp_path: Path) -> None:
    executor, manager, _, clock = setup(tmp_path)
    tx = manager.apply(SOURCE)
    atomic_write(manager.snapshots / f"{tx.snapshot_id}.nft", "flush ruleset\n")
    # Original empty snapshot happens to be identical; corrupt its bytes explicitly.
    atomic_write(manager.snapshots / f"{tx.snapshot_id}.nft", "flush ruleset\n# modified\n")
    clock[0] += 100
    with pytest.raises(NftError, match="hash"):
        manager.expire()
    assert manager.get(tx.id).status == "rollback_failed"
    with pytest.raises(ConflictError):
        manager.apply(SOURCE)
    assert executor.read_source().endswith(SOURCE)


def test_failed_rollback_retries_and_revalidates(tmp_path: Path) -> None:
    executor, manager, runner, clock = setup(tmp_path)
    tx = manager.apply(SOURCE)
    runner.fail_check = True
    clock[0] += 100
    with pytest.raises(NftError):
        manager.expire()
    assert manager.get(tx.id).status == "rollback_failed"
    runner.fail_check = False
    manager.expire()
    assert executor.read_source() == "flush ruleset\n"


@pytest.mark.parametrize("content", ["{bad", "{}", "[]", '{"status":"pending"}'])
def test_corrupt_state_blocks_apply(tmp_path: Path, content: str) -> None:
    _, manager, runner, _ = setup(tmp_path)
    atomic_write(manager.state_file, content)
    with pytest.raises(NftError) as error:
        manager.apply(SOURCE)
    assert error.value.code == "corrupt_state"
    assert not runner.calls


def test_transaction_id_path_traversal_rejected(tmp_path: Path) -> None:
    _, manager, _, _ = setup(tmp_path)
    with pytest.raises(NftError):
        manager.get("../../guardian")


def test_audit_failure_prevents_apply_but_not_rollback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executor, manager, _, clock = setup(tmp_path)
    tx = manager.apply(SOURCE)
    def broken(*args: object, **kwargs: object) -> None:
        raise OSError("disk full")
    monkeypatch.setattr(executor.audit, "record", broken)
    with pytest.raises(OSError):
        manager.confirm(tx.id)
    clock[0] += 100
    manager.expire()
    assert manager.get(tx.id).status == "rolled_back"
    assert executor.sandbox.read_text() == "flush ruleset\n"


def test_old_guardian_cannot_touch_new_transaction(tmp_path: Path) -> None:
    _, manager, _, clock = setup(tmp_path)
    first = manager.apply(SOURCE)
    manager.confirm(first.id)
    second = manager.apply(SOURCE)
    clock[0] += 100
    manager.expire(expected_id=first.id)
    assert manager.get(second.id).status == "pending"
