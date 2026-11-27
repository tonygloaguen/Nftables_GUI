from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from nft_gui.config import Settings
from nft_gui.errors import NftError
from nft_gui.executor.policy import prepare_source
from nft_gui.storage import atomic_write, read_private
from tests.support import SOURCE, setup


def test_default_binding_and_backend(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    assert (settings.backend, settings.host, settings.port, settings.timeout) == ("file", "127.0.0.1", 8420, 10)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.20", "public.example"])
def test_remote_binding_requires_auth(tmp_path: Path, host: str) -> None:
    with pytest.raises(ValueError, match="token"):
        Settings(data_dir=tmp_path, host=host)
    assert Settings(data_dir=tmp_path, host=host, api_token="x" * 32).host == host


def test_live_requires_auth(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="token"):
        Settings(data_dir=tmp_path, backend="live")


def test_file_check_is_isolated_and_never_applies_to_kernel(tmp_path: Path) -> None:
    executor, _, runner, _ = setup(tmp_path)
    result = executor.apply(SOURCE)
    assert executor.read_source() == result == "flush ruleset\n" + SOURCE
    assert len(runner.calls) == 1
    args, _, kwargs = runner.calls[0]
    assert args[:6] == ["/usr/bin/unshare", "--user", "--map-root-user", "--net", "--", "/usr/sbin/nft"]
    assert args[6:8] == ["-c", "-f"]
    assert kwargs["shell"] is False and kwargs["timeout"] == 10 and kwargs["check"] is True
    assert not list(executor.temporary.iterdir())
    assert stat.S_IMODE(executor.sandbox.stat().st_mode) == 0o600


def test_live_uses_allowlisted_sudo_command_and_same_validated_path(tmp_path: Path) -> None:
    executor, _, runner, _ = setup(tmp_path, live=True)
    executor.read_json()
    executor.apply(SOURCE)
    assert runner.calls[0][0] == ["/usr/bin/sudo", "-n", "--", "/usr/sbin/nft", "-j", "list", "ruleset"]
    check, apply = runner.calls[1:]
    assert check[0][4:6] == ["-c", "-f"]
    assert apply[0][4] == "-f"
    assert check[0][-1] == apply[0][-1]
    assert check[1] == apply[1]
    assert not executor.sandbox.exists()


def test_invalid_configuration_keeps_sandbox_and_stderr(tmp_path: Path) -> None:
    executor, _, runner, _ = setup(tmp_path)
    original = executor.apply(SOURCE)
    runner.fail_check = True
    with pytest.raises(NftError) as error:
        executor.apply('table inet "invalid" {}')
    assert error.value.code == "validation_failed"
    assert error.value.detail()["positions"] == [{"line": 4, "column": 7, "end_column": 11}]
    assert "invalid rule" in error.value.stderr
    assert executor.read_source() == original
    assert not list(executor.temporary.iterdir())


def test_timeout_and_missing_binary_fail_closed(tmp_path: Path) -> None:
    executor, _, runner, _ = setup(tmp_path)
    runner.timeout = True
    with pytest.raises(NftError) as error:
        executor.apply(SOURCE)
    assert error.value.code == "timeout"
    assert not executor.sandbox.exists()
    def missing(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError("nft")
    executor._runner = missing
    with pytest.raises(NftError) as error:
        executor.check(SOURCE)
    assert error.value.code == "execution_unavailable"


@pytest.mark.parametrize("source", [
    'include "/etc/shadow"', 'table inet x { include "/tmp/x"; }',
    'define x = 22\ntable inet x {}', 'list ruleset', 'monitor', 'delete table inet x',
    'table inet x {}\nflush ruleset', 'flush ruleset\nflush ruleset',
    'in\\\nclude "/tmp/x"', '{"nftables":[]}', 'table inet x {', '\x00',
])
def test_execution_policy_rejects_non_self_contained_sources(tmp_path: Path, source: str) -> None:
    executor, _, runner, _ = setup(tmp_path)
    with pytest.raises(NftError):
        executor.check(source)
    assert not runner.calls


def test_policy_distinguishes_comments_and_quoted_strings() -> None:
    source = '# include "/tmp/x"\ntable inet "include" { comment "include {; }"; }\n'
    assert prepare_source(source) == "flush ruleset\n" + source
    assert prepare_source(prepare_source(source)) == prepare_source(source)


def test_no_arbitrary_command_or_path_api(tmp_path: Path) -> None:
    executor, _, runner, _ = setup(tmp_path, live=True)
    with pytest.raises(NftError):
        executor._run("flush")
    with pytest.raises(NftError):
        executor._run("apply", tmp_path / "outside.nft")
    assert not runner.calls


def test_secure_storage_rejects_symlinks_and_public_files(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("original")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(NftError):
        atomic_write(link, "changed")
    with pytest.raises(OSError):
        read_private(link)
    with pytest.raises(NftError):
        read_private(target)
    assert target.read_text() == "original"


def test_audit_is_json_and_contains_hashes(tmp_path: Path) -> None:
    executor, manager, _, _ = setup(tmp_path)
    transaction = manager.apply(SOURCE)
    manager.confirm(transaction.id)
    entries = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert {e["action"] for e in entries} >= {"read", "dry-run", "apply", "confirm"}
    assert all(e["timestamp"] and len(e["ruleset_hash"]) == 64 for e in entries)
