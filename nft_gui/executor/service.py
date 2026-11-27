from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from nft_gui.config import Settings
from nft_gui.errors import NftError
from nft_gui.executor.policy import prepare_source
from nft_gui.storage import AuditLog, atomic_write, digest, file_lock, private_dir, read_private

Runner = Callable[..., subprocess.CompletedProcess[str]]


class NftExecutor:
    """The sole process boundary. There is no arbitrary command/argv API."""

    def __init__(self, settings: Settings, *, runner: Runner = subprocess.run) -> None:
        self.settings = settings
        self._runner = runner
        self.directory = private_dir(settings.data_dir)
        self.temporary = private_dir(self.directory / "tmp")
        self.sandbox = self.directory / "sandbox.nft"
        self.audit = AuditLog(self.directory)

    @property
    def live(self) -> bool:
        return self.settings.backend == "live"

    def _run(self, operation: str, path: Path | None = None) -> str:
        if operation == "read" and path is None and self.live:
            arguments = ["-j", "list", "ruleset"]
        elif operation in {"check", "apply"} and path is not None:
            if path.parent != self.temporary or path.is_symlink():
                raise NftError("Untrusted command input path", code="unsafe_path")
            if not self.live and operation != "check":
                raise NftError("Live apply is disabled", code="unsafe_command")
            arguments = (["-c"] if operation == "check" else []) + ["-f", str(path)]
        else:
            raise NftError("Command is not allowlisted", code="unsafe_command")
        if self.live:
            prefix = ([self.settings.sudo_binary, "-n", "--"] if self.settings.privilege == "sudo"
                      else [self.settings.pkexec_binary, "--disable-internal-agent"])
        else:
            # Real nft semantic check, isolated from the host ruleset, without sudo.
            prefix = [self.settings.unshare_binary, "--user", "--map-root-user", "--net", "--"]
        command = [*prefix, self.settings.nft_binary, *arguments]
        try:
            result = self._runner(command, capture_output=True, text=True, check=True,
                                  timeout=10, shell=False, close_fds=True,
                                  env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                                  cwd=self.temporary)
        except subprocess.CalledProcessError as exc:
            raise NftError("nft rejected the operation", stderr=exc.stderr or "",
                           code="validation_failed" if operation == "check" else "execution_failed") from exc
        except subprocess.TimeoutExpired as exc:
            stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            raise NftError("System command exceeded 10 seconds", stderr=stderr, code="timeout") from exc
        except OSError as exc:
            raise NftError("Unable to start nft or its privilege/isolation helper",
                           stderr=str(exc), code="execution_unavailable") from exc
        return result.stdout

    def read_json(self) -> dict[str, Any]:
        if not self.live:
            raise NftError("The file backend stores source, not an active kernel JSON ruleset",
                           code="unsupported_operation")
        try:
            data = json.loads(self._run("read"))
            if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
                raise ValueError("Invalid nftables JSON envelope")
        except (NftError, ValueError) as exc:
            self.audit.record("read", "error", None, detail=str(exc))
            if isinstance(exc, NftError):
                raise
            raise NftError("Invalid JSON from nft", code="invalid_json") from exc
        self.audit.record("read", "ok", digest(json.dumps(data, sort_keys=True)))
        return data

    def read_source(self) -> str:
        if self.live:
            from nft_gui.generator import generate_nft
            from nft_gui.parser import from_nft_json
            return generate_nft(from_nft_json(self.read_json()))
        try:
            source = read_private(self.sandbox)
        except FileNotFoundError:
            source = "flush ruleset\n"
        except (OSError, NftError) as exc:
            self.audit.record("read", "error", None, detail=str(exc))
            raise
        self.audit.record("read", "ok", digest(source))
        return source

    def _with_source(self, source: str, *, apply: bool, recovery: bool = False) -> str:
        try:
            prepared = prepare_source(source)
        except NftError as exc:
            self._audit_check("error", digest(source), str(exc), recovery)
            raise
        ruleset_hash = digest(prepared)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="ruleset-",
                                         suffix=".nft", dir=self.temporary) as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(prepared)
            stream.flush()
            os.fsync(stream.fileno())
            path = Path(stream.name)
            try:
                self._run("check", path)
            except NftError as exc:
                self._audit_check("error", ruleset_hash, exc.stderr or str(exc), recovery)
                raise
            self._audit_check("ok", ruleset_hash, None, recovery)
            if apply:
                if self.live:
                    self._run("apply", path)
                else:
                    atomic_write(self.sandbox, prepared)
        return prepared

    def check(self, source: str) -> str:
        return self._with_source(source, apply=False)

    def apply(self, source: str, *, recovery: bool = False) -> str:
        # Called only by TransactionManager: recheck the SAME private file before apply.
        return self._with_source(source, apply=True, recovery=recovery)

    def _audit_check(self, status: str, ruleset_hash: str, detail: str | None, recovery: bool) -> None:
        try:
            self.audit.record("dry-run", status, ruleset_hash, detail=detail)
        except (OSError, NftError):
            if not recovery:
                raise
            import logging
            logging.getLogger(__name__).exception("Audit unavailable during rollback validation")

    def start_watchdog(self, transaction_id: str) -> None:
        """Detached guardian must acknowledge readiness before the apply starts."""
        if not __import__("re").fullmatch(r"[a-f0-9]{32}", transaction_id):
            raise NftError("Invalid transaction id", code="invalid_transaction")
        ready = self.directory / "transactions" / f"{transaction_id}.ready"
        guardian_lock = ready.with_suffix(".watchdog.lock")
        try:
            with file_lock(guardian_lock, blocking=False):
                # A marker from a dead process must never arm a new apply.
                ready.unlink(missing_ok=True)
        except BlockingIOError:
            if ready.exists() and read_private(ready) == transaction_id:
                return
        command = [sys.executable, "-m", "nft_gui.transactions.watchdog",
                   "--directory", str(self.directory), "--transaction", transaction_id]
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       close_fds=True, start_new_session=True,
                                       cwd=Path(__file__).resolve().parents[2])
        except OSError as exc:
            raise NftError("Cannot start rollback guardian", code="watchdog_unavailable") from exc
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            guardian_running = False
            try:
                with file_lock(guardian_lock, blocking=False):
                    pass
            except BlockingIOError:
                guardian_running = True
            if guardian_running and ready.exists() and read_private(ready) == transaction_id:
                # Reap normally exited guardians without retaining zombies in the API.
                import threading
                threading.Thread(target=process.wait, daemon=True).start()
                return
            if process.poll() is not None:
                break
            time.sleep(0.025)
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
        raise NftError("Rollback guardian did not acknowledge readiness", code="watchdog_unavailable")
