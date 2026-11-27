from __future__ import annotations

import json
import logging
import math
import re
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from nft_gui.errors import ConflictError, NftError
from nft_gui.executor import NftExecutor
from nft_gui.storage import atomic_write, digest, file_lock, private_dir, read_private

Status = Literal["prepared", "applying", "pending", "confirmed", "rolled_back", "rollback_failed", "aborted"]
ACTIVE = {"prepared", "applying", "pending", "rollback_failed"}
LOG = logging.getLogger(__name__)


def boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


@dataclass
class Transaction:
    id: str
    status: Status
    backend: str
    snapshot_id: str
    snapshot_hash: str
    ruleset_hash: str
    expires_at: float
    expires_monotonic: float
    boot: str
    error: str | None = None

    @classmethod
    def parse(cls, text: str) -> Transaction:
        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError("Expected an object")
            result = cls(**data)
            if not re.fullmatch(r"[a-f0-9]{32}", result.id):
                raise ValueError("Invalid id")
            if not re.fullmatch(r"\d{8}T\d{12}Z-[a-f0-9]{32}", result.snapshot_id):
                raise ValueError("Invalid snapshot id")
            if result.status not in ACTIVE | {"confirmed", "rolled_back", "aborted"}:
                raise ValueError("Invalid status")
            if result.backend not in {"file", "mock", "live"}:
                raise ValueError("Invalid backend")
            if not all(re.fullmatch(r"[a-f0-9]{64}", h) for h in (result.snapshot_hash, result.ruleset_hash)):
                raise ValueError("Invalid hash")
            for deadline in (result.expires_at, result.expires_monotonic):
                if type(deadline) not in (float, int) or not math.isfinite(deadline) or deadline < 0:
                    raise ValueError("Invalid deadline")
            if not isinstance(result.boot, str) or (result.error is not None and not isinstance(result.error, str)):
                raise ValueError("Invalid transaction fields")
            return result
        except (ValueError, TypeError, KeyError) as exc:
            raise NftError("Transaction state is corrupt; all new applies are blocked",
                           code="corrupt_state") from exc


class TransactionManager:
    def __init__(self, executor: NftExecutor, *,
                 watchdog: Callable[[str], None] | None = None,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self.executor = executor
        self.directory = executor.directory
        self.snapshots = private_dir(self.directory / "snapshots")
        self.transactions = private_dir(self.directory / "transactions")
        self.state_file = self.directory / "pending.json"
        self.lock_file = self.directory / "transaction.lock"
        self.watchdog = watchdog or executor.start_watchdog
        self.clock = clock
        self.monotonic = monotonic

    def _state(self) -> Transaction | None:
        try:
            transaction = Transaction.parse(read_private(self.state_file))
        except FileNotFoundError:
            return None
        if transaction.backend != self.executor.settings.backend:
            raise NftError("Data directory belongs to a different execution backend",
                           code="backend_mismatch")
        return transaction

    def _save(self, transaction: Transaction) -> None:
        content = json.dumps(asdict(transaction), sort_keys=True, indent=2) + "\n"
        # pending.json is authoritative. History is written after it.
        atomic_write(self.state_file, content)
        atomic_write(self.transactions / f"{transaction.id}.json", content)

    def _expired(self, transaction: Transaction) -> bool:
        return (transaction.boot != boot_id() or self.monotonic() >= transaction.expires_monotonic
                or self.clock() >= transaction.expires_at)

    def _snapshot(self, transaction_id: str) -> tuple[str, str]:
        if self.executor.live:
            from nft_gui.generator import generate_nft
            from nft_gui.parser import from_nft_json
            document = self.executor.read_json()
            source = generate_nft(from_nft_json(document))
        else:
            source = self.executor.read_source()
            document = {"format": "nft-source", "raw_nft": source}
        # Refuse the new configuration unless the previous one can be restored.
        checked = self.executor.check(source)
        identifier = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ-") + transaction_id
        atomic_write(self.snapshots / f"{identifier}.json", json.dumps(document, indent=2) + "\n")
        atomic_write(self.snapshots / f"{identifier}.nft", checked)
        return identifier, digest(checked)

    def _guardian_config(self) -> None:
        s = self.executor.settings
        config = {"backend": s.backend, "nft_binary": s.nft_binary, "sudo_binary": s.sudo_binary,
                  "privilege": s.privilege, "pkexec_binary": s.pkexec_binary,
                  "unshare_binary": s.unshare_binary}
        atomic_write(self.directory / "guardian.json", json.dumps(config))

    def apply(self, source: str, *, confirm_seconds: int | None = None) -> Transaction:
        try:
            return self._apply(source, confirm_seconds=confirm_seconds)
        except Exception as exc:
            self._audit_failure("apply", exc, ruleset_hash=digest(source))
            raise

    def _audit_failure(self, action: str, error: Exception, *, ruleset_hash: str | None = None,
                       transaction_id: str | None = None) -> None:
        try:
            self.executor.audit.record(action, "error", ruleset_hash,
                                       transaction_id=transaction_id, detail=str(error))
        except (OSError, NftError):
            LOG.exception("Cannot record failed %s", action)

    def _apply(self, source: str, *, confirm_seconds: int | None = None) -> Transaction:
        delay = self.executor.settings.default_confirm_seconds if confirm_seconds is None else confirm_seconds
        if type(delay) is not int or not 15 <= delay <= 300:
            raise NftError("Confirmation must be between 15 and 300 seconds", code="invalid_deadline")
        with file_lock(self.lock_file):
            old = self._state()
            if old is not None and old.status in ACTIVE:
                raise ConflictError("A transaction already requires confirmation or rollback")
            prepared = self.executor.check(source)
            transaction_id = uuid.uuid4().hex
            snapshot_id, snapshot_hash = self._snapshot(transaction_id)
            transaction = Transaction(transaction_id, "prepared", self.executor.settings.backend,
                                      snapshot_id, snapshot_hash, digest(prepared),
                                      self.clock() + delay, self.monotonic() + delay, boot_id())
            self._guardian_config()
            self._save(transaction)
            self.executor.audit.record("apply", "started", transaction.ruleset_hash,
                                       transaction_id=transaction.id)
            try:
                self.watchdog(transaction.id)
            except Exception:
                transaction.status = "aborted"
                self._save(transaction)
                self.executor.audit.record("apply", "aborted", transaction.ruleset_hash,
                                           transaction_id=transaction.id, detail="Guardian unavailable")
                raise
            transaction.status = "applying"
            self._save(transaction)
            try:
                self.executor.apply(prepared)
                transaction.status = "pending"
                self._save(transaction)
                self.executor.audit.record("apply", "pending", transaction.ruleset_hash,
                                           transaction_id=transaction.id)
            except Exception as exc:
                transaction.error = str(exc)
                self._restore(transaction, reason="apply_failed_or_uncertain")
                raise
            return transaction

    def _audit_recovery(self, transaction: Transaction, status: str, detail: str) -> None:
        try:
            self.executor.audit.record("rollback", status, transaction.snapshot_hash,
                                       transaction_id=transaction.id, detail=detail)
        except (OSError, NftError):
            # Recovery must still run when a disk/audit failure caused the incident.
            LOG.exception("Cannot write rollback audit record")

    def _restore(self, transaction: Transaction, *, reason: str) -> Transaction:
        self._audit_recovery(transaction, "started", reason)
        try:
            source = read_private(self.snapshots / f"{transaction.snapshot_id}.nft")
            if digest(source) != transaction.snapshot_hash:
                raise NftError("Snapshot hash mismatch", code="corrupt_snapshot")
            self.executor.apply(source, recovery=True)
        except Exception as exc:
            transaction.status = "rollback_failed"
            transaction.error = str(exc)
            self._save(transaction)
            self._audit_recovery(transaction, "error", str(exc))
            raise
        transaction.status = "rolled_back"
        transaction.error = None
        self._save(transaction)
        self._audit_recovery(transaction, "ok", reason)
        return transaction

    def get(self, transaction_id: str) -> Transaction:
        self._valid_id(transaction_id)
        with file_lock(self.lock_file):
            state = self._state()
            if state is not None and state.id == transaction_id:
                return state
            try:
                return Transaction.parse(read_private(self.transactions / f"{transaction_id}.json"))
            except FileNotFoundError as exc:
                raise NftError("Unknown transaction", code="not_found") from exc

    def current(self) -> Transaction | None:
        with file_lock(self.lock_file):
            return self._state()

    def snapshot_source(self, snapshot_id: str) -> str:
        if not re.fullmatch(r"\d{8}T\d{12}Z-[a-f0-9]{32}", snapshot_id):
            raise NftError("Invalid snapshot id", code="not_found")
        try:
            source = read_private(self.snapshots / f"{snapshot_id}.nft")
        except FileNotFoundError as exc:
            raise NftError("Unknown snapshot", code="not_found") from exc
        self.executor.audit.record("read", "ok", digest(source), detail="Snapshot read")
        return source

    @staticmethod
    def _valid_id(transaction_id: str) -> None:
        if not re.fullmatch(r"[a-f0-9]{32}", transaction_id):
            raise NftError("Invalid transaction id", code="invalid_transaction")

    def confirm(self, transaction_id: str) -> Transaction:
        try:
            return self._confirm(transaction_id)
        except Exception as exc:
            self._audit_failure("confirm", exc, transaction_id=transaction_id)
            raise

    def _confirm(self, transaction_id: str) -> Transaction:
        self._valid_id(transaction_id)
        with file_lock(self.lock_file):
            transaction = self._state()
            if transaction is None or transaction.id != transaction_id:
                raise ConflictError("No matching pending transaction")
            if transaction.status == "confirmed":
                return transaction
            if transaction.status != "pending":
                raise ConflictError("Transaction is no longer awaiting confirmation")
            if self._expired(transaction):
                self._restore(transaction, reason="late_confirmation")
                raise ConflictError("Confirmation arrived after expiry; snapshot restored")
            self.executor.audit.record("confirm", "ok", transaction.ruleset_hash,
                                       transaction_id=transaction.id)
            transaction.status = "confirmed"
            self._save(transaction)
            return transaction

    def rollback(self, transaction_id: str) -> Transaction:
        try:
            return self._rollback(transaction_id)
        except Exception as exc:
            self._audit_failure("rollback", exc, transaction_id=transaction_id)
            raise

    def _rollback(self, transaction_id: str) -> Transaction:
        self._valid_id(transaction_id)
        with file_lock(self.lock_file):
            transaction = self._state()
            if transaction is None or transaction.id != transaction_id:
                raise ConflictError("No matching pending transaction")
            if transaction.status == "rolled_back":
                return transaction
            if transaction.status not in ACTIVE:
                raise ConflictError("Transaction is already closed")
            return self._restore(transaction, reason="requested")

    def expire(self, expected_id: str | None = None) -> Transaction | None:
        with file_lock(self.lock_file):
            transaction = self._state()
            if transaction is not None and expected_id is not None and transaction.id != expected_id:
                return transaction
            if transaction is not None and transaction.status in ACTIVE and (
                    self._expired(transaction) or transaction.status == "rollback_failed"):
                return self._restore(transaction, reason="deadline_or_recovery")
            return transaction

    def recover(self) -> None:
        """Re-arm an unexpired transaction or recover after an API restart/reboot."""
        self.expire()
        with file_lock(self.lock_file):
            transaction = self._state()
            if transaction is not None and transaction.status in ACTIVE:
                self.watchdog(transaction.id)
