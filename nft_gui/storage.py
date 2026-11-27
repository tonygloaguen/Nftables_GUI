from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from nft_gui.errors import NftError


def digest(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise NftError("Unsafe data directory", code="unsafe_path")
    path.chmod(0o700)
    return path


def read_private(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise NftError("Unsafe file owner or permissions", code="unsafe_path")
        return stream.read()


def atomic_write(path: Path, content: str) -> None:
    private_dir(path.parent)
    if path.is_symlink():
        raise NftError("Refusing to replace a symbolic link", code="unsafe_path")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=".write-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
            os.replace(temporary, path)
            fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)


@contextmanager
def file_lock(path: Path, *, blocking: bool = True) -> Iterator[None]:
    private_dir(path.parent)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise NftError("Unsafe lock file", code="unsafe_path")
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield
    finally:
        os.close(fd)


class AuditLog:
    def __init__(self, directory: Path) -> None:
        self.directory = private_dir(directory)
        self.path = directory / "audit.jsonl"

    def tail(self, limit: int = 100) -> list[dict[str, object]]:
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return []
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise NftError("Unsafe audit file", code="unsafe_path")
            start = max(0, info.st_size - 262144)
            stream.seek(start)
            if start:
                stream.readline()
            lines = stream.read(262144).splitlines()[-max(1, min(limit, 200)):]
        entries: list[dict[str, object]] = []
        for line in reversed(lines):
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    entries.append(item)
            except ValueError:
                continue
        return entries

    def record(self, action: str, status: str, ruleset_hash: str | None,
               *, transaction_id: str | None = None, detail: str | None = None) -> None:
        from datetime import datetime, timezone
        entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "action": action,
                 "status": status, "ruleset_hash": ruleset_hash,
                 "transaction_id": transaction_id, "detail": detail}
        payload = (json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        with file_lock(self.directory / "audit.lock"):
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "ab") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    raise NftError("Unsafe audit file", code="unsafe_path")
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
