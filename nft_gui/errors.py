from __future__ import annotations

import re


class NftError(Exception):
    """An error suitable for a structured API response."""

    def __init__(self, message: str, *, stderr: str = "", code: str = "nft_error") -> None:
        super().__init__(message)
        self.code = code
        self.stderr = stderr

    def detail(self) -> dict[str, object]:
        positions = [
            {"line": int(m[1]), "column": int(m[2]), "end_column": int(m[3] or m[2])}
            for m in re.finditer(r":(\d+):(\d+)(?:-(\d+))?:", self.stderr)
        ]
        return {"code": self.code, "message": str(self), "stderr": self.stderr,
                "positions": positions}


class UnsupportedError(NftError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="unsupported_syntax")


class ConflictError(NftError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="conflict")
