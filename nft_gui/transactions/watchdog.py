from __future__ import annotations

import argparse
import json
import logging
import secrets
import time
from pathlib import Path

from nft_gui.config import Settings
from nft_gui.executor import NftExecutor
from nft_gui.storage import atomic_write, file_lock, read_private
from nft_gui.transactions.manager import ACTIVE, TransactionManager


def run(directory: Path, transaction_id: str) -> None:
    TransactionManager._valid_id(transaction_id)
    # One guardian per transaction, including after API restarts.
    lock = directory / "transactions" / f"{transaction_id}.watchdog.lock"
    ready = directory / "transactions" / f"{transaction_id}.ready"
    try:
        with file_lock(lock, blocking=False):
            config = json.loads(read_private(directory / "guardian.json"))
            # The guardian has no HTTP server; never retain a reusable static token.
            settings = Settings(data_dir=directory, api_token=secrets.token_urlsafe(32), **config)
            manager = TransactionManager(NftExecutor(settings))
            # Announce before acquiring transaction.lock held by the API during apply.
            atomic_write(ready, transaction_id)
            try:
                while True:
                    try:
                        transaction = manager.expire(expected_id=transaction_id)
                        if transaction is None or transaction.id != transaction_id or transaction.status not in ACTIVE:
                            return
                    except Exception:
                        logging.exception("Rollback guardian will retry; no new apply is permitted")
                    time.sleep(1)
            finally:
                ready.unlink(missing_ok=True)
    except BlockingIOError:
        # Existing guardian owns the lock; its readiness marker is authoritative.
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="nft-gui rollback guardian")
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--transaction", required=True)
    args = parser.parse_args()
    run(args.directory, args.transaction)


if __name__ == "__main__":
    main()
