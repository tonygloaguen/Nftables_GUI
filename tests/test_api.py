from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("pydantic", minversion="2.10")

from fastapi.testclient import TestClient

from nft_gui.api import create_app
from nft_gui.config import Settings
from nft_gui.executor import NftExecutor
from nft_gui.transactions import TransactionManager
from tests.support import SOURCE, FakeNft, setup


def test_api_transaction_validation_confirm_export_and_audit(tmp_path: Path) -> None:
    executor, manager, runner, _ = setup(tmp_path)
    with TestClient(create_app(executor.settings, executor=executor, manager=manager),
                    base_url="http://127.0.0.1:8420") as client:
        assert client.get("/health").json()["backend"] == "file"
        assert client.get("/ruleset").status_code == 200
        assert client.post("/validate", json={"source": SOURCE}).json()["valid"] is True
        response = client.post("/transactions", json={"source": SOURCE, "confirm_seconds": 60})
        assert response.status_code == 201
        identifier = response.json()["id"]
        assert client.post("/transactions", json={"source": SOURCE}).status_code == 409
        assert client.post(f"/transactions/{identifier}/confirm", json={}).status_code == 200
        assert client.get(f"/transactions/{identifier}").json()["status"] == "confirmed"
        exported = client.post("/export", json={"source": SOURCE})
        assert exported.status_code == 200 and 'filename="ruleset.nft"' in exported.headers["content-disposition"]
        runner.fail_check = True
        invalid = client.post("/validate", json={"source": SOURCE})
        assert invalid.status_code == 422
        assert invalid.json()["detail"]["positions"][0]["line"] == 4
    assert '"action":"export"' in executor.audit.path.read_text()


def test_rejects_dns_rebinding_cross_origin_forms_and_invalid_bodies(tmp_path: Path) -> None:
    executor, manager, _, _ = setup(tmp_path)
    with TestClient(create_app(executor.settings, executor=executor, manager=manager),
                    base_url="http://127.0.0.1:8420") as client:
        assert client.get("/health", headers={"Host": "evil.example"}).status_code == 400
        assert client.post("/validate", json={"source": SOURCE}, headers={"Origin": "https://evil.example"}).status_code == 403
        assert client.post("/validate", data={"source": SOURCE}).status_code == 415
        assert client.post("/validate", json={}).status_code == 422
        assert client.post("/validate", json={"source": SOURCE, "ruleset": {}}).status_code == 422
        assert client.post("/transactions", json={"source": SOURCE, "confirm_seconds": "30"}).status_code == 422


def test_authentication_also_protects_read_routes_and_docs(tmp_path: Path) -> None:
    token = "t" * 32
    settings = Settings(data_dir=tmp_path, api_token=token)
    executor = NftExecutor(settings, runner=FakeNft())
    manager = TransactionManager(executor, watchdog=lambda _: None)
    with TestClient(create_app(settings, executor=executor, manager=manager),
                    base_url="http://127.0.0.1:8420") as client:
        assert client.get("/health").status_code == 401
        assert client.get("/docs").status_code == 401
        assert client.get("/health", headers={"Authorization": "Bearer " + token}).status_code == 200
