from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from nft_gui.api import create_app
from nft_gui.config import Settings
from nft_gui.executor import NftExecutor
from nft_gui.transactions import TransactionManager
from tests.support import FakeNft, setup


def test_ui_assets_and_authenticated_session(tmp_path: Path) -> None:
    token = "s" * 32
    settings = Settings(data_dir=tmp_path, api_token=token)
    executor = NftExecutor(settings, runner=FakeNft())
    manager = TransactionManager(executor, watchdog=lambda _: None)
    with TestClient(create_app(settings, executor=executor, manager=manager), base_url="http://127.0.0.1:8420") as client:
        home = client.get("/")
        assert home.status_code == 200 and "text/html" in home.headers["content-type"]
        assert '/assets/app.js' in home.text
        assert client.get("/assets/app.js").status_code == 200
        assert client.get("/assets/model.js").status_code == 200
        assert client.get("/assets/styles.css").status_code == 200
        assert client.get("/session").json() == {"authentication_required": True}
        for route in ("/health", "/ruleset", "/audit", "/snapshots", "/transactions/pending", "/templates"):
            assert client.get(route).status_code == 401
        assert client.get("/health", headers={"Authorization": "Bearer " + token}).status_code == 200
        assert client.get("/assets/../../config.py").status_code != 200


def test_template_preview_is_pure_and_still_requires_validation(tmp_path: Path) -> None:
    executor, manager, runner, _ = setup(tmp_path)
    with TestClient(create_app(executor.settings, executor=executor, manager=manager), base_url="http://127.0.0.1:8420") as client:
        before = executor.read_source()
        calls = len(runner.calls)
        catalog = client.get('/templates').json()
        assert len(catalog['templates']) >= 31
        preview = client.post('/templates/router-nat/preview', json={'values': {'wan_if': 'enp1s0'}})
        assert preview.status_code == 200
        data = preview.json()
        assert data['nft_validated'] is False
        assert 'enp1s0' in data['source']
        assert len(runner.calls) == calls
        assert executor.read_source() == before
        assert manager.current() is None
        assert client.get('/snapshots').json()['snapshots'] == []
        assert client.post('/generate', json=data['ruleset']).json()['source'] == data['source']
        assert client.post('/templates/no-such-template/preview', json={}).status_code == 404
        assert client.post('/templates/ssh/preview', json={'values': {'ssh_port': '0'}}).status_code == 422
        assert client.post('/templates/ssh/preview', json={'values': {'ssh_port': 22}}).status_code == 422


def test_gui_edit_validate_apply_reopen_restore_workflow(tmp_path: Path) -> None:
    executor, manager, _, _ = setup(tmp_path)
    fixture = json.loads((Path(__file__).parent / 'fixtures/ruleset.json').read_text())
    with TestClient(create_app(executor.settings, executor=executor, manager=manager), base_url="http://127.0.0.1:8420") as client:
        ir = client.post('/parse/json', json=fixture).json()
        assert client.post('/parse/ir', json=ir).status_code == 200
        candidate = {'ruleset': ir}
        assert client.post('/validate', json=candidate).status_code == 200
        tx = client.post('/transactions', json=candidate).json()
        assert tx['status'] == 'pending'
        assert client.get('/transactions/pending').json()['transaction']['id'] == tx['id']
        restored_view = client.get('/ruleset').json()
        assert restored_view['ruleset'] == ir
        code = restored_view['source']
        converted = client.post('/parse/text', json={'source': code}).json()
        assert converted['raw_nft'] is None
        assert client.post('/generate', json=converted).json()['source'] == code
        assert client.post('/export', json={**candidate, 'format': 'ir'}).status_code == 200
        assert client.post('/export', json={**candidate, 'format': 'json'}).json() == fixture
        assert client.post(f"/transactions/{tx['id']}/confirm", json={}).status_code == 200
        snapshots = client.get('/snapshots').json()['snapshots']
        assert len(snapshots) == 1
        previous = client.get('/snapshots/' + snapshots[0]['id']).json()
        assert previous['source'] == 'flush ruleset\n'
        restore = client.post('/snapshots/' + snapshots[0]['id'] + '/restore', json={'confirm_seconds': 30}).json()
        assert restore['status'] == 'pending'
        assert executor.read_source() == 'flush ruleset\n'
        assert client.post(f"/transactions/{restore['id']}/rollback", json={}).status_code == 200
        assert executor.read_source() == code
        assert client.get('/ruleset').json()['ruleset'] == ir
        assert client.get('/audit?limit=10').status_code == 200
        assert len(client.get('/audit?limit=10').json()['entries']) == 10
        assert client.get('/audit?limit=9999').status_code == 422


def test_invalid_visual_cache_never_replaces_actual_source(tmp_path: Path) -> None:
    from nft_gui.storage import atomic_write, digest
    executor, manager, _, _ = setup(tmp_path)
    original = executor.apply('table inet actual {}\n')
    atomic_write(tmp_path / 'views' / f'{digest(original)}.json', '{"objects":[]}')
    with TestClient(create_app(executor.settings, executor=executor, manager=manager), base_url="http://127.0.0.1:8420") as client:
        result = client.get('/ruleset').json()
        assert result['source'] == original
        assert result['ruleset']['objects'][0]['name'] == 'actual'
