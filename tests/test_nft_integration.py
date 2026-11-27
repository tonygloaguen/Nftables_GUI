from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def test_generated_ruleset_against_real_nft_in_private_namespace(tmp_path: Path) -> None:
    if os.getenv("NFT_GUI_INTEGRATION") != "1":
        pytest.skip("Set NFT_GUI_INTEGRATION=1 to opt in to isolated nft checks")
    pytest.importorskip("pydantic", minversion="2.10")
    from nft_gui.generator import generate_nft
    from nft_gui.parser import from_nft_json
    from nft_gui.templates import preview_template
    from nft_gui.templates.catalog import TEMPLATES
    unshare, nft = shutil.which("unshare"), shutil.which("nft")
    if unshare is None or nft is None:
        pytest.skip("nft and unshare are required")
    fixture = json.loads((Path(__file__).parent / "fixtures/ruleset.json").read_text())
    path = tmp_path / "ruleset.nft"
    path.write_text(generate_nft(from_nft_json(fixture)))
    path.chmod(0o600)
    command = [unshare, "--user", "--map-root-user", "--net", "--", nft, "-c", "-f", str(path)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
    for template in TEMPLATES:
        preview = preview_template(template.id)
        path.write_text(str(preview['source']))
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        assert result.returncode == 0, template.id + ': ' + result.stderr
    path.write_text("flush ruleset\ntable inet broken { definitely_invalid; }\n")
    rejected = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    assert rejected.returncode != 0 and "Error" in rejected.stderr
