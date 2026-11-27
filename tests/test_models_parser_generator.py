from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic", minversion="2.10")

from pydantic import ValidationError

from nft_gui.errors import NftError, UnsupportedError
from nft_gui.executor.policy import prepare_source
from nft_gui.generator import generate_nft
from nft_gui.models import Chain, Expr, Rule, Ruleset, Table
from nft_gui.parser import from_nft_json, from_nft_text, to_nft_json
from tests.support import SOURCE, setup

FIXTURE = Path(__file__).parent / "fixtures/ruleset.json"


def test_nft_json_roundtrip_is_lossless_even_through_ir_json() -> None:
    original = json.loads(FIXTURE.read_text())
    ir = from_nft_json(original)
    reconstructed = Ruleset.model_validate_json(ir.model_dump_json())
    assert to_nft_json(reconstructed) == original


def test_generates_forward_sets_maps_counters_quotas_and_order() -> None:
    source = generate_nft(from_nft_json(FIXTURE.read_text()))
    assert 'type filter hook forward priority 0;' in source
    assert 'policy drop;' in source
    assert 'set "trusted"' in source and '192.0.2.0/24' in source
    assert 'type inet_service : verdict;' in source
    assert '22 : jump "allowed"' in source
    assert 'packets 12 bytes 2048;' in source
    assert '1000000 bytes used 300 bytes;' in source
    assert 'comment "Return traffic"' in source
    assert source.index('ct state') < source.index('ip saddr') < source.index('tcp dport')
    assert source.index('chain "allowed"') < source.index('map "ports"')
    assert prepare_source(source) == source


def test_unknown_expression_is_preserved_and_generation_fails_closed() -> None:
    document = json.loads(FIXTURE.read_text())
    unknown = {"future-op": {"deep": [1, True, None, {"new": "value"}]}}
    document["nftables"][-1]["rule"]["expr"].insert(0, unknown)
    ir = from_nft_json(document)
    assert to_nft_json(Ruleset.model_validate_json(ir.model_dump_json())) == document
    rule = ir.objects[-1]
    assert isinstance(rule, Rule) and rule.expr[0].unsupported_expr == unknown
    with pytest.raises(UnsupportedError):
        generate_nft(ir)


def test_nested_unknown_field_is_not_silently_ignored() -> None:
    document = json.loads(FIXTURE.read_text())
    document["nftables"][-1]["rule"]["expr"] = [{"counter": {"packets": 0, "bytes": 0, "future": 1}}]
    ir = from_nft_json(document)
    assert to_nft_json(ir) == document
    with pytest.raises(UnsupportedError):
        generate_nft(ir)


@pytest.mark.parametrize("entry", [
    {"future-object": {"family": "inet", "nested": [1, 2]}},
    {"chain": {"family": "inet", "table": "filter", "name": "future", "type": "future", "hook": "forward", "prio": 0}},
    {"set": {"family": "inet", "table": "filter", "name": "future", "type": "ipv4_addr", "new-flag": True}},
])
def test_unknown_objects_or_fields_survive(entry: dict[str, object]) -> None:
    document = json.loads(FIXTURE.read_text())
    document["nftables"].append(entry)
    ir = from_nft_json(document)
    assert to_nft_json(ir) == document
    with pytest.raises(UnsupportedError):
        generate_nft(ir)


@pytest.mark.parametrize("source", [
    '# Preserve my comment\ntable inet x { chain y { counter accept; } }\n',
    'define ports = { 22, 443 }\ntable inet x {}\n',
    'table inet x { set s { type ipv4_addr; flags interval; auto-merge; elements = { 192.0.2.0/24 }; } }\n',
    'table inet x {}\nflush ruleset\n',
    'table inet x { chain y { type future hook forward priority 0; } }\n',
])
def test_opaque_code_returns_byte_identical_source(source: str) -> None:
    ir = from_nft_text(source)
    assert ir.raw_nft == source
    assert generate_nft(Ruleset.model_validate_json(ir.model_dump_json())) == source
    with pytest.raises(UnsupportedError):
        to_nft_json(ir)


def test_simple_code_can_be_edited_visually() -> None:
    source = 'table inet "filter" {\nchain "forward" {\ntype filter hook forward priority 0; policy drop;\nct state established,related counter accept\n}\n}\n'
    ir = from_nft_text(source)
    assert ir.raw_nft is None
    assert isinstance(ir.objects[1], Chain)
    ir.objects[1].policy = "accept"
    regenerated = generate_nft(ir)
    assert 'policy accept;' in regenerated
    assert 'ct state { "established", "related" } counter accept' in regenerated


def test_generated_source_roundtrips_back_to_editable_objects() -> None:
    source = generate_nft(from_nft_json(FIXTURE.read_text()))
    restored = from_nft_text(source)
    assert restored.raw_nft is None
    assert {o.kind for o in restored.objects} >= {"table", "chain", "set", "map", "counter", "quota", "rule"}
    assert all(e.statement is not None for r in restored.objects if isinstance(r, Rule) for e in r.expr)
    assert generate_nft(restored) == source


def test_advanced_rule_survives_common_source_conversion() -> None:
    text = 'table inet x { chain f {\nfib saddr . iif oif missing drop\n} }\n'
    ir = from_nft_text(text)
    assert ir.raw_nft is None
    assert 'fib saddr . iif oif missing drop' in generate_nft(ir)


def test_generated_header_is_kept_if_document_falls_back_to_code() -> None:
    text = '# Generated by nft-gui: complete ruleset replacement\n# User comment\ntable inet x {}\n'
    assert generate_nft(from_nft_text(text)) == text


def test_nat_and_interface_chain_roundtrip() -> None:
    text = 'table inet n { chain prerouting { type nat hook prerouting priority -100; policy accept; } }\nadd rule inet n prerouting meta l4proto "tcp" tcp dport 443 counter dnat ip to 192.0.2.10:8443\n'
    ir = from_nft_text(text)
    assert ir.raw_nft is None
    assert 'dnat ip to 192.0.2.10:8443' in generate_nft(ir)
    netdev = 'table netdev n { chain in { type filter hook ingress device "eth0" priority 0; policy drop; } }'
    parsed = from_nft_text(netdev)
    assert parsed.raw_nft is None
    assert isinstance(parsed.objects[1], Chain) and parsed.objects[1].dev == 'eth0'


def test_raw_expression_never_exports_stale_json() -> None:
    ir = from_nft_json(FIXTURE.read_text())
    rule = ir.objects[-1]
    assert isinstance(rule, Rule)
    rule.expr[0].raw_nft = "drop"
    assert '"allowed" drop' in generate_nft(ir)
    with pytest.raises(UnsupportedError):
        to_nft_json(ir)


def test_visual_edit_reaches_json_export() -> None:
    ir = from_nft_json(FIXTURE.read_text())
    chain = ir.objects[2]
    assert isinstance(chain, Chain)
    chain.policy = "accept"
    assert to_nft_json(ir)["nftables"][2]["chain"]["policy"] == "accept"


def test_models_reject_coercion_and_ambiguous_representation() -> None:
    with pytest.raises(ValidationError):
        Chain(family="inet", table="x", name="f", type="filter")
    with pytest.raises(ValidationError):
        Table(family="inet", name="x", handle="3")
    with pytest.raises(ValidationError):
        Ruleset(raw_nft="flush ruleset", objects=[Table(family="inet", name="x")])
    with pytest.raises(ValidationError):
        Expr(statement={"accept": None}, unsupported_expr={"drop": None})


def test_invalid_json_and_missing_references_fail() -> None:
    with pytest.raises(NftError):
        from_nft_json('{"nftables": {}}')
    with pytest.raises(UnsupportedError):
        generate_nft(Ruleset(objects=[Chain(family="inet", table="missing", name="f")]))


def test_live_snapshot_and_uncertain_apply_restore(tmp_path: Path) -> None:
    executor, manager, runner, _ = setup(tmp_path, live=True)
    runner.json = json.loads(FIXTURE.read_text())
    runner.fail_apply = True
    with pytest.raises(NftError) as error:
        manager.apply(SOURCE)
    assert error.value.code == "timeout"
    saved = json.loads(manager.state_file.read_text())
    assert saved["status"] == "rolled_back"
    snapshot = manager.snapshots / f"{saved['snapshot_id']}.json"
    assert json.loads(snapshot.read_text()) == runner.json
    applies = [c for c in runner.calls if "-f" in c[0] and "-c" not in c[0]]
    assert len(applies) == 2
    assert 'counter "forwarded"' in applies[-1][1]


def test_unsupported_active_ruleset_prevents_live_apply(tmp_path: Path) -> None:
    _, manager, runner, _ = setup(tmp_path, live=True)
    runner.json = {"nftables": [{"future-object": {"unknown": True}}]}
    with pytest.raises(UnsupportedError):
        manager.apply(SOURCE)
    assert not manager.state_file.exists()
    assert not any("-f" in c[0] and "-c" not in c[0] for c in runner.calls)
