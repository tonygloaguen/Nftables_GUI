from __future__ import annotations

import pytest
from pathlib import Path

from nft_gui.errors import NftError
from nft_gui.executor.policy import prepare_source
from nft_gui.generator import generate_nft
from nft_gui.models import Chain, Rule, Ruleset
from nft_gui.parser import from_nft_text
from nft_gui.templates import catalog, preview_template
from nft_gui.templates.catalog import REFERENCES, TEMPLATES


@pytest.mark.parametrize("template_id", [t.id for t in TEMPLATES])
def test_every_template_is_a_lossless_explained_visual_draft(template_id: str) -> None:
    preview = preview_template(template_id)
    ir = Ruleset.model_validate(preview["ruleset"])
    source = generate_nft(ir)
    assert preview["nft_validated"] is False
    assert ir.raw_nft is None
    assert preview["source"] == source
    assert prepare_source(source)
    assert generate_nft(from_nft_text(source)) == source
    assert len([o for o in ir.objects if isinstance(o, Rule)]) == len(preview["rules"])
    for rule in preview["rules"]:
        assert rule["title"] and rule["explanation"] and rule["parts"]
        assert all(part["code"] and part["explanation"] for part in rule["parts"])
    assert next(o for o in ir.objects if isinstance(o, Chain) and o.name == "input").policy == "drop"


def test_catalog_has_unique_ids_and_resolvable_provenance() -> None:
    assert len(TEMPLATES) >= 31
    assert len({t.id for t in TEMPLATES}) == len(TEMPLATES)
    for template in TEMPLATES:
        assert set(template.sources) <= {r.id for r in REFERENCES}
        assert len({p.key for p in template.parameters}) == len(template.parameters)
        assert template.prerequisites and template.caveats
    assert len(catalog()["templates"]) == len(TEMPLATES)


@pytest.mark.parametrize(("template_id", "values"), [
    ("router-nat", {"lan_if": "eth0", "wan_if": "eth0"}),
    ("router-nat", {"wan_if": 'eth0"; flush ruleset'}),
    ("router-nat", {"lan_network": "192.168.10.42/24"}),
    ("router-nat", {"lan_network": "2001:db8::/32"}),
    ("ssh", {"ssh_port": "0"}), ("ssh", {"ssh_port": "65536"}),
    ("ssh", {"admin_network": "any"}), ("ssh", {"unexpected": "foo"}),
    ("wireguard", {"service_ports": "20-10"}), ("wireguard", {"service_ports": "443,"}),
    ("web", {"ssh": "perhaps"}), ("web", {"admin_network": ""}),
    ("port-forward", {"server_ip": "192.168.2.10"}),
    ("inter-vlan", {"clients": "192.168.120.0/24"}),
    ("blocklist", {"blocked": "192.0.2.0/24,192.0.2.1"}),
])
def test_bad_parameters_are_rejected_before_generation(template_id: str, values: dict[str, str]) -> None:
    with pytest.raises(NftError) as exc:
        preview_template(template_id, values)
    assert exc.value.code == "invalid_template"


def test_no_ssh_by_default_and_optional_ssh_is_scoped() -> None:
    assert "Administration SSH" not in preview_template("web")["source"]
    result = preview_template("web", {"ssh": "oui", "ssh_port": "2222", "admin_network": "10.2.0.7/32"})
    ssh = next(r for r in result["rules"] if r["title"] == "Administration SSH restreinte")
    assert "ip saddr 10.2.0.7/32" in ssh["code"] and "tcp dport 2222" in ssh["code"]


def test_dnat_filters_post_translation_tuple_and_original_public_target() -> None:
    result = preview_template("port-forward", {"public_port": "9443", "server_port": "443"})
    nat = next(r for r in result["rules"] if r["chain"] == "prerouting")
    forward = next(r for r in result["rules"] if r["title"] == "Autoriser le flux redirigé")
    assert "ip daddr 203.0.113.10" in nat["code"] and "tcp dport 9443" in nat["code"]
    assert 'dnat to 192.168.10.10:443' in nat["code"]
    for text in ['ip daddr 192.168.10.10', 'tcp dport 443', 'ct status "dnat"', 'meta iifname "eth0"', 'meta oifname "eth1"']:
        assert text in forward["code"]


def test_limited_logging_never_turns_into_a_limited_drop_policy() -> None:
    result = preview_template("logging")
    last = result["rules"][-1]
    assert 'limit rate 5/second' in last["code"]
    assert not last["code"].endswith("drop")
    assert next(p for p in result["policies"] if p["chain"] == "input")["policy"] == "drop"


def test_ssh_limit_runs_before_ssh_accept_but_after_established() -> None:
    rules = preview_template("ssh-limit")["rules"]
    positions = {r["title"]: i for i, r in enumerate(rules)}
    assert positions["Connexions établies et liées"] < positions["Limiter les nouvelles connexions SSH"] < positions["Administration SSH restreinte"]
    assert 'limit rate over 10/minute burst 5 packets counter drop' in rules[-2]["code"]


def test_output_lockdown_uses_specific_dns_and_dhcp_exception() -> None:
    result = preview_template("egress", {"dns_ip": "10.2.0.53"})
    assert next(p for p in result["policies"] if p["chain"] == "output")["policy"] == "drop"
    dns = [r for r in result["rules"] if r["title"].startswith("DNS vers")]
    assert len(dns) == 2 and all("ip daddr 10.2.0.53" in r["code"] for r in dns)
    assert any('udp sport 546 udp dport 547' in r["code"] for r in result["rules"])


def test_previews_do_not_share_mutable_state() -> None:
    one = preview_template("web")
    one["ruleset"]["objects"].clear()
    one["template"]["parameters"].clear()
    two = preview_template("web")
    assert two["ruleset"]["objects"] and two["template"]["parameters"]
    with pytest.raises(NftError) as exc:
        preview_template("no-such-template")
    assert exc.value.code == "not_found"


def test_training_excerpts_are_verbatim_and_attributed() -> None:
    training = [t for t in TEMPLATES if t.origin == "formation"]
    assert len(training) == 7
    for template in training:
        assert template.excerpts
        for excerpt in template.excerpts:
            ref = next(r for r in REFERENCES if r.id == excerpt.source)
            source = (Path(__file__).parents[1] / 'docs/formation/sources' / Path(ref.location).name).read_text()
            for line in excerpt.code.splitlines():
                assert line in source, (template.id, line)
            assert excerpt.explanation and excerpt.adaptation


def test_training_vpn_is_scoped_and_does_not_open_reverse_new_connections() -> None:
    result = preview_template('studi-wireguard', {'service_ports': '443,8443'})
    forward = [r for r in result['rules'] if r['chain'] == 'forward']
    assert len(forward) == 3
    final = forward[-1]['code']
    for part in ['meta iifname "wg0"', 'meta oifname "enp0s9"', 'ip saddr 10.10.10.0/24', 'ip daddr 192.168.20.0/24', 'tcp dport { 443, 8443 }']:
        assert part in final


def test_training_ping_rate_limit_precedes_established_bypass() -> None:
    result = preview_template('studi-ping')
    rules = [r for r in result['rules'] if r['chain'] == 'forward']
    over = next(i for i, r in enumerate(rules) if 'limit rate over' in r['code'])
    established = next(i for i, r in enumerate(rules) if '"established"' in r['code'])
    assert over < established
    assert rules[over]['code'].endswith('counter drop')
    assert 'icmp type "echo-request"' in rules[-1]['code']


def test_training_ad_scope_and_optional_legacy_ports() -> None:
    result = preview_template('studi-ad')
    service_rules = [r for r in result['rules'] if r['chain'] == 'forward'][2:]
    assert service_rules
    assert all('ip daddr 192.168.20.25' in r['code'] for r in service_rules)
    assert not any('tcp dport 139' in r['code'] for r in service_rules)
    customized = preview_template('studi-ad', {'legacy': 'oui', 'adws': 'oui', 'rpc_ports': '50000-50100'})
    assert 'tcp dport 139' in customized['source']
    assert 'tcp dport 9389' in customized['source']
    assert 'tcp dport 50000-50100' in customized['source']


@pytest.mark.parametrize('values', [
    {'admin_if': 'enp0s9'}, {'admin_network': '192.168.20.0/24'}, {'dc_ip': '192.168.21.25'},
])
def test_training_router_rejects_inconsistent_topology(values: dict[str, str]) -> None:
    with pytest.raises(NftError):
        preview_template('studi-ad', values)
