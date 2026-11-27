from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import JsonValue

from nft_gui.errors import NftError
from nft_gui.generator import generate_nft
from nft_gui.generator.expressions import expression
from nft_gui.models import Chain, Expr, Rule, Ruleset, Set, Table
from nft_gui.templates.catalog import get_template
from nft_gui.templates.schema import Template


def port_value(text: str) -> JsonValue:
    values: list[JsonValue] = []
    for part in text.split(","):
        bounds = part.strip().split("-")
        if len(bounds) > 2 or any(not re.fullmatch(r"[0-9]{1,5}", b) for b in bounds):
            raise ValueError("Ports attendus : 22,443,8000-8010.")
        numbers = [int(b) for b in bounds]
        if not all(1 <= n <= 65535 for n in numbers) or numbers[-1] < numbers[0]:
            raise ValueError("Les ports doivent être compris entre 1 et 65535, en ordre croissant.")
        values.append(numbers[0] if len(numbers) == 1 else {"range": [numbers[0], numbers[1]]})
    if len(values) > 64:
        raise ValueError("64 ports ou plages au maximum.")
    return values[0] if len(values) == 1 else {"set": values}


def parameters(template: Template, supplied: dict[str, str]) -> dict[str, str]:
    known = {p.key for p in template.parameters}
    if set(supplied) - known:
        raise NftError("Paramètre inconnu : " + ", ".join(sorted(set(supplied) - known)), code="invalid_template")
    result: dict[str, str] = {}
    for p in template.parameters:
        text = supplied.get(p.key, p.default).strip()
        try:
            if not text or len(text) > 1024:
                raise ValueError("Valeur vide ou trop longue.")
            if p.kind == "choice" and text not in p.choices:
                raise ValueError("Choix non autorisé.")
            if p.kind == "network4":
                text = str(ipaddress.IPv4Network(text, strict=True))
            elif p.kind == "networks4":
                parts = text.split(",")
                if len(parts) > 64:
                    raise ValueError("64 adresses ou réseaux au maximum.")
                nets = [ipaddress.IPv4Network(x.strip(), strict=True) for x in parts]
                if any(a.overlaps(b) for i, a in enumerate(nets) for b in nets[i + 1:]):
                    raise ValueError("Les réseaux de l’ensemble ne doivent pas se chevaucher.")
                text = ",".join(map(str, nets))
            elif p.kind == "address4":
                text = str(ipaddress.IPv4Address(text))
            elif p.kind == "interface" and not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", text):
                raise ValueError("Nom d’interface attendu, 1 à 15 caractères, sans espace ni caractère générique.")
            elif p.kind == "port":
                if not re.fullmatch(r"[0-9]{1,5}", text) or not 1 <= int(text) <= 65535:
                    raise ValueError("Port attendu entre 1 et 65535.")
            elif p.kind == "ports":
                port_value(text)
        except ValueError as exc:
            raise NftError(f"{p.label} : {exc}", code="invalid_template") from exc
        result[p.key] = text
    for left, right in [("lan_if", "wan_if"), ("client_if", "server_if"),
                        ("admin_if", "lan_if"), ("admin_if", "wan_if"),
                        ("vpn_if", "lan_if"), ("vpn_if", "wan_if")]:
        if left in result and right in result and result[left] == result[right]:
            raise NftError("Les deux interfaces de routage doivent être différentes.", code="invalid_template")
    for key in ("server_ip", "dc_ip"):
        if key in result and "lan_network" in result:
            if ipaddress.IPv4Address(result[key]) not in ipaddress.IPv4Network(result["lan_network"]):
                raise NftError("Le serveur interne doit appartenir au réseau local indiqué.", code="invalid_template")
    if template.recipe == "inter-vlan":
        if ipaddress.IPv4Network(result["clients"]).overlaps(ipaddress.IPv4Network(result["servers"])):
            raise NftError("Les deux réseaux VLAN ne doivent pas se chevaucher.", code="invalid_template")
    if template.recipe.startswith("studi-") and "lan_network" in result:
        other = "admin_network" if "admin_if" in result else "vpn_network"
        if other in result and ipaddress.IPv4Network(result["lan_network"]).overlaps(ipaddress.IPv4Network(result[other])):
            raise NftError("Les réseaux à router ne doivent pas se chevaucher.", code="invalid_template")
    return result


def address_value(text: str) -> JsonValue:
    if text.startswith("@") or "/" not in text:
        return text
    network = ipaddress.IPv4Network(text)
    return {"prefix": {"addr": str(network.network_address), "len": network.prefixlen}}


class Draft:
    def __init__(self, title: str, *, locked_output: bool = False) -> None:
        self.ir = Ruleset(objects=[Table(family="inet", name="filter", comment=title)])
        self.notes: list[dict[str, object]] = []
        for hook in ("input", "forward", "output"):
            self.ir.objects.append(Chain(family="inet", table="filter", name=hook,
                                         type="filter", hook=hook, prio=0,
                                         policy="accept" if hook == "output" and not locked_output else "drop"))

    def nat(self, hook: Literal["prerouting", "postrouting"]) -> None:
        if not any(isinstance(x, Table) and x.name == "nat" for x in self.ir.objects):
            self.ir.objects.append(Table(family="ip", name="nat"))
        self.ir.objects.append(Chain(family="ip", table="nat", name=hook,
                                     type="nat", hook=hook, prio=-100 if hook == "prerouting" else 100,
                                     policy="accept"))

    def add(self, chain: str, title: str, explanation: str, *, source: str = "", destination: str = "",
            proto: str = "", ports: str = "", sport: str = "", iif: str = "", oif: str = "",
            states: str = "", action: str = "accept", raw: str = "", raw_explanation: str = "",
            nat_addr: str = "", nat_port: str = "", ct_status: str = "", nfproto: str = "",
            icmp_type: str = "") -> None:
        expr: list[Expr] = []
        parts: list[dict[str, str]] = []

        def add(statement: dict[str, JsonValue], detail: str) -> None:
            expr.append(Expr(statement=statement))
            parts.append({"code": expression(statement), "explanation": detail})

        def match(left: dict[str, JsonValue], right: JsonValue, detail: str) -> None:
            add({"match": {"op": "==", "left": left, "right": right}}, detail)

        if nfproto:
            match({"meta": {"key": "nfproto"}}, nfproto, "Restreint la règle à cette famille réseau.")
        for key, text, label in [("iifname", iif, "d’entrée"), ("oifname", oif, "de sortie")]:
            if text:
                match({"meta": {"key": key}}, text, f"Ne vise que les paquets dont l’interface {label} est {text}.")
        for key, text, label in [("saddr", source, "source"), ("daddr", destination, "destination")]:
            if text:
                match({"payload": {"protocol": "ip", "field": key}}, address_value(text),
                      f"L’adresse IPv4 {label} doit correspondre à {text}." + (" @ désigne un ensemble nommé." if text.startswith("@") else ""))
        if proto:
            match({"meta": {"key": "l4proto"}}, proto, f"Sélectionne le protocole de transport {proto}.")
        for key, text, label in [("sport", sport, "source"), ("dport", ports, "destination")]:
            if text:
                if proto not in {"tcp", "udp"}:
                    raise ValueError("A port condition requires TCP or UDP")
                match({"payload": {"protocol": proto, "field": key}}, port_value(text),
                      f"Sélectionne le ou les ports {label} {text}. Une plage inclut ses deux bornes.")
        if states:
            state_values: list[JsonValue] = list(states.split(","))
            match({"ct": {"key": "state"}}, {"set": state_values},
                  "Consulte le suivi de connexion : established = échange déjà établi ; related = trafic lié ; new = début d’échange ; invalid = paquet non suivi correctement.")
        if ct_status:
            match({"ct": {"key": "status"}}, ct_status, "Exige qu’une traduction DNAT ait déjà été effectuée pour cette connexion.")
        if icmp_type:
            match({"payload": {"protocol": "icmp", "field": "type"}}, icmp_type,
                  "Sélectionne les requêtes d’écho ICMP (ping), sans ouvrir les autres protocoles.")
        if raw:
            expr.append(Expr(raw_nft=raw))
            parts.append({"code": raw, "explanation": raw_explanation})
        add({"counter": None}, "Compte les paquets et octets qui ont satisfait tous les critères précédents ; ne décide pas à lui seul du passage.")
        if action:
            body: JsonValue = None
            if action in {"dnat", "snat"}:
                body = {"addr": nat_addr}
                if nat_port:
                    body["port"] = int(nat_port)
            detail = {"accept": "Autorise le paquet dans cette chaîne. D’autres chaînes ou règles de routage peuvent encore intervenir.",
                      "drop": "Abandonne le paquet sans réponse ; les règles suivantes de cette chaîne ne sont pas évaluées.",
                      "masquerade": "Remplace l’IPv4 source par celle de l’interface de sortie ; le suivi de connexion assure la traduction des réponses.",
                      "snat": "Remplace l’IPv4 source par l’adresse fixe indiquée ; ne constitue pas une autorisation de transfert.",
                      "dnat": "Remplace la destination avant routage. Une autorisation distincte dans forward est nécessaire."}[action]
            add({action: body}, detail)
        is_nat = chain in {"prerouting", "postrouting"}
        rule = Rule(family="ip" if is_nat else "inet", table="nat" if is_nat else "filter",
                    chain=chain, comment=title, expr=expr)
        self.ir.objects.append(rule)
        order = sum(isinstance(o, Rule) and o.family == rule.family and o.table == rule.table and o.chain == chain for o in self.ir.objects)
        self.notes.append({"title": title, "explanation": explanation, "family": rule.family,
                           "table": rule.table, "chain": chain, "order": order,
                           "code": " ".join(p["code"] for p in parts), "parts": parts})


def preview_template(template_id: str, supplied: dict[str, str] | None = None) -> dict[str, object]:
    template = get_template(template_id)
    v = parameters(template, supplied or {})
    recipe = template.recipe
    draft = Draft(template.title, locked_output=recipe == "egress")
    a = draft.add
    a("input", "Boucle locale", "Préserve les communications entre applications de cette machine.", iif="lo")
    if recipe == "blocklist":
        draft.ir.objects.append(Set(family="inet", table="filter", name="blocked_sources",
                                    type="ipv4_addr", flags=["interval"], elem=[address_value(x) for x in v["blocked"].split(",")]))
        a("input", "Sources bloquées", "Placée avant established pour bloquer aussi le trafic entrant d’une session déjà ouverte. Les paquets sur lo restent acceptés.", source="@blocked_sources", action="drop")
    a("input", "Paquets invalides", "Écarte les paquets que le suivi de connexion ne sait pas associer correctement.", states="invalid", action="drop")
    a("input", "Connexions établies et liées", "Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.", states="established,related")
    a("input", "ICMP IPv4", "Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.", proto="icmp")
    a("input", "ICMP IPv6", "Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.", proto="ipv6-icmp")
    if recipe in {"desktop", "egress"}:
        a("input", "Réponses DHCPv4", "Permet au client local de recevoir un bail, y compris lorsque la réponse est diffusée.", proto="udp", sport="67", ports="68", iif=v["client_if"], nfproto="ipv4")
        a("input", "Réponses DHCPv6", "Permet au client DHCPv6 de recevoir sa configuration sur l’interface choisie.", proto="udp", sport="547", ports="546", iif=v["client_if"], nfproto="ipv6")
    if recipe == "ssh-limit":
        a("input", "Limiter les nouvelles connexions SSH", "Au-delà du quota global, bloque les nouveaux paquets SSH. Le suivi des connexions établies est placé plus haut pour préserver les sessions actives.", source=v["admin_network"], proto="tcp", ports=v["ssh_port"], states="new", raw="limit rate over 10/minute burst 5 packets", raw_explanation="Détecte le dépassement d’une limite partagée par tous les clients : 10 paquets/minute, capacité de rafale 5. Ce n’est pas une limite par IP.", action="drop")
    if recipe in {"ssh", "ssh-limit"} or v.get("ssh") == "oui":
        a("input", "Administration SSH restreinte", "Seules les nouvelles connexions SSH provenant du réseau d’administration IPv4 sont admises.", source=v["admin_network"], proto="tcp", ports=v["ssh_port"], iif=v.get("admin_if", "") if recipe.startswith("studi-") else "")
    if recipe.startswith("studi-"):
        build_studi(draft, recipe, v)
    elif recipe in {"web", "web-http3"}:
        a("input", "HTTP et HTTPS publics", "Ouvre les services web en IPv4 et IPv6 sur toutes les interfaces. Le chiffrement TLS relève du serveur web.", proto="tcp", ports="80,443")
        if recipe == "web-http3":
            a("input", "HTTP/3 — QUIC", "Autorise le transport QUIC du serveur HTTPS sur UDP 443, en complément de TCP.", proto="udp", ports="443")
    elif recipe == "reverse-proxy":
        a("input", "Application depuis le proxy", "L’adresse source doit être celle du reverse proxy ; les clients ne contactent pas directement ce port.", source=v["proxy_ip"], proto="tcp", ports=v["service_port"])
    elif recipe == "dns":
        for proto in ("udp", "tcp"):
            a("input", "DNS " + proto.upper(), "Réserve le résolveur aux clients indiqués. TCP est conservé pour les réponses volumineuses et les reprises.", source=v["clients"], proto=proto, ports="53")
    elif recipe == "dhcp":
        a("input", "Demandes DHCPv4", "Un client sans adresse peut utiliser 0.0.0.0 comme source ; l’interface et les ports limitent la règle au segment desservi.", proto="udp", sport="68", ports="67", iif=v["lan_if"], nfproto="ipv4")
    elif recipe in {"ntp", "postgres", "mariadb", "redis", "smb", "nfs"}:
        port = {"ntp": "123", "postgres": "5432", "mariadb": "3306", "redis": "6379", "smb": "445", "nfs": "2049"}[recipe]
        a("input", "Accès au service depuis les clients", "Ouvre uniquement le port du service aux adresses IPv4 du réseau autorisé. Les contrôles d’identité restent à configurer dans le service.", source=v["clients"], proto="udp" if recipe == "ntp" else "tcp", ports=port)
    elif recipe == "monitoring":
        a("input", "Collecte node_exporter", "Réserve l’accès aux métriques système à l’adresse du collecteur.", source=v["monitor_ip"], proto="tcp", ports="9100")
        a("input", "Interfaces Prometheus et Grafana", "Permet au réseau indiqué de consulter les interfaces d’administration ; prévoir leur authentification.", source=v["clients"], proto="tcp", ports="9090,3000")
    elif recipe in {"wireguard", "openvpn"}:
        a("input", "Établissement du VPN", "Accepte le transport chiffré vers le service VPN. La vérification des clés/certificats est assurée par le VPN.", proto="udp", ports=v["vpn_port"])
        a("input", "Services locaux via le VPN", "Les deux critères se cumulent : arriver par le tunnel ET utiliser le réseau VPN attendu. Aucun accès aux machines derrière ce serveur n’est autorisé.", source=v["vpn_network"], iif=v["vpn_if"], proto="tcp", ports=v["service_ports"])
    elif recipe in {"router-nat", "router-snat", "port-forward", "inter-vlan"}:
        a("forward", "Transferts invalides", "Rejette le trafic invalide qui traverse le routeur.", states="invalid", action="drop")
        a("forward", "Réponses aux transferts autorisés", "Autorise le trafic de retour et les échanges liés. Les nouvelles connexions nécessitent une règle suivante.", states="established,related")
        if recipe in {"router-nat", "router-snat"}:
            a("forward", "LAN vers Internet", "L’interface d’entrée, le réseau source et l’interface de sortie doivent tous correspondre. Les nouvelles connexions dans le sens inverse restent bloquées.", source=v["lan_network"], iif=v["lan_if"], oif=v["wan_if"])
            draft.nat("postrouting")
            a("postrouting", "Traduction de la source du LAN", "Le NAT intervient après la décision de routage. Il traduit l’adresse mais n’autorise pas le passage à lui seul.", source=v["lan_network"], oif=v["wan_if"], action="masquerade" if recipe == "router-nat" else "snat", nat_addr=v.get("public_ip", ""))
        elif recipe == "port-forward":
            draft.nat("prerouting")
            a("prerouting", "Redirection vers le serveur interne", "Ne redirige que les paquets reçus du WAN à destination de l’IPv4 publique et du port spécifiés.", iif=v["wan_if"], destination=v["public_ip"], proto="tcp", ports=v["public_port"], action="dnat", nat_addr=v["server_ip"], nat_port=v["server_port"])
            a("forward", "Autoriser le flux redirigé", "Vérifie la destination traduite, le port interne et le statut DNAT, puis autorise le transfert WAN → LAN. Le serveur doit renvoyer ses réponses via cette passerelle.", iif=v["wan_if"], oif=v["lan_if"], destination=v["server_ip"], proto="tcp", ports=v["server_port"], ct_status="dnat")
        else:
            a("forward", "Clients vers le service du VLAN serveurs", "Les réseaux et interfaces d’entrée/sortie limitent le chemin autorisé. Les autres nouveaux échanges entre VLAN sont refusés.", iif=v["client_if"], oif=v["server_if"], source=v["clients"], destination=v["servers"], proto="tcp", ports=v["service_port"])
    elif recipe == "egress":
        a("output", "Sorties locales", "Permet aux applications de dialoguer sur la machine.", oif="lo")
        a("output", "Sorties invalides", "Écarte les paquets sortants invalides.", states="invalid", action="drop")
        a("output", "Réponses sortantes", "Préserve les réponses des services entrants autorisés et les connexions déjà établies.", states="established,related")
        for proto in ("icmp", "ipv6-icmp"):
            a("output", "Contrôle réseau " + proto, "Préserve les erreurs, le diagnostic et le fonctionnement IPv6.", proto=proto)
        for proto in ("udp", "tcp"):
            a("output", "DNS vers le résolveur choisi — " + proto, "Limite les requêtes DNS classiques à une IPv4 précise. Ne bloque pas le DNS transporté dans HTTPS.", destination=v["dns_ip"], proto=proto, ports="53")
        a("output", "Synchronisation horaire", "N’autorise NTP que vers l’adresse choisie.", destination=v["ntp_ip"], proto="udp", ports="123")
        a("output", "Navigation HTTP / HTTPS", "Ouvre TCP 80 et 443 vers toute destination IPv4 ou IPv6. Les autres ports sortants restent bloqués.", proto="tcp", ports="80,443")
        for family, sport, dport in [("ipv4", "68", "67"), ("ipv6", "546", "547")]:
            a("output", "Requêtes DHCP " + family, "Permet de demander et renouveler une adresse sur l’interface choisie.", oif=v["client_if"], nfproto=family, proto="udp", sport=sport, ports=dport)
    elif recipe == "logging":
        a("input", "Journal des paquets non autorisés", "Cette règle non terminale est placée après toutes les autorisations. Les paquets atteignent ensuite la politique drop, qu’ils aient été journalisés ou non.", raw='limit rate 5/second burst 10 packets log prefix "nft-input-drop: "', raw_explanation="Limite le journal à 5 paquets/seconde, rafale de 10. log écrit dans le journal du noyau et ne bloque pas le paquet à lui seul.", action="")
    return {"template": template.model_dump(mode="json"), "values": v,
            "ruleset": draft.ir.model_dump(mode="json"), "source": generate_nft(draft.ir),
            "rules": draft.notes, "nft_validated": False,
            "policies": [{"chain": o.name, "policy": o.policy, "explanation":
                          "Trafic vers la machine." if o.name == "input" else "Trafic depuis la machine." if o.name == "output" else "Trafic qui traverse la machine."}
                         for o in draft.ir.objects if isinstance(o, Chain) and o.table == "filter"]}


def build_studi(draft: Draft, recipe: str, v: dict[str, str]) -> None:
    """Adapt verified training extracts; changes from the originals are explicit."""
    a = draft.add
    if recipe == "studi-server":
        a("input", "SMB depuis le réseau d’administration", "Traduit l’autorisation ufw-user-input du relevé en nftables natif. Cette règle s’exécute sur le serveur qui héberge le partage.", source=v["admin_network"], proto="tcp", ports="445")
        return
    a("forward", "Transferts invalides", "Écarte les paquets invalides avant les règles métier.", states="invalid", action="drop")
    if recipe == "studi-ping":
        a("forward", "Excès de requêtes ICMP", "Bloque l’excès avant established pour que tous les pings du même échange soient soumis à la limite, pas seulement le premier paquet.", source=v["admin_network"], destination=v["server_ip"], iif=v["admin_if"], oif=v["lan_if"], proto="icmp", icmp_type="echo-request", raw="limit rate over 10/second burst 5 packets", raw_explanation="Sélectionne les demandes de ping qui dépassent la limite globale de 10/seconde (rafale 5), puis les abandonne.", action="drop")
    a("forward", "Réponses aux transferts autorisés", "Permet les réponses sans ouvrir toutes les nouvelles connexions dans le sens inverse.", states="established,related")
    if recipe == "studi-samba":
        a("forward", "SSH vers le serveur Linux", "Reprise du flux d’administration vers une seule machine du segment serveurs.", source=v["admin_network"], destination=v["server_ip"], iif=v["admin_if"], oif=v["lan_if"], proto="tcp", ports=v["ssh_port"])
        a("forward", "Samba direct vers le serveur", "TCP 445 transporte le partage SMB. Tous les critères du relevé sont conservés : interfaces, réseau source et adresse du serveur.", source=v["admin_network"], destination=v["server_ip"], iif=v["admin_if"], oif=v["lan_if"], proto="tcp", ports="445")
        if v["legacy"] == "oui":
            for proto, ports in [("tcp", "139"), ("udp", "137,138")]:
                a("forward", "NetBIOS historique — " + proto, "Option issue du TP : sessions NetBIOS TCP 139, noms/datagrammes UDP 137/138. Inutile pour un partage SMB direct sans ces anciens services.", source=v["admin_network"], destination=v["server_ip"], iif=v["admin_if"], oif=v["lan_if"], proto=proto, ports=ports)
    elif recipe == "studi-ad":
        for title, proto, ports, note in [
            ("DNS du domaine", "udp", "53", "Résolution des noms et des enregistrements de services du domaine."),
            ("DNS du domaine — TCP", "tcp", "53", "Complète UDP pour les réponses DNS nécessitant TCP."),
            ("Kerberos et changement de mot de passe", "tcp", "88,464", "88 : authentification Kerberos ; 464 : changement de mot de passe Kerberos."),
            ("Kerberos — UDP", "udp", "88,464", "Conserve les transports UDP de Kerberos présents dans le relevé."),
            ("Horloge et découverte LDAP", "udp", "123,389", "123 : synchronisation horaire ; 389/UDP : découverte LDAP (CLDAP)."),
            ("Annuaire et catalogue global", "tcp", "389,636,3268,3269", "389 : LDAP ; 636 : LDAPS ; 3268/3269 : catalogue global, avec ou sans TLS. Ouvrir ces ports ne configure pas les certificats."),
            ("SMB du domaine", "tcp", "445", "Accès aux partages du domaine, notamment SYSVOL/NETLOGON."),
            ("Point d’entrée RPC", "tcp", "135", "Le mappeur RPC indique au client le port dynamique à contacter."),
            ("Ports RPC dynamiques", "tcp", v["rpc_ports"], "Le port est choisi par le service RPC du contrôleur ; limiter la plage nécessite aussi de configurer le serveur."),
        ]:
            a("forward", title, note, source=v["admin_network"], destination=v["dc_ip"], iif=v["admin_if"], oif=v["lan_if"], proto=proto, ports=ports)
        if v["legacy"] == "oui":
            a("forward", "Session NetBIOS historique du domaine", "TCP 139 figurait dans le relevé. Il devient facultatif pour un environnement qui utilise SMB direct.", source=v["admin_network"], destination=v["dc_ip"], iif=v["admin_if"], oif=v["lan_if"], proto="tcp", ports="139")
        if v["adws"] == "oui":
            a("forward", "Administration AD Web Services", "Option supplémentaire absente du relevé, pour les outils qui utilisent ADWS.", source=v["admin_network"], destination=v["dc_ip"], iif=v["admin_if"], oif=v["lan_if"], proto="tcp", ports="9389")
    elif recipe == "studi-wireguard":
        a("input", "Transport WireGuard", "Le tunnel arrive sur le routeur lui-même : input. Les paquets déchiffrés à destination du LAN traversent ensuite forward.", iif=v["wan_if"], proto="udp", ports=v["vpn_port"])
        a("forward", "Services du LAN accessibles par le VPN", "Remplace les ouvertures historiques tous protocoles / deux sens par un accès TCP ciblé VPN → LAN. Les réponses sont gérées plus haut.", source=v["vpn_network"], destination=v["lan_network"], iif=v["vpn_if"], oif=v["lan_if"], proto="tcp", ports=v["service_ports"])
    elif recipe in {"studi-internet", "studi-router"}:
        if recipe == "studi-router":
            a("forward", "Administration vers le LAN — tous protocoles", "Reprise de la règle large du fichier avant durcissement. Aucun port ni protocole n’est limité ; les profils Samba et AD permettent de la remplacer par des exceptions précises.", source=v["admin_network"], destination=v["lan_network"], iif=v["admin_if"], oif=v["lan_if"])
        draft.nat("postrouting")
        for iface, network, label in [(v["admin_if"], v["admin_network"], "administration"), (v["lan_if"], v["lan_network"], "serveurs")]:
            if recipe == "studi-router":
                a("forward", "Sorties du segment " + label, "Reprise de l’état avant durcissement : tout trafic IPv4 du segment vers le WAN est autorisé.", source=network, iif=iface, oif=v["wan_if"])
            else:
                a("forward", "DNS UDP du segment " + label, "Reprend l’accès DNS sortant du TP, sans contraindre l’adresse du résolveur.", source=network, iif=iface, oif=v["wan_if"], proto="udp", ports="53")
                a("forward", "DNS TCP et web du segment " + label, "53 : DNS via TCP ; 80 : HTTP ; 443 : HTTPS. Aucun autre nouveau flux de ce segment vers Internet n’est ouvert.", source=network, iif=iface, oif=v["wan_if"], proto="tcp", ports="53,80,443")
            a("postrouting", "Masquerade du segment " + label, "Conserve les deux réseaux internes distincts et remplace leur adresse source uniquement à la sortie WAN.", source=network, oif=v["wan_if"], action="masquerade")
    elif recipe == "studi-ping":
        a("forward", "Ping vers le serveur choisi", "Autorise les requêtes non rejetées par la limite placée avant established. Les réponses sont couvertes par le suivi de connexion.", source=v["admin_network"], destination=v["server_ip"], iif=v["admin_if"], oif=v["lan_if"], proto="icmp", icmp_type="echo-request")
    else:
        raise NftError("Recette de formation inconnue.", code="invalid_template")
