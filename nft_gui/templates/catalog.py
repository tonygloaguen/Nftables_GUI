from __future__ import annotations

from nft_gui.errors import NftError
from nft_gui.templates.schema import Parameter, Reference, Template
from nft_gui.templates.lessons import LESSONS

REFERENCES = [
    Reference(id="manual", title="Manuel officiel nftables", location="https://netfilter.org/projects/nftables/manpage.html", note="Syntaxe des chaînes, expressions, compteurs et décisions. Exemples de ce catalogue rédigés et adaptés pour l’application."),
    Reference(id="workstation", title="nftables wiki : poste de travail", location="https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_workstation", note="Principe du filtrage avec suivi de connexion et maintien du fonctionnement IPv6."),
    Reference(id="nat", title="nftables wiki : NAT", location="https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)", note="Distinction entre traduction d’adresses et autorisation du transfert."),
    Reference(id="limit", title="nftables wiki : limitation de débit", location="https://wiki.nftables.org/wiki-nftables/index.php/Rate_limiting_matchings", note="La limite porte sur la règle entière ; elle n’est pas une limite par adresse IP."),
]


def param(key: str, label: str, default: str, kind: str, help: str = "") -> Parameter:
    return Parameter.model_validate({"key": key, "label": label, "default": default,
                                    "kind": kind, "help": help})


ADMIN = [Parameter(key="ssh", label="Autoriser l’administration SSH", default="non", kind="choice", choices=["non", "oui"]),
         param("admin_network", "Réseau d’administration IPv4", "192.168.1.0/24", "network4", "Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH."),
         param("ssh_port", "Port SSH", "22", "port")]
LAN = [param("lan_network", "Réseau local IPv4", "192.168.10.0/24", "network4"),
       param("lan_if", "Interface du réseau local", "eth1", "interface", "Nom réel : consultez ip -br link. Un VLAN peut être nommé enp2s0.10.")]
WAN = [param("wan_if", "Interface vers Internet", "eth0", "interface")]
CLIENTS = [param("clients", "Clients autorisés (réseau IPv4)", "192.168.1.0/24", "network4")]

COMMON_CAVEATS = [
    "Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).",
    "Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.",
    "Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.",
]


def entry(id: str, title: str, category: str, summary: str, *, parameters: list[Parameter] | None = None,
          prerequisites: list[str] | None = None, caveats: list[str] | None = None,
          sources: list[str] | None = None, recipe: str | None = None) -> Template:
    return Template(id=id, title=title, category=category, summary=summary, recipe=recipe or id,
                    parameters=[p.model_copy(deep=True) for p in [*ADMIN, *(parameters or [])]],
                    prerequisites=prerequisites or ["Le service concerné doit être installé, configuré et en écoute sur la machine."],
                    caveats=[*COMMON_CAVEATS, *(caveats or [])], sources=sources or ["manual", "workstation"])


TEMPLATES = [
    entry("desktop", "Poste Linux", "Postes & administration", "Naviguer et travailler ; seules les réponses et les fonctions réseau de base entrent.", parameters=[param("client_if", "Interface du client DHCP", "eth0", "interface")], prerequisites=["Adapter l’interface si le poste reçoit son adresse par DHCP."], caveats=["Les réponses DHCPv4 et DHCPv6 sont autorisées sur l’interface choisie. Les partages et la découverte mDNS restent fermés."]),
    entry("ssh", "Serveur administré par SSH", "Postes & administration", "Ouvrir SSH uniquement au réseau d’administration indiqué.", caveats=["SSH est activé dans ce modèle, même si l’option SSH facultative des autres modèles est désactivée."]),
    entry("ssh-limit", "SSH avec limite de nouvelles connexions", "Postes & administration", "Limiter les tentatives de nouvelles connexions avant d’autoriser SSH depuis le réseau d’administration.", sources=["manual", "limit"], caveats=["Limite globale de 10 nouveaux paquets SSH par minute, rafale de 5. Ce n’est ni un compteur d’échecs de mot de passe, ni une protection par IP ; les connexions établies continuent."]),
    entry("web", "Serveur web HTTP / HTTPS", "Services", "Publier TCP 80 et 443, avec SSH facultatif et restreint."),
    entry("web-http3", "Serveur web avec HTTP/3", "Services", "Publier HTTP/HTTPS et QUIC sur UDP 443.", caveats=["Le serveur web doit prendre en charge HTTP/3 et disposer de certificats TLS ; ouvrir UDP 443 ne l’active pas."]),
    entry("reverse-proxy", "Application derrière un reverse proxy", "Services", "N’ouvrir le port de l’application qu’à l’adresse du reverse proxy.", parameters=[param("proxy_ip", "Adresse IPv4 du reverse proxy", "192.168.1.10", "address4"), param("service_port", "Port TCP de l’application", "8080", "port")], caveats=["Le modèle concerne le serveur applicatif situé derrière le proxy, pas la machine proxy publique."]),
    entry("dns", "Résolveur DNS du réseau local", "Services", "Recevoir les requêtes DNS des clients autorisés en UDP et TCP.", parameters=CLIENTS, caveats=["Configurer aussi les ACL du résolveur. TCP 53 est nécessaire pour certaines réponses et reprises."]),
    entry("dhcp", "Serveur DHCPv4 du LAN", "Services", "Accepter les demandes DHCP sur une interface locale dédiée.", parameters=[param("lan_if", "Interface desservie", "eth1", "interface")], caveats=["Ne filtre pas la source par sous-réseau : un client sans bail utilise 0.0.0.0. Aucun serveur DHCPv6 ni relais DHCP n’est configuré."]),
    entry("ntp", "Serveur de temps NTP", "Services", "Servir l’heure aux seuls clients du réseau local.", parameters=CLIENTS),
    entry("postgres", "Base PostgreSQL privée", "Données & stockage", "Accepter TCP 5432 uniquement depuis le réseau applicatif.", parameters=CLIENTS, caveats=["Configurer aussi listen_addresses, pg_hba.conf, l’authentification et TLS dans PostgreSQL."]),
    entry("mariadb", "Base MariaDB / MySQL privée", "Données & stockage", "Accepter TCP 3306 uniquement depuis le réseau applicatif.", parameters=CLIENTS, caveats=["Limiter également les comptes SQL et bind-address ; ne pas publier la base sur Internet."]),
    entry("redis", "Redis privé", "Données & stockage", "Limiter TCP 6379 au réseau applicatif.", parameters=CLIENTS, caveats=["Le pare-feu ne remplace pas les ACL, l’authentification et TLS de Redis."]),
    entry("smb", "Partage de fichiers SMB", "Données & stockage", "Autoriser le SMB direct sur TCP 445 depuis le LAN.", parameters=CLIENTS, caveats=["Les anciens ports NetBIOS 137–139 et la découverte automatique ne sont pas ouverts. Utiliser un chemin de partage explicite."]),
    entry("nfs", "Partage NFSv4", "Données & stockage", "Autoriser TCP 2049 depuis le réseau des clients.", parameters=CLIENTS, caveats=["Modèle NFSv4 uniquement. NFSv3 utilise aussi rpcbind et des ports RPC à fixer ; il n’est pas couvert."]),
    entry("monitoring", "Supervision Prometheus / Grafana", "Supervision", "Séparer l’accès à node_exporter du réseau autorisé à consulter les tableaux de bord.", parameters=[param("monitor_ip", "Adresse du collecteur Prometheus", "192.168.1.20", "address4"), *CLIENTS], caveats=["TCP 9100 est réservé au collecteur. TCP 9090 et 3000 sont ouverts aux clients indiqués. L’authentification des interfaces reste à configurer."]),
    entry("wireguard", "Accès local via WireGuard", "VPN", "Recevoir le tunnel WireGuard et autoriser des services locaux aux clients du VPN.", parameters=[param("vpn_if", "Interface du tunnel", "wg0", "interface"), param("vpn_network", "Réseau IPv4 du VPN", "10.8.0.0/24", "network4"), param("vpn_port", "Port UDP WireGuard", "51820", "port"), param("service_ports", "Ports TCP accessibles dans le tunnel", "22,443", "ports")], caveats=["Configurez les clés, peers et AllowedIPs dans WireGuard. Ce modèle dessert la machine VPN elle-même ; il ne route pas les clients vers Internet ou le LAN."]),
    entry("openvpn", "Accès local via OpenVPN", "VPN", "Recevoir OpenVPN en UDP et ouvrir des services locaux dans le tunnel.", parameters=[param("vpn_if", "Interface du tunnel", "tun0", "interface"), param("vpn_network", "Réseau IPv4 du VPN", "10.9.0.0/24", "network4"), param("vpn_port", "Port UDP OpenVPN", "1194", "port"), param("service_ports", "Ports TCP accessibles dans le tunnel", "22,443", "ports")], caveats=["Certificats, authentification et configuration du tunnel sont à préparer dans OpenVPN. Aucun routage des clients vers Internet n’est ajouté."]),
    entry("router-nat", "Routeur LAN → Internet (masquerade)", "Routage & NAT", "Transférer le trafic IPv4 du LAN vers Internet et masquer son adresse source.", parameters=[*LAN, *WAN], sources=["manual", "nat"], prerequisites=["Activer net.ipv4.ip_forward sur le routeur et définir les routes/passerelles. L’application ne modifie pas les sysctl."], caveats=["Les nouvelles connexions WAN → LAN sont bloquées. Le transfert IPv6 reste bloqué ; aucune traduction IPv6 n’est ajoutée."]),
    entry("router-snat", "Routeur avec adresse publique fixe (SNAT)", "Routage & NAT", "Traduire la source des sorties du LAN vers une IPv4 fixe.", parameters=[*LAN, *WAN, param("public_ip", "IPv4 portée par l’interface WAN", "203.0.113.10", "address4")], sources=["manual", "nat"], prerequisites=["Activer le routage IPv4 et configurer l’adresse publique réelle sur le WAN."], caveats=["203.0.113.10 est une adresse de documentation à remplacer. Pour une adresse WAN dynamique, choisir masquerade."]),
    entry("port-forward", "Publier un serveur interne (DNAT)", "Routage & NAT", "Rediriger un port TCP public vers un service du LAN et autoriser précisément ce transfert.", parameters=[*LAN, *WAN, param("public_ip", "IPv4 publique visée", "203.0.113.10", "address4"), param("public_port", "Port TCP public", "8443", "port"), param("server_ip", "IPv4 du serveur interne", "192.168.10.10", "address4"), param("server_port", "Port TCP du serveur interne", "443", "port")], sources=["manual", "nat"], prerequisites=["Activer le routage IPv4. Le serveur interne doit renvoyer ses réponses via ce routeur."], caveats=["La règle forward voit l’adresse et le port APRÈS DNAT. Le modèle ne fournit ni hairpin NAT, ni accès Internet général au LAN."]),
    entry("inter-vlan", "Filtrage entre deux VLAN", "Routage & NAT", "Autoriser un service TCP des clients vers les serveurs et bloquer les autres nouveaux transferts.", parameters=[param("client_if", "Interface VLAN des clients", "eth1.110", "interface"), param("clients", "Réseau des clients", "192.168.110.0/24", "network4"), param("server_if", "Interface VLAN des serveurs", "eth1.120", "interface"), param("servers", "Réseau des serveurs", "192.168.120.0/24", "network4"), param("service_port", "Port TCP autorisé", "443", "port")], prerequisites=["Créer les interfaces VLAN et les routes, activer le routage IPv4 ; aucun de ces réglages n’est effectué par le modèle."], caveats=["Aucun NAT : les adresses source sont conservées. Les réponses sont acceptées par le suivi de connexion."]),
    entry("egress", "Sorties limitées : web, DNS et NTP", "Durcissement", "Bloquer les nouvelles sorties sauf DNS vers un résolveur choisi, NTP et navigation web.", parameters=[param("dns_ip", "Résolveur DNS IPv4", "192.168.1.1", "address4"), param("ntp_ip", "Serveur NTP IPv4", "192.168.1.1", "address4"), param("client_if", "Interface du client DHCP", "eth0", "interface")], caveats=["ICMP/ICMPv6 et DHCP restent autorisés. HTTPS peut transporter du DNS chiffré : ce modèle ne garantit pas l’usage exclusif du résolveur choisi. QUIC et les autres ports sortants sont bloqués."]),
    entry("blocklist", "Bloquer un ensemble d’adresses IPv4", "Durcissement", "Maintenir une liste de sources bloquées dans un ensemble réutilisable.", parameters=[param("blocked", "Adresses ou réseaux à bloquer", "192.0.2.10/32,198.51.100.0/24", "networks4")], caveats=["Adresses d’exemple réservées à la documentation. Le blocage précède les connexions établies, concerne input uniquement et peut donc couper une session existante."]),
    entry("logging", "Journaliser les refus sans saturer les logs", "Supervision", "Ajouter une journalisation limitée à la fin de la chaîne input.", sources=["manual", "limit"], caveats=["Au maximum 5 messages par seconde, rafale de 10, globalement. La politique drop bloque aussi les paquets au-delà de la limite de journalisation."]),
]

REFERENCES.extend([
    Reference(id="studi-before", title="Formation AIS — routage avant durcissement", location="04_PREUVES/L2_ROUTAGE_FILTRAGE/P-L2-01_nftables_ruleset_avant.txt", note="Fichier original consulté : administration 192.168.56.0/24, LAN 192.168.20.0/24, sortie enp0s3. L’autorisation inter-segments initiale était large."),
    Reference(id="studi-after", title="Formation AIS — routage après durcissement", location="04_PREUVES/L2_ROUTAGE_FILTRAGE/P-L2-02_nftables_ruleset_apres.txt", note="Règles retrouvées : SSH, Samba, DNS/HTTP/HTTPS sortants, masquerade et WireGuard. Les invites shell du relevé ne sont pas reprises dans les modèles."),
    Reference(id="studi-smb-note", title="Formation AIS — exception Samba 445", location="04_PREUVES/L2_ROUTAGE_FILTRAGE/P-L2-04_nftables_exception_445.txt", note="Note de synthèse confirmant l’exception forward vers 192.168.20.10 ; ce document n’est pas un ruleset exécutable complet."),
    Reference(id="studi-segments", title="Formation AIS — segmentation et Active Directory", location="04_PREUVES/L2_SEGMENTATION/rtrlinux/P-L2-06_nftables_ruleset_apres.txt", note="Source des ports Active Directory vers 192.168.20.25, des règles WireGuard et du diagnostic ICMP limité. Les compteurs historiques sont réinitialisés dans les nouveaux brouillons."),
    Reference(id="studi-host", title="Formation AIS — pare-feu du serveur Linux", location="04_PREUVES/L3_DURCISSEMENT/P-L3-09_nftables_ufw_serveur.txt", note="Synthèse UFW/iptables-nft : SSH et SMB depuis le réseau d’administration. Le modèle traduit cette intention en nftables natif ; les chaînes gérées par UFW ne sont pas copiées."),
    Reference(id="windows-ports", title="Microsoft — services et ports Windows", location="https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements", note="Référence des services AD et RPC. Les ports utiles dépendent des fonctions activées ; le modèle vise clients → un contrôleur, pas tous les scénarios de réplication."),
    Reference(id="headers", title="nftables wiki — en-têtes IPv6", location="https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_headers", note="Les adaptations utilisent meta l4proto pour reconnaître ICMPv6 même en présence d’en-têtes d’extension."),
])

STUDI_SEGMENT = [param("admin_if", "Interface du segment d’administration", "enp0s10", "interface"),
                 param("lan_if", "Interface du segment serveurs", "enp0s9", "interface"),
                 param("lan_network", "Réseau des serveurs IPv4", "192.168.20.0/24", "network4")]
LEGACY = Parameter(key="legacy", label="Ajouter les anciens ports NetBIOS", default="non", kind="choice", choices=["non", "oui"], help="Désactivés par défaut ; les ports du relevé historique restent documentés.")
STUDI_PREREQUISITES = ["Appliquer ce modèle au routeur Linux de la maquette. Configurer les interfaces, les routes et net.ipv4.ip_forward avant les tests."]
TEMPLATES.extend([
    entry("studi-samba", "TP AIS — SSH et Samba entre segments", "Formation AIS", "Reprendre les exceptions de la maquette vers le serveur 192.168.20.10, avec les anciens ports NetBIOS en option.", parameters=[*STUDI_SEGMENT, param("server_ip", "Serveur SSH / Samba", "192.168.20.10", "address4"), LEGACY], prerequisites=STUDI_PREREQUISITES, sources=["studi-after", "studi-smb-note", "studi-segments"], caveats=["Reprise de forward, pas d’input : le serveur cible est une autre machine. TCP 22 et 445 sont conservés. Les anciens ports TCP 139 et UDP 137/138 sont désactivés par défaut, contrairement au relevé historique."]),
    entry("studi-ad", "TP AIS — accès au contrôleur Active Directory", "Formation AIS", "Reprendre les flux DNS, Kerberos, LDAP, SMB et RPC vers le contrôleur 192.168.20.25.", parameters=[*STUDI_SEGMENT, param("dc_ip", "Contrôleur de domaine IPv4", "192.168.20.25", "address4"), param("rpc_ports", "Plage RPC dynamique configurée sur le DC", "49152-65535", "ports"), LEGACY, Parameter(key="adws", label="Ajouter AD Web Services (TCP 9389)", default="non", kind="choice", choices=["non", "oui"])], prerequisites=STUDI_PREREQUISITES, sources=["studi-segments", "windows-ports"], caveats=["La plage RPC est large mais limitée au DC choisi, au réseau client et aux interfaces. Ne la réduire que si le serveur a lui-même été configuré pour la nouvelle plage.", "Les ports LDAPS et catalogue global sont repris du TP ; à retirer s’ils ne sont pas utilisés. TCP 139 devient facultatif et TCP 9389 est une option supplémentaire, absente du relevé.", "Ce modèle vise les clients vers un DC. Il ne couvre pas automatiquement la réplication entre DC, les approbations ou tous les outils d’administration."]),
    entry("studi-wireguard", "TP AIS — VPN vers des services du LAN", "Formation AIS", "Adapter le tunnel 10.10.10.0/24 vers le LAN 192.168.20.0/24 en limitant les services accessibles.", parameters=[param("lan_if", "Interface du LAN", "enp0s9", "interface"), param("lan_network", "Réseau du LAN", "192.168.20.0/24", "network4"), param("wan_if", "Interface recevant le tunnel", "enp0s3", "interface"), param("vpn_if", "Interface WireGuard", "wg0", "interface"), param("vpn_network", "Réseau du VPN", "10.10.10.0/24", "network4"), param("vpn_port", "Port UDP WireGuard", "51820", "port"), param("service_ports", "Ports TCP autorisés VPN → LAN", "22,445", "ports")], prerequisites=[*STUDI_PREREQUISITES, "Configurer les peers/AllowedIPs et la route de retour du LAN vers le réseau VPN."], sources=["studi-after", "studi-segments"], caveats=["Adaptation volontaire : les deux règles historiques autorisaient tous les protocoles dans les deux sens. Le modèle autorise de nouvelles connexions TCP seulement du VPN vers les ports choisis ; les réponses passent par established/related.", "Aucun NAT dans le tunnel, aucune ouverture LAN → VPN pour les nouvelles connexions."]),
    entry("studi-internet", "TP AIS — deux segments vers DNS et le web", "Formation AIS", "Reprendre les sorties DNS, HTTP et HTTPS des réseaux 192.168.56.0/24 et 192.168.20.0/24, avec masquerade.", parameters=[*STUDI_SEGMENT, param("wan_if", "Interface vers Internet", "enp0s3", "interface")], prerequisites=STUDI_PREREQUISITES, sources=["studi-before", "studi-after", "studi-segments", "nat"], caveats=["UDP 53 et TCP 53/80/443 sont ouverts vers toute destination Internet, comme dans le TP. NTP, QUIC et les autres nouveaux transferts restent bloqués.", "Les deux segments ne peuvent pas initier de communications entre eux dans ce modèle. Le routeur lui-même conserve une politique output accept."]),
    entry("studi-server", "TP AIS — serveur Linux SSH / SMB", "Formation AIS", "Traduire les autorisations UFW du serveur en règles nftables natives : SSH et SMB depuis le réseau d’administration.", parameters=[], prerequisites=["Appliquer sur le serveur Linux qui héberge SSH/Samba, pas sur le routeur. Préparer explicitement le remplacement de la gestion UFW si elle est active."], sources=["studi-host", "studi-smb-note"], caveats=["TCP 445 est autorisé depuis 192.168.56.0/24. SSH est activé par défaut mais reste facultatif. Aucun ancien port NetBIOS n’est ajouté.", "Le document source est une synthèse, pas une sauvegarde complète. Le modèle n’est donc pas une copie à l’identique de l’état UFW."]),
    entry("studi-ping", "TP AIS — diagnostic ICMP limité entre segments", "Formation AIS", "Reprendre les pings du réseau d’administration vers un serveur déterminé, avec limite de débit.", parameters=[*STUDI_SEGMENT, param("server_ip", "Serveur à diagnostiquer", "192.168.20.10", "address4")], prerequisites=STUDI_PREREQUISITES, sources=["studi-segments", "limit"], caveats=["Le TP autorisait deux destinations (192.168.20.10 et .25). Le modèle cible une adresse choisie ; dupliquer la règle pour une autre cible.", "Limite de 10 requêtes ICMP par seconde, rafale de 5, partagée par la règle. Le contrôle de débit est placé avant established : les pings suivants d’un même échange ne contournent pas la limite."]),
    entry("studi-router", "TP AIS — routeur initial à deux segments", "Formation AIS", "Comprendre le routage large du fichier avant durcissement et les deux règles de masquerade.", parameters=[*STUDI_SEGMENT, param("wan_if", "Interface vers Internet", "enp0s3", "interface")], prerequisites=STUDI_PREREQUISITES, sources=["studi-before", "nat"], caveats=["Profil pédagogique permissif : tous les nouveaux protocoles sont autorisés du segment d’administration vers le LAN et des deux segments vers Internet. Préférer les profils Samba/AD/sorties limitées pour restreindre les usages.", "Adaptations au relevé : iif/oif deviennent iifname/oifname, invalid est rejeté, ICMPv6 est conservé et les compteurs démarrent à zéro."]),
])
for _template in TEMPLATES:
    if _template.id.startswith("studi-"):
        _template.origin = "formation"
        _template.excerpts = LESSONS[_template.id]
        for _parameter in _template.parameters:
            if _parameter.key == "admin_network":
                _parameter.default = "192.168.56.0/24"
            if _parameter.key == "ssh":
                _parameter.default = "oui"

# These two profiles always expose SSH, constrained to admin_network.
for _template in TEMPLATES:
    if _template.id in {"ssh", "ssh-limit"}:
        _template.parameters = [p for p in _template.parameters if p.key != "ssh"]


def catalog() -> dict[str, object]:
    return {"templates": [t.model_dump(mode="json") for t in TEMPLATES],
            "references": [r.model_dump(mode="json") for r in REFERENCES]}


def get_template(template_id: str) -> Template:
    for template in TEMPLATES:
        if template.id == template_id:
            return template.model_copy(deep=True)
    raise NftError("Modèle introuvable.", code="not_found")
