"""Exact excerpts from the user's training files, with explicit adaptation notes."""
from nft_gui.templates.schema import SourceExcerpt

LESSONS = {
    "studi-samba": [SourceExcerpt(
        source="studi-after",
        code='iifname "enp0s10" oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.10 tcp dport 445 accept',
        explanation="Sur le routeur, forward traite le trafic de passage. Le paquet doit venir d’enp0s10 ET du réseau 192.168.56.0/24, sortir par enp0s9 ET viser 192.168.20.10 sur TCP 445. accept permet le partage SMB ; les autres destinations ne correspondent pas.",
        adaptation="Même intention et mêmes limites, avec interfaces/adresses paramétrables et compteur ajouté. Les règles SSH et anciens ports NetBIOS du fichier sont séparées ; NetBIOS est facultatif."),
    ],
    "studi-ad": [SourceExcerpt(
        source="studi-segments",
        code='iifname "enp0s10" oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 tcp dport { 53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269 } counter packets 27 bytes 1404 accept\niifname "enp0s10" oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 udp dport { 53, 88, 123, 389, 464 } accept\niifname "enp0s10" oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 tcp dport 49152-65535 accept',
        explanation="Les trois lignes ciblent un seul DC. La première réunit les services TCP, la seconde DNS/Kerberos/NTP/CLDAP en UDP, la troisième les ports négociés par RPC. Les valeurs 27 paquets / 1404 octets sont une mesure au moment du relevé, pas une limite.",
        adaptation="Les ports sont répartis par service pour être lisibles. TCP 139 devient optionnel ; ADWS 9389 est une option nouvelle. Les compteurs historiques ne sont pas restaurés. La plage RPC reste configurable."),
    ],
    "studi-wireguard": [SourceExcerpt(
        source="studi-segments",
        code='iifname "wg0" oifname "enp0s9" ip saddr 10.10.10.0/24 ip daddr 192.168.20.0/24 accept\niifname "enp0s9" oifname "wg0" ip saddr 192.168.20.0/24 ip daddr 10.10.10.0/24 accept',
        explanation="La première règle laisse entrer dans le LAN tout trafic routé venant du VPN. La seconde autorise aussi de nouvelles connexions initiées par le LAN vers le VPN. Ni le protocole ni les ports ne sont limités.",
        adaptation="Le modèle conserve le chemin VPN → LAN mais exige TCP et les ports choisis. La règle inverse générale est retirée ; les réponses sont autorisées par established/related. Le port UDP du tunnel reste une règle input distincte."),
    ],
    "studi-internet": [SourceExcerpt(
        source="studi-after",
        code='iifname "enp0s9" oifname "enp0s3" ip saddr 192.168.20.0/24 udp dport 53 accept\niifname "enp0s9" oifname "enp0s3" ip saddr 192.168.20.0/24 tcp dport { 53, 80, 443 } accept\noifname "enp0s3" ip saddr 192.168.20.0/24 masquerade',
        explanation="Les deux premières lignes, dans forward, ouvrent DNS et le web du LAN vers le WAN. La troisième, dans postrouting de type nat, remplace la source par l’IPv4 du WAN. Le fichier contient le même ensemble pour 192.168.56.0/24.",
        adaptation="Les deux segments et les ports sont conservés et paramétrés. Les ouvertures inter-segments et VPN du ruleset complet ne font pas partie de ce modèle centré sur les sorties Internet."),
    ],
    "studi-server": [SourceExcerpt(
        source="studi-host",
        code='ip saddr 192.168.56.0/24 tcp dport 22 accept\nip saddr 192.168.56.0/24 tcp dport 445 accept',
        explanation="Ces expressions sont citées dans une synthèse de ufw-user-input. Elles autorisent SSH et SMB vers le serveur lui-même depuis le segment d’administration. Ce ne sont pas des règles de transfert vers une autre machine.",
        adaptation="Reconstruction dans une table inet native, avec le socle loopback/suivi de connexion/ICMP. Il ne s’agit pas d’une conversion exhaustive de toutes les chaînes UFW."),
    ],
    "studi-ping": [SourceExcerpt(
        source="studi-segments",
        code='iifname "enp0s10" oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr { 192.168.20.10, 192.168.20.25 } ip protocol icmp icmp type echo-request limit rate 10/second burst 5 packets counter packets 3 bytes 228 accept comment "diagnostic ICMP depuis le segment d administration"',
        explanation="La règle vise les demandes de ping vers deux machines. limit n’autorise que les paquets sous le quota global de la règle ; les autres continuent vers le refus par défaut. Dans le fichier, established/related est placé avant : les paquets d’un échange déjà établi peuvent donc ne plus atteindre cette limite.",
        adaptation="La destination devient un champ. Une règle limit rate over … drop est placée AVANT established/related, suivie d’une autorisation des requêtes restantes. Les compteurs 3/228 sont réinitialisés."),
    ],
    "studi-router": [SourceExcerpt(
        source="studi-before",
        code='iif "enp0s10" oif "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.0/24 accept\niif "enp0s9" oif "enp0s3" ip saddr 192.168.20.0/24 accept\niif "enp0s10" oif "enp0s3" ip saddr 192.168.56.0/24 accept',
        explanation="Ces trois règles autorisent tous les protocoles dans les chemins indiqués. La politique forward drop bloque les autres chemins, mais ne rend pas ces trois autorisations plus restrictives. Le ruleset contient deux masquerade pour les sorties des deux réseaux.",
        adaptation="Profil pédagogique volontairement large, clairement signalé. Les noms d’interfaces sont comparés avec iifname/oifname, le suivi invalide est rejeté et ICMPv6 reste fonctionnel. Les autres modèles de formation décomposent le durcissement."),
    ],
}
