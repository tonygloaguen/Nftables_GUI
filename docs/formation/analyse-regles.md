# Les règles retrouvées dans la formation AIS

Les cinq preuves textuelles utilisées sont conservées dans `sources/`. Le fichier `provenance.json` donne leur emplacement relatif dans les preuves de formation et leur empreinte SHA-256. Les documents de synthèse sont distingués des relevés complets. Les modèles portent le badge **Issu de la formation** dans l’interface ; chaque fiche montre les extraits d’origine, leur explication et les changements apportés.

## La maquette décrite dans les relevés

| Élément | Valeur retrouvée | Rôle |
| --- | --- | --- |
| Segment d’administration | 192.168.56.0/24, interface enp0s10 du routeur | Source des connexions d’administration |
| Segment serveurs | 192.168.20.0/24, interface enp0s9 | Réseau des serveurs |
| Serveur Linux | 192.168.20.10 | SSH et Samba |
| Contrôleur de domaine | 192.168.20.25 | Services Active Directory |
| Sortie Internet | enp0s3 | Routage et masquerade |
| Tunnel WireGuard | wg0, 10.10.10.0/24 | Accès VPN au LAN |

Ces valeurs appartiennent à la maquette. Elles sont proposées dans les modèles de formation et restent modifiables.

## 1. D’un routeur permissif à des exceptions précises

Le fichier `P-L2-01_nftables_ruleset_avant.txt` possède une politique `forward drop`, mais autorise largement trois chemins : administration → serveurs, serveurs → Internet, administration → Internet. Une politique restrictive n’empêche donc pas une règle explicite d’autoriser tous les protocoles sur un chemin.

```nft
iif "enp0s10" oif "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.0/24 accept
```

Les quatre conditions se cumulent : interface d’entrée, interface de sortie, réseau source et réseau destination. Aucun port n’est précisé. Le modèle **TP AIS — routeur initial à deux segments** conserve cette portée pour illustrer le point de départ. Les modèles suivants montrent des restrictions par service.

## 2. L’exception Samba se place dans forward sur le routeur

```nft
iifname "enp0s10" oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.10 tcp dport 445 accept
```

Le paquet traverse le routeur pour atteindre le serveur : il relève de `forward`. Sur le serveur Linux lui-même, une règle équivalente se place dans `input`. La note `P-L2-04_nftables_exception_445.txt` confirme l’exception mais n’est pas un script complet.

Le relevé contient aussi SSH/TCP 22 et les anciens ports NetBIOS TCP 139, UDP 137/138. Le modèle **SSH et Samba entre segments** rend NetBIOS facultatif, désactivé par défaut. La fiche précise ce changement ; l’original reste consultable dans les sources.

## 3. Active Directory : expliquer les groupes de ports

Dans `P-L2-06_nftables_ruleset_apres.txt`, les flux sont limités à `192.168.20.25`. Le modèle les sépare par fonction pour éviter une seule longue liste opaque.

| Ports du relevé | Fonction expliquée |
| --- | --- |
| TCP/UDP 53 | DNS du domaine |
| TCP/UDP 88 | Kerberos |
| TCP/UDP 464 | Changement de mot de passe Kerberos |
| UDP 123 | Synchronisation horaire |
| TCP 389 / UDP 389 | LDAP / découverte CLDAP |
| TCP 636 | LDAP sur TLS, à configurer côté serveur |
| TCP 3268 / 3269 | Catalogue global, avec ou sans TLS |
| TCP 445 | SMB, notamment pour les partages du domaine |
| TCP 135 | Point d’entrée RPC |
| TCP 49152–65535 | Ports dynamiques RPC |
| TCP 139 | Session NetBIOS historique ; option désactivée dans le modèle |

La plage RPC semble large mais les critères d’adresse et d’interfaces la limitent au contrôleur choisi. La réduire dans le pare-feu seul peut casser les services ; il faut également configurer les ports du serveur. TCP 9389 (ADWS) est proposé en option, explicitement absent du relevé initial. Le modèle vise les clients vers un contrôleur, sans prétendre couvrir toutes les réplications et approbations AD.

Référence de vérification : [Microsoft — services et ports réseau Windows](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements).

## 4. Les deux règles WireGuard historiques ouvrent deux sens

```nft
iifname "wg0" oifname "enp0s9" ip saddr 10.10.10.0/24 ip daddr 192.168.20.0/24 accept
iifname "enp0s9" oifname "wg0" ip saddr 192.168.20.0/24 ip daddr 10.10.10.0/24 accept
```

La deuxième ligne ne sert pas uniquement aux réponses : elle autorise de nouvelles connexions du LAN vers le VPN. Les deux lignes acceptent tous les protocoles. Le modèle **VPN vers des services du LAN** retient un sens d’initiation VPN → LAN et une liste de ports TCP choisie par l’utilisateur. `ct state established,related accept` couvre les réponses. Le routage, la route de retour et les `AllowedIPs` WireGuard restent à configurer ; aucun NAT n’est ajouté dans le tunnel.

Le port UDP 51820, qui reçoit le tunnel sur le routeur, appartient à `input`. Il ne suffit pas à autoriser les paquets déchiffrés à traverser `forward`.

## 5. Autoriser une sortie et traduire sa source sont deux opérations

Le relevé après durcissement ouvre UDP 53 et TCP 53/80/443 vers Internet pour chacun des deux segments. Les règles `masquerade` sont dans une chaîne `postrouting` de type `nat` ; les décisions d’autorisation sont dans `forward`.

```nft
oifname "enp0s3" ip saddr 192.168.20.0/24 masquerade
oifname "enp0s3" ip saddr 192.168.56.0/24 masquerade
```

Elles remplacent les adresses source internes par celle de la sortie WAN. Elles ne permettent pas, à elles seules, de franchir une politique `forward drop`. Le modèle **Deux segments vers DNS et le web** conserve la restriction de services du TP et les deux règles NAT.

## 6. Le compteur n’est pas une limite ; le placement de limit compte

Le relevé contient un ping limité à `10/second burst 5 packets` vers deux serveurs, après la règle qui accepte `established,related`. Les pings d’un échange déjà établi peuvent donc passer avant la règle de limitation.

Le modèle **Diagnostic ICMP limité entre segments** place un rejet de l’excès avant l’autorisation des connexions établies. Il autorise ensuite les requêtes restantes vers une adresse choisie. La limite est globale à cette règle, pas individuelle par client. Les compteurs historiques tels que `counter packets 3 bytes 228` sont des mesures, pas des seuils ; les nouveaux brouillons repartent avec des compteurs neufs.

Référence : [nftables — limites de débit](https://wiki.nftables.org/wiki-nftables/index.php/Rate_limiting_matchings).

## 7. Reprise du pare-feu du serveur Linux

`P-L3-09_nftables_ufw_serveur.txt` est une synthèse UFW/iptables-nft, et non un export complet. Elle autorise SSH et SMB depuis le segment d’administration. Le modèle **Serveur Linux SSH / SMB** reconstruit cette intention dans une table nftables native. Il ne recopie pas les chaînes internes d’UFW. Un remplacement réel doit tenir compte du gestionnaire de pare-feu déjà actif.

## Adaptations communes et vérification

- Les modèles sont des configurations complètes, pas des ajouts automatiques aux règles actives. Chaque fiche indique son périmètre ; les profils spécialisés ne reprennent pas toutes les exceptions du relevé complet.
- Les noms d’interfaces sont comparés avec `iifname/oifname`. Les noms et réseaux restent des champs à personnaliser.
- Le filtrage ICMPv6 utilise `meta l4proto` pour gérer les en-têtes d’extension ; la source utilisait aussi `ip6 nexthdr ipv6-icmp`. Voir [la documentation nftables sur les en-têtes](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_headers).
- Les invites shell, étapes d’édition et compteurs historiques des preuves ne sont pas injectés dans les nouveaux scripts.
- Le blocage IPv6 du transit reste explicite par la politique `forward drop`. Les modèles de transit présentés ici ouvrent des flux IPv4.
- Un aperçu généré n’est pas une validation du noyau. La vérification `nft -c` et le mécanisme d’application temporaire restent obligatoires dans l’application.

Le catalogue complet et ses règles adaptées se trouvent dans [modeles-expliques.md](../modeles-expliques.md). Les extraits d’origine sont également visibles dans les fiches de formation de l’interface.
