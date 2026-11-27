# Modèles nftables expliqués

Ce catalogue est généré depuis les mêmes modèles que l’interface. Les valeurs proposées sont des exemples à adapter. Les scripts remplacent le ruleset complet ; ils ne sont pas appliqués par cet export.

## Lire une règle

| Élément | Rôle |
| --- | --- |
| `input` | Paquets destinés à cette machine. |
| `output` | Paquets émis par cette machine. |
| `forward` | Paquets qui traversent le routeur. |
| `iifname` / `oifname` | Interfaces d’entrée / de sortie. |
| `ip saddr` / `ip daddr` | Adresse ou réseau source / destination IPv4. |
| `tcp dport` / `udp dport` | Port du service visé. |
| `ct state` | État de l’échange selon le suivi de connexion. |
| `counter` | Compteur de paquets et d’octets, sans décision de filtrage. |
| `accept` / `drop` | Autoriser dans cette chaîne / abandonner le paquet. |
| `policy drop` | Abandonner ce qui atteint la fin de la chaîne. |
| `dnat` / `snat` / `masquerade` | Traduire les adresses, indépendamment des autorisations de transfert. |

Les critères d’une même règle se cumulent. L’ordre est significatif à l’intérieur de chaque chaîne. `log` et `counter` ne terminent pas l’évaluation. Une autorisation dans une chaîne ne contourne pas les autres chaînes du système.

## Sources

- **Manuel officiel nftables** — https://netfilter.org/projects/nftables/manpage.html
  Syntaxe des chaînes, expressions, compteurs et décisions. Exemples de ce catalogue rédigés et adaptés pour l’application.
- **nftables wiki : poste de travail** — https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_workstation
  Principe du filtrage avec suivi de connexion et maintien du fonctionnement IPv6.
- **nftables wiki : NAT** — https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)
  Distinction entre traduction d’adresses et autorisation du transfert.
- **nftables wiki : limitation de débit** — https://wiki.nftables.org/wiki-nftables/index.php/Rate_limiting_matchings
  La limite porte sur la règle entière ; elle n’est pas une limite par adresse IP.
- **Formation AIS — routage avant durcissement** — 04_PREUVES/L2_ROUTAGE_FILTRAGE/P-L2-01_nftables_ruleset_avant.txt
  Fichier original consulté : administration 192.168.56.0/24, LAN 192.168.20.0/24, sortie enp0s3. L’autorisation inter-segments initiale était large.
- **Formation AIS — routage après durcissement** — 04_PREUVES/L2_ROUTAGE_FILTRAGE/P-L2-02_nftables_ruleset_apres.txt
  Règles retrouvées : SSH, Samba, DNS/HTTP/HTTPS sortants, masquerade et WireGuard. Les invites shell du relevé ne sont pas reprises dans les modèles.
- **Formation AIS — exception Samba 445** — 04_PREUVES/L2_ROUTAGE_FILTRAGE/P-L2-04_nftables_exception_445.txt
  Note de synthèse confirmant l’exception forward vers 192.168.20.10 ; ce document n’est pas un ruleset exécutable complet.
- **Formation AIS — segmentation et Active Directory** — 04_PREUVES/L2_SEGMENTATION/rtrlinux/P-L2-06_nftables_ruleset_apres.txt
  Source des ports Active Directory vers 192.168.20.25, des règles WireGuard et du diagnostic ICMP limité. Les compteurs historiques sont réinitialisés dans les nouveaux brouillons.
- **Formation AIS — pare-feu du serveur Linux** — 04_PREUVES/L3_DURCISSEMENT/P-L3-09_nftables_ufw_serveur.txt
  Synthèse UFW/iptables-nft : SSH et SMB depuis le réseau d’administration. Le modèle traduit cette intention en nftables natif ; les chaînes gérées par UFW ne sont pas copiées.
- **Microsoft — services et ports Windows** — https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements
  Référence des services AD et RPC. Les ports utiles dépendent des fonctions activées ; le modèle vise clients → un contrôleur, pas tous les scénarios de réplication.
- **nftables wiki — en-têtes IPv6** — https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_headers
  Les adaptations utilisent meta l4proto pour reconnaître ICMPv6 même en présence d’en-têtes d’extension.

## Catalogue

### Poste Linux

Catégorie : Postes & administration. Origine : classique.

Naviguer et travailler ; seules les réponses et les fonctions réseau de base entrent.

Script complet : [examples/templates/desktop.nft](../examples/templates/desktop.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Interface du client DHCP | `eth0` |  |

Prérequis :

- Adapter l’interface si le poste reçoit son adresse par DHCP.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Les réponses DHCPv4 et DHCPv6 sont autorisées sur l’interface choisie. Les partages et la découverte mDNS restent fermés.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Réponses DHCPv4**

```nft
meta nfproto "ipv4" meta iifname "eth0" meta l4proto "udp" udp sport 67 udp dport 68 counter accept
```

Permet au client local de recevoir un bail, y compris lorsque la réponse est diffusée.

**filter / input · 7 — Réponses DHCPv6**

```nft
meta nfproto "ipv6" meta iifname "eth0" meta l4proto "udp" udp sport 547 udp dport 546 counter accept
```

Permet au client DHCPv6 de recevoir sa configuration sur l’interface choisie.

### Serveur administré par SSH

Catégorie : Postes & administration. Origine : classique.

Ouvrir SSH uniquement au réseau d’administration indiqué.

Script complet : [examples/templates/ssh.nft](../examples/templates/ssh.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- SSH est activé dans ce modèle, même si l’option SSH facultative des autres modèles est désactivée.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Administration SSH restreinte**

```nft
ip saddr 192.168.1.0/24 meta l4proto "tcp" tcp dport 22 counter accept
```

Seules les nouvelles connexions SSH provenant du réseau d’administration IPv4 sont admises.

### SSH avec limite de nouvelles connexions

Catégorie : Postes & administration. Origine : classique.

Limiter les tentatives de nouvelles connexions avant d’autoriser SSH depuis le réseau d’administration.

Script complet : [examples/templates/ssh-limit.nft](../examples/templates/ssh-limit.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Limite globale de 10 nouveaux paquets SSH par minute, rafale de 5. Ce n’est ni un compteur d’échecs de mot de passe, ni une protection par IP ; les connexions établies continuent.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Limiter les nouvelles connexions SSH**

```nft
ip saddr 192.168.1.0/24 meta l4proto "tcp" tcp dport 22 ct state { "new" } limit rate over 10/minute burst 5 packets counter drop
```

Au-delà du quota global, bloque les nouveaux paquets SSH. Le suivi des connexions établies est placé plus haut pour préserver les sessions actives.

**filter / input · 7 — Administration SSH restreinte**

```nft
ip saddr 192.168.1.0/24 meta l4proto "tcp" tcp dport 22 counter accept
```

Seules les nouvelles connexions SSH provenant du réseau d’administration IPv4 sont admises.

### Serveur web HTTP / HTTPS

Catégorie : Services. Origine : classique.

Publier TCP 80 et 443, avec SSH facultatif et restreint.

Script complet : [examples/templates/web.nft](../examples/templates/web.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — HTTP et HTTPS publics**

```nft
meta l4proto "tcp" tcp dport { 80, 443 } counter accept
```

Ouvre les services web en IPv4 et IPv6 sur toutes les interfaces. Le chiffrement TLS relève du serveur web.

### Serveur web avec HTTP/3

Catégorie : Services. Origine : classique.

Publier HTTP/HTTPS et QUIC sur UDP 443.

Script complet : [examples/templates/web-http3.nft](../examples/templates/web-http3.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Le serveur web doit prendre en charge HTTP/3 et disposer de certificats TLS ; ouvrir UDP 443 ne l’active pas.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — HTTP et HTTPS publics**

```nft
meta l4proto "tcp" tcp dport { 80, 443 } counter accept
```

Ouvre les services web en IPv4 et IPv6 sur toutes les interfaces. Le chiffrement TLS relève du serveur web.

**filter / input · 7 — HTTP/3 — QUIC**

```nft
meta l4proto "udp" udp dport 443 counter accept
```

Autorise le transport QUIC du serveur HTTPS sur UDP 443, en complément de TCP.

### Application derrière un reverse proxy

Catégorie : Services. Origine : classique.

N’ouvrir le port de l’application qu’à l’adresse du reverse proxy.

Script complet : [examples/templates/reverse-proxy.nft](../examples/templates/reverse-proxy.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Adresse IPv4 du reverse proxy | `192.168.1.10` |  |
| Port TCP de l’application | `8080` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Le modèle concerne le serveur applicatif situé derrière le proxy, pas la machine proxy publique.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Application depuis le proxy**

```nft
ip saddr 192.168.1.10 meta l4proto "tcp" tcp dport 8080 counter accept
```

L’adresse source doit être celle du reverse proxy ; les clients ne contactent pas directement ce port.

### Résolveur DNS du réseau local

Catégorie : Services. Origine : classique.

Recevoir les requêtes DNS des clients autorisés en UDP et TCP.

Script complet : [examples/templates/dns.nft](../examples/templates/dns.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Clients autorisés (réseau IPv4) | `192.168.1.0/24` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Configurer aussi les ACL du résolveur. TCP 53 est nécessaire pour certaines réponses et reprises.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — DNS UDP**

```nft
ip saddr 192.168.1.0/24 meta l4proto "udp" udp dport 53 counter accept
```

Réserve le résolveur aux clients indiqués. TCP est conservé pour les réponses volumineuses et les reprises.

**filter / input · 7 — DNS TCP**

```nft
ip saddr 192.168.1.0/24 meta l4proto "tcp" tcp dport 53 counter accept
```

Réserve le résolveur aux clients indiqués. TCP est conservé pour les réponses volumineuses et les reprises.

### Serveur DHCPv4 du LAN

Catégorie : Services. Origine : classique.

Accepter les demandes DHCP sur une interface locale dédiée.

Script complet : [examples/templates/dhcp.nft](../examples/templates/dhcp.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Interface desservie | `eth1` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Ne filtre pas la source par sous-réseau : un client sans bail utilise 0.0.0.0. Aucun serveur DHCPv6 ni relais DHCP n’est configuré.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Demandes DHCPv4**

```nft
meta nfproto "ipv4" meta iifname "eth1" meta l4proto "udp" udp sport 68 udp dport 67 counter accept
```

Un client sans adresse peut utiliser 0.0.0.0 comme source ; l’interface et les ports limitent la règle au segment desservi.

### Serveur de temps NTP

Catégorie : Services. Origine : classique.

Servir l’heure aux seuls clients du réseau local.

Script complet : [examples/templates/ntp.nft](../examples/templates/ntp.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Clients autorisés (réseau IPv4) | `192.168.1.0/24` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Accès au service depuis les clients**

```nft
ip saddr 192.168.1.0/24 meta l4proto "udp" udp dport 123 counter accept
```

Ouvre uniquement le port du service aux adresses IPv4 du réseau autorisé. Les contrôles d’identité restent à configurer dans le service.

### Base PostgreSQL privée

Catégorie : Données & stockage. Origine : classique.

Accepter TCP 5432 uniquement depuis le réseau applicatif.

Script complet : [examples/templates/postgres.nft](../examples/templates/postgres.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Clients autorisés (réseau IPv4) | `192.168.1.0/24` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Configurer aussi listen_addresses, pg_hba.conf, l’authentification et TLS dans PostgreSQL.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Accès au service depuis les clients**

```nft
ip saddr 192.168.1.0/24 meta l4proto "tcp" tcp dport 5432 counter accept
```

Ouvre uniquement le port du service aux adresses IPv4 du réseau autorisé. Les contrôles d’identité restent à configurer dans le service.

### Base MariaDB / MySQL privée

Catégorie : Données & stockage. Origine : classique.

Accepter TCP 3306 uniquement depuis le réseau applicatif.

Script complet : [examples/templates/mariadb.nft](../examples/templates/mariadb.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Clients autorisés (réseau IPv4) | `192.168.1.0/24` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Limiter également les comptes SQL et bind-address ; ne pas publier la base sur Internet.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Accès au service depuis les clients**

```nft
ip saddr 192.168.1.0/24 meta l4proto "tcp" tcp dport 3306 counter accept
```

Ouvre uniquement le port du service aux adresses IPv4 du réseau autorisé. Les contrôles d’identité restent à configurer dans le service.

### Redis privé

Catégorie : Données & stockage. Origine : classique.

Limiter TCP 6379 au réseau applicatif.

Script complet : [examples/templates/redis.nft](../examples/templates/redis.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Clients autorisés (réseau IPv4) | `192.168.1.0/24` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Le pare-feu ne remplace pas les ACL, l’authentification et TLS de Redis.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Accès au service depuis les clients**

```nft
ip saddr 192.168.1.0/24 meta l4proto "tcp" tcp dport 6379 counter accept
```

Ouvre uniquement le port du service aux adresses IPv4 du réseau autorisé. Les contrôles d’identité restent à configurer dans le service.

### Partage de fichiers SMB

Catégorie : Données & stockage. Origine : classique.

Autoriser le SMB direct sur TCP 445 depuis le LAN.

Script complet : [examples/templates/smb.nft](../examples/templates/smb.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Clients autorisés (réseau IPv4) | `192.168.1.0/24` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Les anciens ports NetBIOS 137–139 et la découverte automatique ne sont pas ouverts. Utiliser un chemin de partage explicite.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Accès au service depuis les clients**

```nft
ip saddr 192.168.1.0/24 meta l4proto "tcp" tcp dport 445 counter accept
```

Ouvre uniquement le port du service aux adresses IPv4 du réseau autorisé. Les contrôles d’identité restent à configurer dans le service.

### Partage NFSv4

Catégorie : Données & stockage. Origine : classique.

Autoriser TCP 2049 depuis le réseau des clients.

Script complet : [examples/templates/nfs.nft](../examples/templates/nfs.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Clients autorisés (réseau IPv4) | `192.168.1.0/24` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Modèle NFSv4 uniquement. NFSv3 utilise aussi rpcbind et des ports RPC à fixer ; il n’est pas couvert.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Accès au service depuis les clients**

```nft
ip saddr 192.168.1.0/24 meta l4proto "tcp" tcp dport 2049 counter accept
```

Ouvre uniquement le port du service aux adresses IPv4 du réseau autorisé. Les contrôles d’identité restent à configurer dans le service.

### Supervision Prometheus / Grafana

Catégorie : Supervision. Origine : classique.

Séparer l’accès à node_exporter du réseau autorisé à consulter les tableaux de bord.

Script complet : [examples/templates/monitoring.nft](../examples/templates/monitoring.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Adresse du collecteur Prometheus | `192.168.1.20` |  |
| Clients autorisés (réseau IPv4) | `192.168.1.0/24` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- TCP 9100 est réservé au collecteur. TCP 9090 et 3000 sont ouverts aux clients indiqués. L’authentification des interfaces reste à configurer.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Collecte node_exporter**

```nft
ip saddr 192.168.1.20 meta l4proto "tcp" tcp dport 9100 counter accept
```

Réserve l’accès aux métriques système à l’adresse du collecteur.

**filter / input · 7 — Interfaces Prometheus et Grafana**

```nft
ip saddr 192.168.1.0/24 meta l4proto "tcp" tcp dport { 9090, 3000 } counter accept
```

Permet au réseau indiqué de consulter les interfaces d’administration ; prévoir leur authentification.

### Accès local via WireGuard

Catégorie : VPN. Origine : classique.

Recevoir le tunnel WireGuard et autoriser des services locaux aux clients du VPN.

Script complet : [examples/templates/wireguard.nft](../examples/templates/wireguard.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Interface du tunnel | `wg0` |  |
| Réseau IPv4 du VPN | `10.8.0.0/24` |  |
| Port UDP WireGuard | `51820` |  |
| Ports TCP accessibles dans le tunnel | `22,443` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Configurez les clés, peers et AllowedIPs dans WireGuard. Ce modèle dessert la machine VPN elle-même ; il ne route pas les clients vers Internet ou le LAN.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Établissement du VPN**

```nft
meta l4proto "udp" udp dport 51820 counter accept
```

Accepte le transport chiffré vers le service VPN. La vérification des clés/certificats est assurée par le VPN.

**filter / input · 7 — Services locaux via le VPN**

```nft
meta iifname "wg0" ip saddr 10.8.0.0/24 meta l4proto "tcp" tcp dport { 22, 443 } counter accept
```

Les deux critères se cumulent : arriver par le tunnel ET utiliser le réseau VPN attendu. Aucun accès aux machines derrière ce serveur n’est autorisé.

### Accès local via OpenVPN

Catégorie : VPN. Origine : classique.

Recevoir OpenVPN en UDP et ouvrir des services locaux dans le tunnel.

Script complet : [examples/templates/openvpn.nft](../examples/templates/openvpn.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Interface du tunnel | `tun0` |  |
| Réseau IPv4 du VPN | `10.9.0.0/24` |  |
| Port UDP OpenVPN | `1194` |  |
| Ports TCP accessibles dans le tunnel | `22,443` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Certificats, authentification et configuration du tunnel sont à préparer dans OpenVPN. Aucun routage des clients vers Internet n’est ajouté.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Établissement du VPN**

```nft
meta l4proto "udp" udp dport 1194 counter accept
```

Accepte le transport chiffré vers le service VPN. La vérification des clés/certificats est assurée par le VPN.

**filter / input · 7 — Services locaux via le VPN**

```nft
meta iifname "tun0" ip saddr 10.9.0.0/24 meta l4proto "tcp" tcp dport { 22, 443 } counter accept
```

Les deux critères se cumulent : arriver par le tunnel ET utiliser le réseau VPN attendu. Aucun accès aux machines derrière ce serveur n’est autorisé.

### Routeur LAN → Internet (masquerade)

Catégorie : Routage & NAT. Origine : classique.

Transférer le trafic IPv4 du LAN vers Internet et masquer son adresse source.

Script complet : [examples/templates/router-nat.nft](../examples/templates/router-nat.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Réseau local IPv4 | `192.168.10.0/24` |  |
| Interface du réseau local | `eth1` | Nom réel : consultez ip -br link. Un VLAN peut être nommé enp2s0.10. |
| Interface vers Internet | `eth0` |  |

Prérequis :

- Activer net.ipv4.ip_forward sur le routeur et définir les routes/passerelles. L’application ne modifie pas les sysctl.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Les nouvelles connexions WAN → LAN sont bloquées. Le transfert IPv6 reste bloqué ; aucune traduction IPv6 n’est ajoutée.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / forward · 1 — Transferts invalides**

```nft
ct state { "invalid" } counter drop
```

Rejette le trafic invalide qui traverse le routeur.

**filter / forward · 2 — Réponses aux transferts autorisés**

```nft
ct state { "established", "related" } counter accept
```

Autorise le trafic de retour et les échanges liés. Les nouvelles connexions nécessitent une règle suivante.

**filter / forward · 3 — LAN vers Internet**

```nft
meta iifname "eth1" meta oifname "eth0" ip saddr 192.168.10.0/24 counter accept
```

L’interface d’entrée, le réseau source et l’interface de sortie doivent tous correspondre. Les nouvelles connexions dans le sens inverse restent bloquées.

**nat / postrouting · 1 — Traduction de la source du LAN**

```nft
meta oifname "eth0" ip saddr 192.168.10.0/24 counter masquerade
```

Le NAT intervient après la décision de routage. Il traduit l’adresse mais n’autorise pas le passage à lui seul.

### Routeur avec adresse publique fixe (SNAT)

Catégorie : Routage & NAT. Origine : classique.

Traduire la source des sorties du LAN vers une IPv4 fixe.

Script complet : [examples/templates/router-snat.nft](../examples/templates/router-snat.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Réseau local IPv4 | `192.168.10.0/24` |  |
| Interface du réseau local | `eth1` | Nom réel : consultez ip -br link. Un VLAN peut être nommé enp2s0.10. |
| Interface vers Internet | `eth0` |  |
| IPv4 portée par l’interface WAN | `203.0.113.10` |  |

Prérequis :

- Activer le routage IPv4 et configurer l’adresse publique réelle sur le WAN.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- 203.0.113.10 est une adresse de documentation à remplacer. Pour une adresse WAN dynamique, choisir masquerade.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / forward · 1 — Transferts invalides**

```nft
ct state { "invalid" } counter drop
```

Rejette le trafic invalide qui traverse le routeur.

**filter / forward · 2 — Réponses aux transferts autorisés**

```nft
ct state { "established", "related" } counter accept
```

Autorise le trafic de retour et les échanges liés. Les nouvelles connexions nécessitent une règle suivante.

**filter / forward · 3 — LAN vers Internet**

```nft
meta iifname "eth1" meta oifname "eth0" ip saddr 192.168.10.0/24 counter accept
```

L’interface d’entrée, le réseau source et l’interface de sortie doivent tous correspondre. Les nouvelles connexions dans le sens inverse restent bloquées.

**nat / postrouting · 1 — Traduction de la source du LAN**

```nft
meta oifname "eth0" ip saddr 192.168.10.0/24 counter snat to 203.0.113.10
```

Le NAT intervient après la décision de routage. Il traduit l’adresse mais n’autorise pas le passage à lui seul.

### Publier un serveur interne (DNAT)

Catégorie : Routage & NAT. Origine : classique.

Rediriger un port TCP public vers un service du LAN et autoriser précisément ce transfert.

Script complet : [examples/templates/port-forward.nft](../examples/templates/port-forward.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Réseau local IPv4 | `192.168.10.0/24` |  |
| Interface du réseau local | `eth1` | Nom réel : consultez ip -br link. Un VLAN peut être nommé enp2s0.10. |
| Interface vers Internet | `eth0` |  |
| IPv4 publique visée | `203.0.113.10` |  |
| Port TCP public | `8443` |  |
| IPv4 du serveur interne | `192.168.10.10` |  |
| Port TCP du serveur interne | `443` |  |

Prérequis :

- Activer le routage IPv4. Le serveur interne doit renvoyer ses réponses via ce routeur.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- La règle forward voit l’adresse et le port APRÈS DNAT. Le modèle ne fournit ni hairpin NAT, ni accès Internet général au LAN.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / forward · 1 — Transferts invalides**

```nft
ct state { "invalid" } counter drop
```

Rejette le trafic invalide qui traverse le routeur.

**filter / forward · 2 — Réponses aux transferts autorisés**

```nft
ct state { "established", "related" } counter accept
```

Autorise le trafic de retour et les échanges liés. Les nouvelles connexions nécessitent une règle suivante.

**nat / prerouting · 1 — Redirection vers le serveur interne**

```nft
meta iifname "eth0" ip daddr 203.0.113.10 meta l4proto "tcp" tcp dport 8443 counter dnat to 192.168.10.10:443
```

Ne redirige que les paquets reçus du WAN à destination de l’IPv4 publique et du port spécifiés.

**filter / forward · 3 — Autoriser le flux redirigé**

```nft
meta iifname "eth0" meta oifname "eth1" ip daddr 192.168.10.10 meta l4proto "tcp" tcp dport 443 ct status "dnat" counter accept
```

Vérifie la destination traduite, le port interne et le statut DNAT, puis autorise le transfert WAN → LAN. Le serveur doit renvoyer ses réponses via cette passerelle.

### Filtrage entre deux VLAN

Catégorie : Routage & NAT. Origine : classique.

Autoriser un service TCP des clients vers les serveurs et bloquer les autres nouveaux transferts.

Script complet : [examples/templates/inter-vlan.nft](../examples/templates/inter-vlan.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Interface VLAN des clients | `eth1.110` |  |
| Réseau des clients | `192.168.110.0/24` |  |
| Interface VLAN des serveurs | `eth1.120` |  |
| Réseau des serveurs | `192.168.120.0/24` |  |
| Port TCP autorisé | `443` |  |

Prérequis :

- Créer les interfaces VLAN et les routes, activer le routage IPv4 ; aucun de ces réglages n’est effectué par le modèle.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Aucun NAT : les adresses source sont conservées. Les réponses sont acceptées par le suivi de connexion.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / forward · 1 — Transferts invalides**

```nft
ct state { "invalid" } counter drop
```

Rejette le trafic invalide qui traverse le routeur.

**filter / forward · 2 — Réponses aux transferts autorisés**

```nft
ct state { "established", "related" } counter accept
```

Autorise le trafic de retour et les échanges liés. Les nouvelles connexions nécessitent une règle suivante.

**filter / forward · 3 — Clients vers le service du VLAN serveurs**

```nft
meta iifname "eth1.110" meta oifname "eth1.120" ip saddr 192.168.110.0/24 ip daddr 192.168.120.0/24 meta l4proto "tcp" tcp dport 443 counter accept
```

Les réseaux et interfaces d’entrée/sortie limitent le chemin autorisé. Les autres nouveaux échanges entre VLAN sont refusés.

### Sorties limitées : web, DNS et NTP

Catégorie : Durcissement. Origine : classique.

Bloquer les nouvelles sorties sauf DNS vers un résolveur choisi, NTP et navigation web.

Script complet : [examples/templates/egress.nft](../examples/templates/egress.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Résolveur DNS IPv4 | `192.168.1.1` |  |
| Serveur NTP IPv4 | `192.168.1.1` |  |
| Interface du client DHCP | `eth0` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- ICMP/ICMPv6 et DHCP restent autorisés. HTTPS peut transporter du DNS chiffré : ce modèle ne garantit pas l’usage exclusif du résolveur choisi. QUIC et les autres ports sortants sont bloqués.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Réponses DHCPv4**

```nft
meta nfproto "ipv4" meta iifname "eth0" meta l4proto "udp" udp sport 67 udp dport 68 counter accept
```

Permet au client local de recevoir un bail, y compris lorsque la réponse est diffusée.

**filter / input · 7 — Réponses DHCPv6**

```nft
meta nfproto "ipv6" meta iifname "eth0" meta l4proto "udp" udp sport 547 udp dport 546 counter accept
```

Permet au client DHCPv6 de recevoir sa configuration sur l’interface choisie.

**filter / output · 1 — Sorties locales**

```nft
meta oifname "lo" counter accept
```

Permet aux applications de dialoguer sur la machine.

**filter / output · 2 — Sorties invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets sortants invalides.

**filter / output · 3 — Réponses sortantes**

```nft
ct state { "established", "related" } counter accept
```

Préserve les réponses des services entrants autorisés et les connexions déjà établies.

**filter / output · 4 — Contrôle réseau icmp**

```nft
meta l4proto "icmp" counter accept
```

Préserve les erreurs, le diagnostic et le fonctionnement IPv6.

**filter / output · 5 — Contrôle réseau ipv6-icmp**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve les erreurs, le diagnostic et le fonctionnement IPv6.

**filter / output · 6 — DNS vers le résolveur choisi — udp**

```nft
ip daddr 192.168.1.1 meta l4proto "udp" udp dport 53 counter accept
```

Limite les requêtes DNS classiques à une IPv4 précise. Ne bloque pas le DNS transporté dans HTTPS.

**filter / output · 7 — DNS vers le résolveur choisi — tcp**

```nft
ip daddr 192.168.1.1 meta l4proto "tcp" tcp dport 53 counter accept
```

Limite les requêtes DNS classiques à une IPv4 précise. Ne bloque pas le DNS transporté dans HTTPS.

**filter / output · 8 — Synchronisation horaire**

```nft
ip daddr 192.168.1.1 meta l4proto "udp" udp dport 123 counter accept
```

N’autorise NTP que vers l’adresse choisie.

**filter / output · 9 — Navigation HTTP / HTTPS**

```nft
meta l4proto "tcp" tcp dport { 80, 443 } counter accept
```

Ouvre TCP 80 et 443 vers toute destination IPv4 ou IPv6. Les autres ports sortants restent bloqués.

**filter / output · 10 — Requêtes DHCP ipv4**

```nft
meta nfproto "ipv4" meta oifname "eth0" meta l4proto "udp" udp sport 68 udp dport 67 counter accept
```

Permet de demander et renouveler une adresse sur l’interface choisie.

**filter / output · 11 — Requêtes DHCP ipv6**

```nft
meta nfproto "ipv6" meta oifname "eth0" meta l4proto "udp" udp sport 546 udp dport 547 counter accept
```

Permet de demander et renouveler une adresse sur l’interface choisie.

### Bloquer un ensemble d’adresses IPv4

Catégorie : Durcissement. Origine : classique.

Maintenir une liste de sources bloquées dans un ensemble réutilisable.

Script complet : [examples/templates/blocklist.nft](../examples/templates/blocklist.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Adresses ou réseaux à bloquer | `192.0.2.10/32,198.51.100.0/24` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Adresses d’exemple réservées à la documentation. Le blocage précède les connexions établies, concerne input uniquement et peut donc couper une session existante.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Sources bloquées**

```nft
ip saddr @"blocked_sources" counter drop
```

Placée avant established pour bloquer aussi le trafic entrant d’une session déjà ouverte. Les paquets sur lo restent acceptés.

**filter / input · 3 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 4 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 5 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 6 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

### Journaliser les refus sans saturer les logs

Catégorie : Supervision. Origine : classique.

Ajouter une journalisation limitée à la fin de la chaîne input.

Script complet : [examples/templates/logging.nft](../examples/templates/logging.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `non` |  |
| Réseau d’administration IPv4 | `192.168.1.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |

Prérequis :

- Le service concerné doit être installé, configuré et en écoute sur la machine.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Au maximum 5 messages par seconde, rafale de 10, globalement. La politique drop bloque aussi les paquets au-delà de la limite de journalisation.

Règles dans leur ordre au sein de chaque chaîne :

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Journal des paquets non autorisés**

```nft
limit rate 5/second burst 10 packets log prefix "nft-input-drop: " counter
```

Cette règle non terminale est placée après toutes les autorisations. Les paquets atteignent ensuite la politique drop, qu’ils aient été journalisés ou non.

### TP AIS — SSH et Samba entre segments

Catégorie : Formation AIS. Origine : formation.

Reprendre les exceptions de la maquette vers le serveur 192.168.20.10, avec les anciens ports NetBIOS en option.

Script complet : [examples/templates/studi-samba.nft](../examples/templates/studi-samba.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `oui` |  |
| Réseau d’administration IPv4 | `192.168.56.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Interface du segment d’administration | `enp0s10` |  |
| Interface du segment serveurs | `enp0s9` |  |
| Réseau des serveurs IPv4 | `192.168.20.0/24` |  |
| Serveur SSH / Samba | `192.168.20.10` |  |
| Ajouter les anciens ports NetBIOS | `non` | Désactivés par défaut ; les ports du relevé historique restent documentés. |

Prérequis :

- Appliquer ce modèle au routeur Linux de la maquette. Configurer les interfaces, les routes et net.ipv4.ip_forward avant les tests.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Reprise de forward, pas d’input : le serveur cible est une autre machine. TCP 22 et 445 sont conservés. Les anciens ports TCP 139 et UDP 137/138 sont désactivés par défaut, contrairement au relevé historique.

Règles dans leur ordre au sein de chaque chaîne :

**Extrait original de la formation**

```nft
iifname "enp0s10" oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.10 tcp dport 445 accept
```

Sur le routeur, forward traite le trafic de passage. Le paquet doit venir d’enp0s10 ET du réseau 192.168.56.0/24, sortir par enp0s9 ET viser 192.168.20.10 sur TCP 445. accept permet le partage SMB ; les autres destinations ne correspondent pas.

Adaptation : Même intention et mêmes limites, avec interfaces/adresses paramétrables et compteur ajouté. Les règles SSH et anciens ports NetBIOS du fichier sont séparées ; NetBIOS est facultatif.

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Administration SSH restreinte**

```nft
meta iifname "enp0s10" ip saddr 192.168.56.0/24 meta l4proto "tcp" tcp dport 22 counter accept
```

Seules les nouvelles connexions SSH provenant du réseau d’administration IPv4 sont admises.

**filter / forward · 1 — Transferts invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets invalides avant les règles métier.

**filter / forward · 2 — Réponses aux transferts autorisés**

```nft
ct state { "established", "related" } counter accept
```

Permet les réponses sans ouvrir toutes les nouvelles connexions dans le sens inverse.

**filter / forward · 3 — SSH vers le serveur Linux**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.10 meta l4proto "tcp" tcp dport 22 counter accept
```

Reprise du flux d’administration vers une seule machine du segment serveurs.

**filter / forward · 4 — Samba direct vers le serveur**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.10 meta l4proto "tcp" tcp dport 445 counter accept
```

TCP 445 transporte le partage SMB. Tous les critères du relevé sont conservés : interfaces, réseau source et adresse du serveur.

### TP AIS — accès au contrôleur Active Directory

Catégorie : Formation AIS. Origine : formation.

Reprendre les flux DNS, Kerberos, LDAP, SMB et RPC vers le contrôleur 192.168.20.25.

Script complet : [examples/templates/studi-ad.nft](../examples/templates/studi-ad.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `oui` |  |
| Réseau d’administration IPv4 | `192.168.56.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Interface du segment d’administration | `enp0s10` |  |
| Interface du segment serveurs | `enp0s9` |  |
| Réseau des serveurs IPv4 | `192.168.20.0/24` |  |
| Contrôleur de domaine IPv4 | `192.168.20.25` |  |
| Plage RPC dynamique configurée sur le DC | `49152-65535` |  |
| Ajouter les anciens ports NetBIOS | `non` | Désactivés par défaut ; les ports du relevé historique restent documentés. |
| Ajouter AD Web Services (TCP 9389) | `non` |  |

Prérequis :

- Appliquer ce modèle au routeur Linux de la maquette. Configurer les interfaces, les routes et net.ipv4.ip_forward avant les tests.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- La plage RPC est large mais limitée au DC choisi, au réseau client et aux interfaces. Ne la réduire que si le serveur a lui-même été configuré pour la nouvelle plage.
- Les ports LDAPS et catalogue global sont repris du TP ; à retirer s’ils ne sont pas utilisés. TCP 139 devient facultatif et TCP 9389 est une option supplémentaire, absente du relevé.
- Ce modèle vise les clients vers un DC. Il ne couvre pas automatiquement la réplication entre DC, les approbations ou tous les outils d’administration.

Règles dans leur ordre au sein de chaque chaîne :

**Extrait original de la formation**

```nft
iifname "enp0s10" oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 tcp dport { 53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269 } counter packets 27 bytes 1404 accept
iifname "enp0s10" oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 udp dport { 53, 88, 123, 389, 464 } accept
iifname "enp0s10" oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 tcp dport 49152-65535 accept
```

Les trois lignes ciblent un seul DC. La première réunit les services TCP, la seconde DNS/Kerberos/NTP/CLDAP en UDP, la troisième les ports négociés par RPC. Les valeurs 27 paquets / 1404 octets sont une mesure au moment du relevé, pas une limite.

Adaptation : Les ports sont répartis par service pour être lisibles. TCP 139 devient optionnel ; ADWS 9389 est une option nouvelle. Les compteurs historiques ne sont pas restaurés. La plage RPC reste configurable.

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Administration SSH restreinte**

```nft
meta iifname "enp0s10" ip saddr 192.168.56.0/24 meta l4proto "tcp" tcp dport 22 counter accept
```

Seules les nouvelles connexions SSH provenant du réseau d’administration IPv4 sont admises.

**filter / forward · 1 — Transferts invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets invalides avant les règles métier.

**filter / forward · 2 — Réponses aux transferts autorisés**

```nft
ct state { "established", "related" } counter accept
```

Permet les réponses sans ouvrir toutes les nouvelles connexions dans le sens inverse.

**filter / forward · 3 — DNS du domaine**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 meta l4proto "udp" udp dport 53 counter accept
```

Résolution des noms et des enregistrements de services du domaine.

**filter / forward · 4 — DNS du domaine — TCP**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 meta l4proto "tcp" tcp dport 53 counter accept
```

Complète UDP pour les réponses DNS nécessitant TCP.

**filter / forward · 5 — Kerberos et changement de mot de passe**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 meta l4proto "tcp" tcp dport { 88, 464 } counter accept
```

88 : authentification Kerberos ; 464 : changement de mot de passe Kerberos.

**filter / forward · 6 — Kerberos — UDP**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 meta l4proto "udp" udp dport { 88, 464 } counter accept
```

Conserve les transports UDP de Kerberos présents dans le relevé.

**filter / forward · 7 — Horloge et découverte LDAP**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 meta l4proto "udp" udp dport { 123, 389 } counter accept
```

123 : synchronisation horaire ; 389/UDP : découverte LDAP (CLDAP).

**filter / forward · 8 — Annuaire et catalogue global**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 meta l4proto "tcp" tcp dport { 389, 636, 3268, 3269 } counter accept
```

389 : LDAP ; 636 : LDAPS ; 3268/3269 : catalogue global, avec ou sans TLS. Ouvrir ces ports ne configure pas les certificats.

**filter / forward · 9 — SMB du domaine**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 meta l4proto "tcp" tcp dport 445 counter accept
```

Accès aux partages du domaine, notamment SYSVOL/NETLOGON.

**filter / forward · 10 — Point d’entrée RPC**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 meta l4proto "tcp" tcp dport 135 counter accept
```

Le mappeur RPC indique au client le port dynamique à contacter.

**filter / forward · 11 — Ports RPC dynamiques**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.25 meta l4proto "tcp" tcp dport 49152-65535 counter accept
```

Le port est choisi par le service RPC du contrôleur ; limiter la plage nécessite aussi de configurer le serveur.

### TP AIS — VPN vers des services du LAN

Catégorie : Formation AIS. Origine : formation.

Adapter le tunnel 10.10.10.0/24 vers le LAN 192.168.20.0/24 en limitant les services accessibles.

Script complet : [examples/templates/studi-wireguard.nft](../examples/templates/studi-wireguard.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `oui` |  |
| Réseau d’administration IPv4 | `192.168.56.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Interface du LAN | `enp0s9` |  |
| Réseau du LAN | `192.168.20.0/24` |  |
| Interface recevant le tunnel | `enp0s3` |  |
| Interface WireGuard | `wg0` |  |
| Réseau du VPN | `10.10.10.0/24` |  |
| Port UDP WireGuard | `51820` |  |
| Ports TCP autorisés VPN → LAN | `22,445` |  |

Prérequis :

- Appliquer ce modèle au routeur Linux de la maquette. Configurer les interfaces, les routes et net.ipv4.ip_forward avant les tests.
- Configurer les peers/AllowedIPs et la route de retour du LAN vers le réseau VPN.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Adaptation volontaire : les deux règles historiques autorisaient tous les protocoles dans les deux sens. Le modèle autorise de nouvelles connexions TCP seulement du VPN vers les ports choisis ; les réponses passent par established/related.
- Aucun NAT dans le tunnel, aucune ouverture LAN → VPN pour les nouvelles connexions.

Règles dans leur ordre au sein de chaque chaîne :

**Extrait original de la formation**

```nft
iifname "wg0" oifname "enp0s9" ip saddr 10.10.10.0/24 ip daddr 192.168.20.0/24 accept
iifname "enp0s9" oifname "wg0" ip saddr 192.168.20.0/24 ip daddr 10.10.10.0/24 accept
```

La première règle laisse entrer dans le LAN tout trafic routé venant du VPN. La seconde autorise aussi de nouvelles connexions initiées par le LAN vers le VPN. Ni le protocole ni les ports ne sont limités.

Adaptation : Le modèle conserve le chemin VPN → LAN mais exige TCP et les ports choisis. La règle inverse générale est retirée ; les réponses sont autorisées par established/related. Le port UDP du tunnel reste une règle input distincte.

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Administration SSH restreinte**

```nft
ip saddr 192.168.56.0/24 meta l4proto "tcp" tcp dport 22 counter accept
```

Seules les nouvelles connexions SSH provenant du réseau d’administration IPv4 sont admises.

**filter / forward · 1 — Transferts invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets invalides avant les règles métier.

**filter / forward · 2 — Réponses aux transferts autorisés**

```nft
ct state { "established", "related" } counter accept
```

Permet les réponses sans ouvrir toutes les nouvelles connexions dans le sens inverse.

**filter / input · 7 — Transport WireGuard**

```nft
meta iifname "enp0s3" meta l4proto "udp" udp dport 51820 counter accept
```

Le tunnel arrive sur le routeur lui-même : input. Les paquets déchiffrés à destination du LAN traversent ensuite forward.

**filter / forward · 3 — Services du LAN accessibles par le VPN**

```nft
meta iifname "wg0" meta oifname "enp0s9" ip saddr 10.10.10.0/24 ip daddr 192.168.20.0/24 meta l4proto "tcp" tcp dport { 22, 445 } counter accept
```

Remplace les ouvertures historiques tous protocoles / deux sens par un accès TCP ciblé VPN → LAN. Les réponses sont gérées plus haut.

### TP AIS — deux segments vers DNS et le web

Catégorie : Formation AIS. Origine : formation.

Reprendre les sorties DNS, HTTP et HTTPS des réseaux 192.168.56.0/24 et 192.168.20.0/24, avec masquerade.

Script complet : [examples/templates/studi-internet.nft](../examples/templates/studi-internet.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `oui` |  |
| Réseau d’administration IPv4 | `192.168.56.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Interface du segment d’administration | `enp0s10` |  |
| Interface du segment serveurs | `enp0s9` |  |
| Réseau des serveurs IPv4 | `192.168.20.0/24` |  |
| Interface vers Internet | `enp0s3` |  |

Prérequis :

- Appliquer ce modèle au routeur Linux de la maquette. Configurer les interfaces, les routes et net.ipv4.ip_forward avant les tests.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- UDP 53 et TCP 53/80/443 sont ouverts vers toute destination Internet, comme dans le TP. NTP, QUIC et les autres nouveaux transferts restent bloqués.
- Les deux segments ne peuvent pas initier de communications entre eux dans ce modèle. Le routeur lui-même conserve une politique output accept.

Règles dans leur ordre au sein de chaque chaîne :

**Extrait original de la formation**

```nft
iifname "enp0s9" oifname "enp0s3" ip saddr 192.168.20.0/24 udp dport 53 accept
iifname "enp0s9" oifname "enp0s3" ip saddr 192.168.20.0/24 tcp dport { 53, 80, 443 } accept
oifname "enp0s3" ip saddr 192.168.20.0/24 masquerade
```

Les deux premières lignes, dans forward, ouvrent DNS et le web du LAN vers le WAN. La troisième, dans postrouting de type nat, remplace la source par l’IPv4 du WAN. Le fichier contient le même ensemble pour 192.168.56.0/24.

Adaptation : Les deux segments et les ports sont conservés et paramétrés. Les ouvertures inter-segments et VPN du ruleset complet ne font pas partie de ce modèle centré sur les sorties Internet.

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Administration SSH restreinte**

```nft
meta iifname "enp0s10" ip saddr 192.168.56.0/24 meta l4proto "tcp" tcp dport 22 counter accept
```

Seules les nouvelles connexions SSH provenant du réseau d’administration IPv4 sont admises.

**filter / forward · 1 — Transferts invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets invalides avant les règles métier.

**filter / forward · 2 — Réponses aux transferts autorisés**

```nft
ct state { "established", "related" } counter accept
```

Permet les réponses sans ouvrir toutes les nouvelles connexions dans le sens inverse.

**filter / forward · 3 — DNS UDP du segment administration**

```nft
meta iifname "enp0s10" meta oifname "enp0s3" ip saddr 192.168.56.0/24 meta l4proto "udp" udp dport 53 counter accept
```

Reprend l’accès DNS sortant du TP, sans contraindre l’adresse du résolveur.

**filter / forward · 4 — DNS TCP et web du segment administration**

```nft
meta iifname "enp0s10" meta oifname "enp0s3" ip saddr 192.168.56.0/24 meta l4proto "tcp" tcp dport { 53, 80, 443 } counter accept
```

53 : DNS via TCP ; 80 : HTTP ; 443 : HTTPS. Aucun autre nouveau flux de ce segment vers Internet n’est ouvert.

**nat / postrouting · 1 — Masquerade du segment administration**

```nft
meta oifname "enp0s3" ip saddr 192.168.56.0/24 counter masquerade
```

Conserve les deux réseaux internes distincts et remplace leur adresse source uniquement à la sortie WAN.

**filter / forward · 5 — DNS UDP du segment serveurs**

```nft
meta iifname "enp0s9" meta oifname "enp0s3" ip saddr 192.168.20.0/24 meta l4proto "udp" udp dport 53 counter accept
```

Reprend l’accès DNS sortant du TP, sans contraindre l’adresse du résolveur.

**filter / forward · 6 — DNS TCP et web du segment serveurs**

```nft
meta iifname "enp0s9" meta oifname "enp0s3" ip saddr 192.168.20.0/24 meta l4proto "tcp" tcp dport { 53, 80, 443 } counter accept
```

53 : DNS via TCP ; 80 : HTTP ; 443 : HTTPS. Aucun autre nouveau flux de ce segment vers Internet n’est ouvert.

**nat / postrouting · 2 — Masquerade du segment serveurs**

```nft
meta oifname "enp0s3" ip saddr 192.168.20.0/24 counter masquerade
```

Conserve les deux réseaux internes distincts et remplace leur adresse source uniquement à la sortie WAN.

### TP AIS — serveur Linux SSH / SMB

Catégorie : Formation AIS. Origine : formation.

Traduire les autorisations UFW du serveur en règles nftables natives : SSH et SMB depuis le réseau d’administration.

Script complet : [examples/templates/studi-server.nft](../examples/templates/studi-server.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `oui` |  |
| Réseau d’administration IPv4 | `192.168.56.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |

Prérequis :

- Appliquer sur le serveur Linux qui héberge SSH/Samba, pas sur le routeur. Préparer explicitement le remplacement de la gestion UFW si elle est active.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- TCP 445 est autorisé depuis 192.168.56.0/24. SSH est activé par défaut mais reste facultatif. Aucun ancien port NetBIOS n’est ajouté.
- Le document source est une synthèse, pas une sauvegarde complète. Le modèle n’est donc pas une copie à l’identique de l’état UFW.

Règles dans leur ordre au sein de chaque chaîne :

**Extrait original de la formation**

```nft
ip saddr 192.168.56.0/24 tcp dport 22 accept
ip saddr 192.168.56.0/24 tcp dport 445 accept
```

Ces expressions sont citées dans une synthèse de ufw-user-input. Elles autorisent SSH et SMB vers le serveur lui-même depuis le segment d’administration. Ce ne sont pas des règles de transfert vers une autre machine.

Adaptation : Reconstruction dans une table inet native, avec le socle loopback/suivi de connexion/ICMP. Il ne s’agit pas d’une conversion exhaustive de toutes les chaînes UFW.

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Administration SSH restreinte**

```nft
ip saddr 192.168.56.0/24 meta l4proto "tcp" tcp dport 22 counter accept
```

Seules les nouvelles connexions SSH provenant du réseau d’administration IPv4 sont admises.

**filter / input · 7 — SMB depuis le réseau d’administration**

```nft
ip saddr 192.168.56.0/24 meta l4proto "tcp" tcp dport 445 counter accept
```

Traduit l’autorisation ufw-user-input du relevé en nftables natif. Cette règle s’exécute sur le serveur qui héberge le partage.

### TP AIS — diagnostic ICMP limité entre segments

Catégorie : Formation AIS. Origine : formation.

Reprendre les pings du réseau d’administration vers un serveur déterminé, avec limite de débit.

Script complet : [examples/templates/studi-ping.nft](../examples/templates/studi-ping.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `oui` |  |
| Réseau d’administration IPv4 | `192.168.56.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Interface du segment d’administration | `enp0s10` |  |
| Interface du segment serveurs | `enp0s9` |  |
| Réseau des serveurs IPv4 | `192.168.20.0/24` |  |
| Serveur à diagnostiquer | `192.168.20.10` |  |

Prérequis :

- Appliquer ce modèle au routeur Linux de la maquette. Configurer les interfaces, les routes et net.ipv4.ip_forward avant les tests.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Le TP autorisait deux destinations (192.168.20.10 et .25). Le modèle cible une adresse choisie ; dupliquer la règle pour une autre cible.
- Limite de 10 requêtes ICMP par seconde, rafale de 5, partagée par la règle. Le contrôle de débit est placé avant established : les pings suivants d’un même échange ne contournent pas la limite.

Règles dans leur ordre au sein de chaque chaîne :

**Extrait original de la formation**

```nft
iifname "enp0s10" oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr { 192.168.20.10, 192.168.20.25 } ip protocol icmp icmp type echo-request limit rate 10/second burst 5 packets counter packets 3 bytes 228 accept comment "diagnostic ICMP depuis le segment d administration"
```

La règle vise les demandes de ping vers deux machines. limit n’autorise que les paquets sous le quota global de la règle ; les autres continuent vers le refus par défaut. Dans le fichier, established/related est placé avant : les paquets d’un échange déjà établi peuvent donc ne plus atteindre cette limite.

Adaptation : La destination devient un champ. Une règle limit rate over … drop est placée AVANT established/related, suivie d’une autorisation des requêtes restantes. Les compteurs 3/228 sont réinitialisés.

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Administration SSH restreinte**

```nft
meta iifname "enp0s10" ip saddr 192.168.56.0/24 meta l4proto "tcp" tcp dport 22 counter accept
```

Seules les nouvelles connexions SSH provenant du réseau d’administration IPv4 sont admises.

**filter / forward · 1 — Transferts invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets invalides avant les règles métier.

**filter / forward · 2 — Excès de requêtes ICMP**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.10 meta l4proto "icmp" icmp type "echo-request" limit rate over 10/second burst 5 packets counter drop
```

Bloque l’excès avant established pour que tous les pings du même échange soient soumis à la limite, pas seulement le premier paquet.

**filter / forward · 3 — Réponses aux transferts autorisés**

```nft
ct state { "established", "related" } counter accept
```

Permet les réponses sans ouvrir toutes les nouvelles connexions dans le sens inverse.

**filter / forward · 4 — Ping vers le serveur choisi**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.10 meta l4proto "icmp" icmp type "echo-request" counter accept
```

Autorise les requêtes non rejetées par la limite placée avant established. Les réponses sont couvertes par le suivi de connexion.

### TP AIS — routeur initial à deux segments

Catégorie : Formation AIS. Origine : formation.

Comprendre le routage large du fichier avant durcissement et les deux règles de masquerade.

Script complet : [examples/templates/studi-router.nft](../examples/templates/studi-router.nft)

Paramètres proposés :

| Paramètre | Exemple | Précision |
| --- | --- | --- |
| Autoriser l’administration SSH | `oui` |  |
| Réseau d’administration IPv4 | `192.168.56.0/24` | Utilisez votre IP suivie de /32 pour un seul poste. Ne concerne que SSH. |
| Port SSH | `22` |  |
| Interface du segment d’administration | `enp0s10` |  |
| Interface du segment serveurs | `enp0s9` |  |
| Réseau des serveurs IPv4 | `192.168.20.0/24` |  |
| Interface vers Internet | `enp0s3` |  |

Prérequis :

- Appliquer ce modèle au routeur Linux de la maquette. Configurer les interfaces, les routes et net.ipv4.ip_forward avant les tests.

Portée et limites :

- Le modèle remplace tout le brouillon. Une application remplace ensuite tout le ruleset, y compris les règles d’autres logiciels (Docker, libvirt, UFW…).
- Les adresses et interfaces proposées sont des exemples à adapter. Aucune détection automatique du réseau n’est effectuée.
- Sauf indication contraire, les sorties sont autorisées, les nouveaux transferts sont bloqués et ICMP/ICMPv6 est autorisé pour le fonctionnement réseau. Les services limités à un réseau IPv4 ne sont pas ouverts en IPv6.
- Profil pédagogique permissif : tous les nouveaux protocoles sont autorisés du segment d’administration vers le LAN et des deux segments vers Internet. Préférer les profils Samba/AD/sorties limitées pour restreindre les usages.
- Adaptations au relevé : iif/oif deviennent iifname/oifname, invalid est rejeté, ICMPv6 est conservé et les compteurs démarrent à zéro.

Règles dans leur ordre au sein de chaque chaîne :

**Extrait original de la formation**

```nft
iif "enp0s10" oif "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.0/24 accept
iif "enp0s9" oif "enp0s3" ip saddr 192.168.20.0/24 accept
iif "enp0s10" oif "enp0s3" ip saddr 192.168.56.0/24 accept
```

Ces trois règles autorisent tous les protocoles dans les chemins indiqués. La politique forward drop bloque les autres chemins, mais ne rend pas ces trois autorisations plus restrictives. Le ruleset contient deux masquerade pour les sorties des deux réseaux.

Adaptation : Profil pédagogique volontairement large, clairement signalé. Les noms d’interfaces sont comparés avec iifname/oifname, le suivi invalide est rejeté et ICMPv6 reste fonctionnel. Les autres modèles de formation décomposent le durcissement.

**filter / input · 1 — Boucle locale**

```nft
meta iifname "lo" counter accept
```

Préserve les communications entre applications de cette machine.

**filter / input · 2 — Paquets invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets que le suivi de connexion ne sait pas associer correctement.

**filter / input · 3 — Connexions établies et liées**

```nft
ct state { "established", "related" } counter accept
```

Laisse entrer les réponses aux connexions sortantes et le trafic lié, sans ouvrir un nouveau service.

**filter / input · 4 — ICMP IPv4**

```nft
meta l4proto "icmp" counter accept
```

Autorise les diagnostics et les messages d’erreur IPv4, notamment ceux utiles à la découverte du MTU.

**filter / input · 5 — ICMP IPv6**

```nft
meta l4proto "ipv6-icmp" counter accept
```

Préserve la découverte de voisins/routeurs, les erreurs et les diagnostics IPv6. Ce choix autorise tous les types ICMPv6.

**filter / input · 6 — Administration SSH restreinte**

```nft
meta iifname "enp0s10" ip saddr 192.168.56.0/24 meta l4proto "tcp" tcp dport 22 counter accept
```

Seules les nouvelles connexions SSH provenant du réseau d’administration IPv4 sont admises.

**filter / forward · 1 — Transferts invalides**

```nft
ct state { "invalid" } counter drop
```

Écarte les paquets invalides avant les règles métier.

**filter / forward · 2 — Réponses aux transferts autorisés**

```nft
ct state { "established", "related" } counter accept
```

Permet les réponses sans ouvrir toutes les nouvelles connexions dans le sens inverse.

**filter / forward · 3 — Administration vers le LAN — tous protocoles**

```nft
meta iifname "enp0s10" meta oifname "enp0s9" ip saddr 192.168.56.0/24 ip daddr 192.168.20.0/24 counter accept
```

Reprise de la règle large du fichier avant durcissement. Aucun port ni protocole n’est limité ; les profils Samba et AD permettent de la remplacer par des exceptions précises.

**filter / forward · 4 — Sorties du segment administration**

```nft
meta iifname "enp0s10" meta oifname "enp0s3" ip saddr 192.168.56.0/24 counter accept
```

Reprise de l’état avant durcissement : tout trafic IPv4 du segment vers le WAN est autorisé.

**nat / postrouting · 1 — Masquerade du segment administration**

```nft
meta oifname "enp0s3" ip saddr 192.168.56.0/24 counter masquerade
```

Conserve les deux réseaux internes distincts et remplace leur adresse source uniquement à la sortie WAN.

**filter / forward · 5 — Sorties du segment serveurs**

```nft
meta iifname "enp0s9" meta oifname "enp0s3" ip saddr 192.168.20.0/24 counter accept
```

Reprise de l’état avant durcissement : tout trafic IPv4 du segment vers le WAN est autorisé.

**nat / postrouting · 2 — Masquerade du segment serveurs**

```nft
meta oifname "enp0s3" ip saddr 192.168.20.0/24 counter masquerade
```

Conserve les deux réseaux internes distincts et remplace leur adresse source uniquement à la sortie WAN.
