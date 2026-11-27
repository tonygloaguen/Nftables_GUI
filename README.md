# Nftables GUI — éditeur graphique local

Backend local FastAPI/Pydantic v2 pour Python **3.11+**. Le mode **file** est le
défaut ; il stocke les règles dans un fichier privé et vérifie leur syntaxe avec
`nft -c -f` dans un espace réseau isolé. L'écoute par défaut est
**127.0.0.1:8420**. L'interface graphique est servie directement par FastAPI,
sans compilation JavaScript, CDN ni serveur frontend supplémentaire.

## Lancement rapide

Depuis une copie du dépôt :

```bash
cd Nftables_GUI
bash lancer.sh
```

Après extraction de l’archive, entrer dans le dossier extrait puis exécuter
également `bash lancer.sh`. Le lanceur fonctionne quel que soit son emplacement.

Le lanceur utilise le dossier où il se trouve, crée `.venv` s'il manque et
installe les dépendances déclarées si nécessaire. La première installation
demande un accès réseau. Il ne demande aucun privilège root et ne modifie pas
le pare-feu. Ouvrir ensuite <http://127.0.0.1:8420>.

## Utiliser l'interface

1. **Modèles expliqués** : catalogue de 31 configurations avec recherche et
   catégories (poste, SSH, web, DNS/DHCP/NTP, bases de données, partages,
   supervision, VPN, routage/NAT, VLAN, filtrage sortant, blocage et journaux).
   Chaque fiche présente les prérequis, paramètres, sources, politiques et règles
   décomposées expression par expression. L'aperçu se met à jour avec les valeurs
   saisies. **Créer le brouillon** remplace le brouillon et reste à vérifier.
   Sept modèles sont issus des preuves de la formation AIS : Samba entre segments,
   Active Directory, VPN routé, sorties Internet, serveur Linux, diagnostic ICMP et
   routeur initial. Les extraits d’origine et adaptations sont affichés dans les
   fiches. Voir [l’analyse des sources](docs/formation/analyse-regles.md) et
   [le catalogue complet](docs/modeles-expliques.md).
2. **Tables et chaînes** : choisir la famille IP, le hook, le type de chaîne,
   sa priorité et sa politique par défaut ; ajouter ou supprimer des chaînes.
3. **Ajouter une règle** : choisir l'action, le protocole, les adresses ou
   réseaux, les ports, les interfaces et les états de connexion. Compteurs,
   journalisation, sauts de chaîne, DNAT/SNAT et masquerade sont disponibles.
4. **Réordonner, dupliquer ou modifier** les règles. L'aperçu nftables suit les
   changements. Les modifications sont enregistrées dans ce navigateur comme
   brouillon ; le bouton Annuler permet de revenir aux modifications précédentes.
5. **Vérifier**, puis **Appliquer** : relire la configuration et choisir un
   délai. Vérifier l'accès réseau, puis cliquer sur **Confirmer** dans le bandeau.
   Un bouton permet de revenir immédiatement à la sauvegarde.

Les vues **Ensembles & objets**, **Éditeur de code**, **Sauvegardes** et
**Journal d'activité** complètent l'éditeur. Les imports acceptent les scripts
`.nft`, le JSON nftables et les exports IR. Pour sauvegarder un brouillon sans
nécessiter une validation système, exporter en **Brouillon visuel .json**.

Les configurations simples générées par l'éditeur peuvent être converties du
code vers les formulaires. Les règles avancées restent éditables en source ou
en expressions structurées. Les documents comprenant des constructions non
mappées ou des commentaires utilisateur restent intégralement en mode code.
Les grands entiers qui dépassent la précision de JavaScript sont refusés par
l'import visuel, afin d'éviter un arrondi silencieux ; utiliser la source `.nft`
ou l'API JSON directe pour ces données.

Une restauration depuis les sauvegardes crée elle-même une nouvelle sauvegarde
et une transaction temporaire : elle exige également une confirmation.

## Installation et démarrage

Sur Linux, prévoir `nftables`, `util-linux` (`unshare`), Python et son module
`venv`. Depuis le dossier du projet :

```bash
/usr/bin/python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m nft_gui
```

L'éditeur graphique est disponible sur <http://127.0.0.1:8420/>.
La documentation interactive est disponible sur <http://127.0.0.1:8420/docs> en
mode fichier sans jeton. L'import du paquet ne lance ni commande ni serveur.
Les tests ne nécessitent pas de privilège administrateur.

Après une modification du code, arrêter le serveur avec `Ctrl+C` dans son
terminal, puis relancer `.venv/bin/python -m nft_gui` et actualiser la page.

`unshare --user --map-root-user --net` doit être autorisé pour les validations du
mode fichier. Si les espaces de noms utilisateur sont désactivés, la validation
échoue explicitement et le fichier reste inchangé. Il n'existe pas de validation
fictive activée automatiquement quand `nft` ou les permissions manquent.

## Configuration

| Variable | Défaut | Usage |
| --- | --- | --- |
| `NFT_GUI_BACKEND` | `file` | `file`, `mock` (alias de `file`) ou `live` |
| `NFT_GUI_DATA_DIR` | `~/.local/share/nft-gui` | Chemin absolu, dédié à un seul backend |
| `NFT_GUI_HOST` | `127.0.0.1` | Adresse d'écoute |
| `NFT_GUI_PORT` | `8420` | Port HTTP |
| `NFT_GUI_API_TOKEN` | absent | Jeton Bearer, au moins 32 caractères |
| `NFT_GUI_PRIVILEGE` | `sudo` | `sudo` ou `pkexec`, uniquement en mode live |

Un jeton est obligatoire pour **live**, même sur localhost, et pour toute écoute
hors loopback. Une adresse explicite et un accès TLS protégé sont nécessaires
pour une utilisation distante. Le contrôle `Host` autorise localhost, les
adresses loopback et l'adresse configurée ; un déploiement derrière un autre nom
DNS demande d'adapter explicitement cette liste.

Quand un jeton est configuré, l'interface affiche un formulaire de connexion.
Le jeton reste en mémoire, sans enregistrement dans le stockage du navigateur.
Seuls la coque HTML, ses fichiers statiques et `/session` sont publics ; aucune
règle ou information de transaction n'y est exposée. Le jeton protège les
lectures, `/docs` et `/openapi.json`. L'interface envoie
`Authorization: Bearer …` sur ses requêtes API. Les origines différentes,
les requêtes navigateur `cross-site` et les mutations sans `application/json`
sont rejetées. Aucun CORS ouvert n'est installé.

## API

| Méthode et route | Fonction |
| --- | --- |
| `GET /` | Interface graphique |
| `GET /templates` | Catalogue pédagogique et références |
| `POST /templates/{id}/preview` | Construire un IR et son explication, sans commande système |
| `GET /session` | Indique si une authentification est nécessaire |
| `GET /health` | Mode d'exécution |
| `GET /ruleset` | État actif en live, source du bac à sable en file |
| `POST /parse/json` | JSON `nft -j list ruleset` vers IR |
| `POST /parse/text` | Source `.nft` vers IR, avec repli texte sans perte |
| `POST /parse/ir` | Validation du format de brouillon visuel |
| `POST /generate` | IR vers aperçu `.nft` ; aperçu non encore validé |
| `POST /validate` | Validation réelle et hash SHA-256 du script préparé |
| `POST /transactions` | Validation, snapshot et application temporaire |
| `GET /transactions/pending` | Transaction courante, y compris après rechargement |
| `GET /transactions/{id}` | État de la transaction |
| `POST /transactions/{id}/confirm` | Confirmation avant expiration |
| `POST /transactions/{id}/rollback` | Restauration du snapshot |
| `POST /export` | Export `.nft` validé, JSON nft ou IR |
| `GET /snapshots` | Liste des sauvegardes récentes |
| `GET /snapshots/{id}` | Source d'une sauvegarde |
| `POST /snapshots/{id}/restore` | Restauration par nouvelle transaction temporaire |
| `GET /audit?limit=100` | Dernières opérations (maximum 200) |

Les routes validate, transactions et export acceptent **soit** `source`, **soit**
`ruleset`. La création de transaction accepte aussi `confirm_seconds`, entre 15
et 300 secondes, par défaut 60. Exemple en mode fichier :

```bash
curl --fail-with-body http://127.0.0.1:8420/validate \
  -H 'Content-Type: application/json' \
  -d '{"source":"table inet demo { chain forward { type filter hook forward priority 0; policy drop; } }"}'

curl --fail-with-body http://127.0.0.1:8420/transactions \
  -H 'Content-Type: application/json' \
  -d '{"source":"table inet demo { chain forward { type filter hook forward priority 0; policy drop; } }","confirm_seconds":60}'

# Remplacer IDENTIFIANT par la valeur id retournée.
curl --fail-with-body http://127.0.0.1:8420/transactions/IDENTIFIANT/confirm \
  -H 'Content-Type: application/json' -d '{}'
```

`expires_at` est une date Unix en secondes UTC. Les erreurs nft renvoient le
`stderr` original et, lorsque présents, `line`, `column` et `end_column`. Les
positions portent sur le script `source` préparé : une ligne `flush ruleset`
est ajoutée au début lorsqu'elle manque. La validation d'une source invalide ne
modifie jamais le bac à sable.

## Modèles et conservation des données

L'IR utilise une liste ordonnée d'objets discriminés par `kind` : `Table`, `Chain`,
`Rule`, `Set`, `Map`, `Counter`, `Quota`, ainsi que `OpaqueObject`. Les relations
utilisent les clés `family`, `table` et `chain`. Les expressions sont des objets
`Expr`. La validation Pydantic est stricte et refuse les attributs IR inconnus.

- Le JSON nft inconnu est conservé dans `unsupported_expr`, `extra_fields` ou
  `nft_object`. L'ordre, les valeurs et les champs présents sont conservés lors
  d'un aller-retour JSON nft → IR → JSON nft, même après sérialisation de l'IR.
- Une expression texte inconnue est conservée dans `raw_nft`. Pour les fichiers
  contenant des commentaires, macros ou déclarations non mappées par le parseur
  texte, le **document entier** reste en mode code, avec sa source exacte.
- Le parseur texte offre une conversion visuelle prudente des tables, chaînes,
  ensembles, maps, compteurs, quotas, matches simples, verdicts, logs et NAT
  générés par l'éditeur. Une expression non reconnue reste en `raw_nft` ; une
  déclaration inconnue conserve tout le document en mode code.
- Le générateur couvre notamment les chaînes `forward`, les ensembles, maps,
  compteurs, quotas, verdicts, matches payload/meta/ct, références nommées, logs
  simples et masquerade/redirect. Les champs non pris en charge bloquent la
  génération, au lieu de produire un pare-feu incomplet.
- Un document `raw_nft` édité ne peut pas produire un JSON nft prétendument
  équivalent : ce format d'export est refusé. La source ou l'IR restent exportables.

Le générateur déclare les chaînes avant les verdict maps et les objets avant
les règles, puis conserve l'ordre des règles dans chaque chaîne. Les handles
du noyau sont conservés dans le JSON de sauvegarde, mais seront réattribués par
le noyau lors d'une restauration.

## Exécution et transactions

`NftExecutor` est la seule frontière de création de processus. Les arguments
sont toujours des listes, sans shell, avec un timeout de **10 secondes** et des
chemins exécutables absolus. Les scripts temporaires ont les permissions `0600`,
dans un répertoire `0700`, et sont supprimés après usage. La vérification et
l'application portent sur le **même fichier temporaire**.

En live, seules les formes suivantes sont implémentées, préfixées par
`sudo -n -- /usr/sbin/nft` ou `pkexec --disable-internal-agent /usr/sbin/nft` :

```text
-j list ruleset
-c -f <fichier temporaire contrôlé>
-f <même fichier temporaire>
```

La remise à zéro est une instruction `flush ruleset` dans le batch validé. Il
n'existe pas d'endpoint de flush immédiat qui contournerait snapshot et délai de
confirmation. Les includes, macros, consultations, commandes interactives et
fichiers JSON utilisés comme scripts sont refusés à la frontière d'exécution.
Les scripts admis sont autonomes : déclarations de tables, règles et éventuel
`flush ruleset` initial.

Chaque transaction suit cet ordre :

1. Verrou interprocessus ; refus si une autre transaction est encore ouverte.
2. Validation de la nouvelle configuration.
3. Lecture de l'état précédent et validation de sa restauration.
4. Snapshot horodaté JSON + `.nft`, écrit atomiquement en `0600`.
5. État de transaction persistant, puis démarrage et acquittement d'un processus
   de surveillance indépendant du serveur HTTP.
6. Nouvelle validation sur le fichier exact, puis remplacement en un batch nft.
7. Confirmation avant expiration, ou restauration automatique et validée.

Le watchdog survit à la fermeture du serveur API. Le délai utilise l'horloge
monotone et l'heure persistée ; un changement de boot déclenche une restauration
à la reprise. L'application reprend les transactions inachevées au démarrage.
La surveillance vérifie l'expiration toutes les secondes ; une commande déjà
en cours peut ajouter son timeout au délai de restauration.

Un échec de rollback reste visible et bloque les nouvelles applications ; le
watchdog réessaie. Un snapshot altéré ou un état corrompu est refusé. L'échec du
journal d'audit bloque une nouvelle application ou confirmation, mais ne doit
pas empêcher une restauration urgente.

Le journal `audit.jsonl` contient timestamp UTC, action, statut, hash SHA-256,
identifiant de transaction et détail d'erreur. Les lectures, validations,
applications, confirmations, rollbacks et exports sont tracés. Aucune règle ni
aucun jeton n'est ajouté au journal par défaut ; les diagnostics nft peuvent
contenir la ligne fautive.

## Activation live et limites d'exploitation

Le code fourni n'active pas le mode live et n'installe aucune règle sudo/polkit.
Prévoir un compte de service dédié et des autorisations administrateur limitées
aux formes de commandes ci-dessus. Ne pas lancer FastAPI en root ni accorder
`NOPASSWD: ALL`. Le compte autorisé à charger un ruleset possède, par définition,
le contrôle du pare-feu ; la liste blanche applicative ne remplace pas une
politique système adaptée.

Utiliser un répertoire distinct, par exemple `/var/lib/nft-gui`, préparé pour le
compte de service. Le mode live exige `NFT_GUI_BACKEND=live` et un jeton. Avec
pkexec, une politique non interactive est nécessaire ; l'absence d'autorisation
est une erreur, pas une demande de mot de passe depuis HTTP.

Le backend remplace **tout le ruleset**. Il suppose qu'aucun autre gestionnaire
(Docker, firewalld, autre administrateur) ne le modifie pendant la transaction.
Un état actif contenant des objets non sérialisables en `.nft` bloque toute
application live, puisque sa restauration ne pourrait pas être garantie.

Le watchdog protège contre la disparition de l'API, pas contre la destruction de
tous les processus, du disque ou de la machine. Pour une exploitation système,
il faut superviser la reprise du service et ne pas tuer le watchdog avec le
groupe de processus de l'API. Après un redémarrage machine, la reprise s'effectue
au démarrage du backend ; elle n'a pas lieu pendant son arrêt. Les exceptions
du watchdog sont visibles dans l'état persistant et l'audit ; ses flux standard
sont détachés de ceux du serveur.

## Vérification

```bash
.venv/bin/python -m pytest -m 'not integration'
.venv/bin/python -m mypy
.venv/bin/python -m ruff check .

# Tests des fonctions de l'éditeur, sans dépendance npm (Node.js facultatif) :
node tests/test_frontend.js
node --check nft_gui/api/static/app.js

# Vérification supplémentaire avec le véritable nft, dans un réseau isolé :
NFT_GUI_INTEGRATION=1 .venv/bin/python -m pytest -m integration
```

Les tests unitaires injectent un exécuteur déterministe. Deux tests démarrent un
véritable processus de surveillance, avec un validateur de test inoffensif,
et vérifient aussi le cas où le processus applicatif se termine brutalement.
Les tests d'intégration sont explicites et n'appliquent aucune règle au réseau
hôte.

Validation effectuée le 27 novembre 2026 : **137 tests Python passés**, **25 tests
des fonctions JavaScript passés**, contrôle mypy strict et ruff réussis. Les tests
couvrent notamment la session protégée, les ressources de l'interface, le cycle
édition → vérification → application → confirmation → relecture visuelle,
ainsi que la restauration d'une sauvegarde et son annulation.

Dans l'environnement d'exécution de l'agent, les tests TestClient ont utilisé
une boucle asyncio avec réveil périodique pour compenser les notifications
interthreads bloquées par le sandbox. Cette adaptation concerne uniquement le
lancement des tests ; elle n'est pas intégrée à l'application. Les tests
JavaScript ont été exécutés avec GJS, également compatible avec leur module.

Le test d'intégration nft réel reste non exécuté : `unshare` est refusé dans cet
environnement. L'ouverture automatisée du navigateur a aussi été refusée ; le
rendu visuel et les clics en navigateur ne sont donc pas déclarés vérifiés.

## Organisation

| Module | Rôle |
| --- | --- |
| `nft_gui/models/` | IR Pydantic v2 |
| `nft_gui/parser/` | Import JSON et source texte conservatrice |
| `nft_gui/generator/` | Sérialisation `.nft` et expressions |
| `nft_gui/executor/` | Politique de source, validations et processus |
| `nft_gui/transactions/` | Snapshots, confirmations, rollback et watchdog |
| `nft_gui/api/` | FastAPI, authentification et protection des requêtes |
| `nft_gui/api/static/` | Interface HTML/CSS/JavaScript sans dépendance externe |
| `nft_gui/templates/` | Catalogue, validation des paramètres et génération des modèles expliqués |
| `docs/modeles-expliques.md` | Catalogue lisible avec règles et commentaires |
| `examples/templates/` | Scripts générés à partir des modèles (valeurs d’exemple) |
| `nft_gui/storage.py` | Écritures atomiques, verrous et audit |
| `tests/` | Tests de comportement, API, conversion et intégration isolée |

Références : [manuel nft officiel](https://www.netfilter.org/projects/nftables/manpage.html),
schéma `libnftables-json(5)` fourni avec nftables,
[FastAPI](https://fastapi.tiangolo.com/),
[Pydantic v2](https://docs.pydantic.dev/latest/).

## Contribution et CI

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour l’environnement de développement,
les tests et la préparation d’une PR, et [SECURITY.md](SECURITY.md) pour le
périmètre de sécurité. La CI GitHub utilise Ubuntu 26.04, des actions fixées par
SHA et les versions explicites Python 3.11.18/3.14.10 et Node.js 24.22.3.
Elle vérifie les tests Python, les tests et la
syntaxe JavaScript, la cohérence du catalogue généré et la distribution Python.
Deux jobs de sécurité indépendants exécutent Bandit sur le code Python et
pip-audit sur les dépendances directes et transitives. Les alertes Bandit de
gravité moyenne ou élevée et les vulnérabilités connues font échouer la CI.
Elle ne déploie rien et n’applique aucune règle au pare-feu hôte.
