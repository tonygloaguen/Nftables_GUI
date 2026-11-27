# Contribuer à Nftables GUI

Le projet est une application Linux locale. Le développement et les tests utilisent le backend fichier ; les tests unitaires injectent un exécuteur contrôlé et n’agissent pas sur le pare-feu hôte.

## Installer l’environnement

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip 'setuptools>=84.1' wheel
.venv/bin/python -m pip install -e '.[dev,security]'
```

Node.js 24 est utilisé dans la CI pour les vérifications JavaScript. L’interface n’a aucune dépendance npm et ne nécessite pas de compilation pour fonctionner.

## Vérifier une modification

```bash
.venv/bin/python -m pytest -m 'not integration'
.venv/bin/python -m mypy
.venv/bin/python -m ruff check .
.venv/bin/python -m bandit -r nft_gui scripts --severity-level medium
mkdir -p .local
.venv/bin/python -m pip freeze --all --exclude nft-gui-backend > .local/requirements-audit.txt
.venv/bin/python -m pip_audit -r .local/requirements-audit.txt --no-deps --disable-pip --strict --progress-spinner off --timeout 30
npm test
npm run check
.venv/bin/python -m build
```

Bandit analyse le backend et les scripts Python ; les alertes de gravité moyenne ou élevée font échouer ce contrôle. Les fixtures de test ne sont pas analysées. `pip-audit` contrôle les dépendances installées, directes et transitives, y compris celles de développement et de sécurité. Un export `pip freeze --all` fige les versions effectivement installées pour l’audit. Seul le projet local `nft-gui-backend`, absent de PyPI, en est exclu ; ses dépendances restent analysées. Les options `--no-deps --disable-pip` évitent une nouvelle résolution de cet export complet. Toute vulnérabilité connue ou erreur de collecte fait échouer le contrôle. L’audit nécessite l’accès réseau à PyPI ; cet export temporaire ne constitue pas un fichier de verrouillage des installations futures.

Les deux contrôles s’exécutent dans des jobs distincts sur chaque push et pull request, ainsi qu’au lancement manuel de la CI. Ils ne corrigent pas automatiquement le code ou les dépendances. Ne pas ajouter d’exclusion de vulnérabilité ni désactiver une règle Bandit sans une justification précise dans la PR.

Si un modèle change, régénérer le catalogue et les exemples avant le commit :

```bash
.venv/bin/python scripts/export_templates.py
git diff -- docs/modeles-expliques.md examples/templates
```

Les modèles doivent conserver les expressions non reconnues, préciser les hypothèses réseau et distinguer les règles d’origine de leurs adaptations. Une prévisualisation ne vaut jamais validation par `nft`.

## Tests d’intégration nftables

À exécuter explicitement sur un poste Linux permettant les espaces de noms utilisateur et réseau, avec `nftables` et `unshare` installés :

```bash
NFT_GUI_INTEGRATION=1 .venv/bin/python -m pytest -m integration
```

Ce test lance `nft -c -f` dans un espace réseau isolé. Ne pas remplacer cette isolation par une validation ou une application sur le réseau hôte. La CI normale n’exécute pas ce test et n’applique aucune règle réelle.

## Préparer une pull request

Créer une branche à partir de `main`, limiter les changements à un objectif et utiliser le modèle de PR fourni. Décrire le comportement obtenu, les vérifications réellement réalisées et les limites restantes. Pour une modification de l’interface, joindre une capture du bac à sable lorsque le rendu a été vérifié.

Ne pas committer `.venv`, les fichiers `.env`, des jetons, des clés, les snapshots du pare-feu réel ou les journaux d’exécution. Le répertoire `.local/` sert aux métadonnées privées propres au poste et est ignoré par Git.

## Licence

Aucune licence de redistribution n’est définie pour cette version. Le choix d’une licence appartient au propriétaire du projet ; la préparation du dépôt n’en attribue pas automatiquement une.
