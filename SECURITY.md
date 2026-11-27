# Sécurité

Nftables GUI est un outil d’administration locale en développement. Il ne doit pas être exposé directement sur Internet.

## Garanties attendues des changements

- Écoute sur `127.0.0.1:8420` et backend fichier par défaut.
- Jeton obligatoire pour le mode live ou une écoute hors loopback.
- Commandes système confinées à `NftExecutor`, sans shell et avec délai maximal.
- Vérification `nft -c` avant application, snapshot préalable et retour arrière armé.
- Conservation des constructions non reconnues, sans suppression silencieuse.

Les tests unitaires ne constituent pas une certification de sécurité et ne valident pas la connectivité d’un déploiement réel. Les tests noyau et le parcours navigateur doivent être vérifiés dans un environnement adapté avant d’utiliser une nouvelle version en mode live.

## Contrôles automatiques

La CI exécute Bandit sur le code Python et `pip-audit` sur les dépendances installées. Bandit bloque les alertes de gravité moyenne ou élevée ; `pip-audit` bloque les vulnérabilités connues et les erreurs de collecte. Ces résultats ne couvrent pas les vulnérabilités encore inconnues et ne remplacent pas la revue du code système.

## Signaler un problème

Contacter le propriétaire du dépôt par un canal privé déjà établi. Si GitHub affiche **Security → Report a vulnerability** sur ce dépôt, utiliser ce formulaire privé. Ne pas joindre de règles de production, secrets ou preuves d’exploitation dans une issue publique. Aucun délai de correction garanti n’est annoncé pour ce projet.
