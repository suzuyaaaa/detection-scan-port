NetScan IDS
===========

Tests locaux
------------

Installer les dependances :

    pip install -r requirement.txt

Lancer les tests :

    pytest -q

Les tests utilisent la variable NETSCAN_SKIP_MODEL_LOAD=1 pour ne pas charger le
modele ML lourd pendant la verification. Cela permet de tester Flask, SQLite et
la logique IDS sans lancer de capture reseau reelle.

CI/CD
-----

Le fichier .github/workflows/ci.yml configure GitHub Actions.

A chaque push ou pull request vers main/master, GitHub :

1. recupere le code du depot ;
2. installe Python 3.11 ;
3. installe les dependances de requirement.txt ;
4. lance pytest -q ;
5. bloque la fusion si un test echoue.

Tests ajoutes
-------------

- creation de la base SQLite et des regles IDS par defaut ;
- chargement du dashboard Flask ;
- rejet d'une adresse IP invalide sans creer d'alerte ;
- creation d'une alerte Info quand aucune capture reseau n'est retournee ;
- detection d'un scan de ports avec les regles IDS ;
- filtrage des alertes par severite ;
- generation d'un rapport CSV et sauvegarde dans l'historique ;
- classification detaillee d'une alerte de type SYN Flood.
