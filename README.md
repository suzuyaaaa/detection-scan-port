# 🛡️ NetScan IDS — Système de Détection d'Intrusion Réseau

![Python](https://img.shields.io/badge/Python-3.10-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.x-lightgrey?style=flat-square&logo=flask)
![Scapy](https://img.shields.io/badge/Scapy-2.5-green?style=flat-square)
![ML](https://img.shields.io/badge/ML-scikit--learn-orange?style=flat-square&logo=scikit-learn)
![Docker](https://img.shields.io/badge/Docker-ready-blue?style=flat-square&logo=docker)
![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-black?style=flat-square&logo=github-actions)

---

## 📌 Description

**NetScan IDS** est un système de détection d'intrusion réseau intelligent développé en Python.
Il est capable de détecter des scans réseau (comme Nmap) en combinant :

- 🔍 **Règles IDS classiques** — seuils configurables sur le trafic TCP
- 🤖 **Machine Learning** — modèle entraîné sur le dataset UNSW-NB15
- 📡 **Capture temps réel** — analyse du trafic réseau avec Scapy
- 🌐 **Interface web** — tableau de bord Flask avec stockage SQLite

---

## 🏗️ Architecture du Projet
NetScan-IDS/
│
├── app.py                        # Application Flask principale
├── requirements.txt              # Dépendances Python
├── Dockerfile                    # Containerisation Docker
├── docker-compose.yml            # Orchestration Docker
├── test_scan.py                  # Tests automatiques
│
├── network/
│   ├── capture_traffic.py        # Capture paquets avec Scapy
│   ├── simulate_attack.py        # Simulation scan Nmap
│   └── live_ids.py               # IDS temps réel
│
├── ml/
│   ├── model.pkl                 # Modèle ML entraîné
│   └── encoders.pkl              # Encodeurs des features
│
├── templates/
│   ├── base.html                 # Template de base
│   ├── dashboard.html            # Tableau de bord
│   ├── alertes.html              # Gestion des alertes
│   ├── detail_alerte.html        # Détail d'une alerte
│   ├── historique.html           # Historique des scans
│   ├── regles.html               # Configuration des règles
│   └── rapports.html             # Génération de rapports
│
├── static/
│   └── js/
│       └── script.js
│
└── .github/
└── workflows/
└── ci.yml                # Pipeline CI/CD

---

## ⚙️ Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| 📡 Capture réseau | Analyse du trafic TCP en temps réel avec Scapy |
| 🔍 Détection IDS | Règles configurables (PORT_SCAN, SYN, RATE, TCP, UDP...) |
| 🤖 Détection ML | Modèle Random Forest entraîné sur UNSW-NB15 |
| 🚨 Alertes | Classifiées en Critique / Moyen / Info |
| 📊 Dashboard | Graphiques d'activité réseau en temps réel |
| 📁 Historique | Trace complète de toutes les analyses |
| 📄 Rapports | Export CSV par période et par type |
| 🛡️ Règles IDS | Ajout / modification / suppression des règles |
| 🐳 Docker | Déploiement containerisé |
| ⚙️ CI/CD | Pipeline GitHub Actions automatisé |

---

## 🚀 Installation et Lancement

### Méthode 1 — Lancement direct Python

```bash
# 1. Cloner le projet
git clone https://github.com/ton-username/netscan-ids.git
cd netscan-ids

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer l'application (nécessite les droits root pour Scapy)
sudo python app.py
```

L'interface est accessible sur : **http://localhost:5000**

---

### Méthode 2 — Lancement avec Docker (recommandé)

```bash
# 1. Builder l'image
docker build -t netscan-ids .

# 2. Lancer le container
docker run --network host --cap-add NET_ADMIN --cap-add NET_RAW -p 5000:5000 netscan-ids
```

---

### Méthode 3 — Docker Compose (le plus simple)

```bash
# Lancer
docker-compose up --build

# Arrêter
docker-compose down

# Voir les logs
docker-compose logs -f
```

---

## 🧪 Tests

```bash
# Lancer tous les tests
pytest test_scan.py -v

# Avec rapport de couverture
pytest test_scan.py -v --cov=app --cov-report=term-missing
```

Les tests couvrent :
- ✅ Accessibilité de toutes les pages
- ✅ APIs JSON
- ✅ Base de données SQLite
- ✅ Validation des adresses IP
- ✅ Gestion des règles IDS

---

## ⚙️ CI/CD — GitHub Actions

Le pipeline s'exécute automatiquement à chaque `git push` :
git push
│
├── 1. 🔍 Lint          → vérification syntaxe Python
├── 2. 🧪 Tests         → tests automatiques
├── 3. 📁 Structure     → vérification des fichiers
├── 4. 🐳 Docker Build  → construction image Docker
└── 5. ✅ Résumé        → rapport final

---

## 🖥️ Scénario Réseau Réel

Le système a été testé sur un réseau local avec 3 machines :

| Machine | Rôle | IP |
|---|---|---|
| PC 1 | Attaquant (Nmap) | 192.168.1.x |
| PC 2 | Victime surveillée | 192.168.1.x |
| PC 3 | Serveur NetScan IDS | 192.168.1.x |

**Déroulement du test :**
1. PC 3 lance NetScan IDS
2. PC 1 lance un scan Nmap sur PC 2 : `nmap -sS -p 1-1000 192.168.1.x`
3. NetScan IDS détecte le scan en temps réel
4. Une alerte Critique est générée automatiquement

---

## 🔍 Types de Scans Détectés

| Type | Description | Sévérité |
|---|---|---|
| SYN Stealth Scan | Scan furtif TCP SYN (Nmap -sS) | 🔴 Critique |
| Port Scan | Balayage de ports TCP/UDP | 🔴 Critique |
| SYN Flood | Attaque par déni de service | 🔴 Critique |
| Comportement suspect | Détecté par ML uniquement | 🟡 Moyen |
| Trafic normal | Aucune menace détectée | 🟢 Info |

---

## 🛠️ Technologies Utilisées

| Technologie | Usage |
|---|---|
| Python 3.10 | Langage principal |
| Flask | Interface web |
| Scapy | Capture réseau |
| scikit-learn | Modèle Machine Learning |
| SQLite | Base de données |
| Bootstrap 5 | Interface utilisateur |
| Chart.js | Graphiques |
| Docker | Containerisation |
| GitHub Actions | CI/CD |

---

## 👨‍💻 Auteur

Projet réalisé dans le cadre d'un module de **Sécurité Réseau**.