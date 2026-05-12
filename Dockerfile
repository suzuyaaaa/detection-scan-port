# ─────────────────────────────────────────────
# NetScan IDS — Dockerfile
# ─────────────────────────────────────────────

# Image de base Python légère
FROM python:3.10-slim

# Métadonnées
LABEL maintainer="NetScan IDS"
LABEL description="Système de Détection d'Intrusion réseau intelligent"
LABEL version="2.0"

# Définir le répertoire de travail
WORKDIR /app

# Installer les dépendances système nécessaires pour Scapy
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    nmap \
    net-tools \
    iputils-ping \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copier d'abord le fichier de dependances (optimise le cache Docker)
COPY requirement.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirement.txt

# Copier tout le code source
COPY . .

# Créer le dossier pour la base de données SQLite
RUN mkdir -p /app/data

# Variable d'environnement pour Flask
ENV FLASK_APP=webapp.app
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Exposer le port Flask
EXPOSE 5000

# Healthcheck — vérifie que Flask répond
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000')" || exit 1

# Commande de démarrage
CMD ["python", "-m", "webapp.app"]
