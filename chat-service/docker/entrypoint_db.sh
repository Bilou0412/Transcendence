#!/bin/bash
set -e  # Arrêter le script en cas d'erreur

# Vérifier que les variables d'environnement sont bien définies
: "${CHAT_DB_NAME:?Erreur: CHAT_DB_NAME non défini}"
: "${CHAT_DB_USER:?Erreur: CHAT_DB_USER non défini}"
: "${CHAT_DB_PASSWORD:?Erreur: CHAT_DB_PASSWORD non défini}"

# Définir les variables PostgreSQL
export POSTGRES_DB="$CHAT_DB_NAME"
export POSTGRES_USER="$CHAT_DB_USER"
export POSTGRES_PASSWORD="$CHAT_DB_PASSWORD"

# Lancer PostgreSQL
exec docker-entrypoint.sh postgres
