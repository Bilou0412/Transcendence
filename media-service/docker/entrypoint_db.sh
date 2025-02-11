#!/bin/bash
set -e  # Arrêter le script en cas d'erreur

# Vérifier que les variables d'environnement sont bien définies
: "${MEDIA_DB_NAME:?Erreur: MEDIA_DB_NAME non défini}"
: "${MEDIA_DB_USER:?Erreur: MEDIA_DB_USER non défini}"
: "${MEDIA_DB_PASSWORD:?Erreur: MEDIA_DB_PASSWORD non défini}"

# Définir les variables PostgreSQL
export POSTGRES_DB="$MEDIA_DB_NAME"
export POSTGRES_USER="$MEDIA_DB_USER"
export POSTGRES_PASSWORD="$MEDIA_DB_PASSWORD"

# Lancer PostgreSQL
exec docker-entrypoint.sh postgres
