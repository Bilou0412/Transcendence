#!/bin/bash
set -e  # Arrêter le script en cas d'erreur

# Vérifier que les variables d'environnement sont bien définies
: "${USERMANAGEMENT_DB_NAME:?Erreur: USERMANAGEMENT_DB_NAME non défini}"
: "${USERMANAGEMENT_DB_USER:?Erreur: USERMANAGEMENT_DB_USER non défini}"
: "${USERMANAGEMENT_DB_PASSWORD:?Erreur: USERMANAGEMENT_DB_PASSWORD non défini}"

# Définir les variables PostgreSQL
export POSTGRES_DB="$USERMANAGEMENT_DB_NAME"
export POSTGRES_USER="$USERMANAGEMENT_DB_USER"
export POSTGRES_PASSWORD="$USERMANAGEMENT_DB_PASSWORD"

# Lancer PostgreSQL
exec docker-entrypoint.sh postgres
