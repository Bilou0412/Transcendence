#!/bin/bash
set -e  # Arrêter le script en cas d'erreur

# Vérifier que les variables d'environnement sont bien définies
: "${AUTH_DB_NAME:?Erreur: AUTH_DB_NAME non défini}"
: "${AUTH_DB_USER:?Erreur: AUTH_DB_USER non défini}"
: "${AUTH_DB_PASSWORD:?Erreur: AUTH_DB_PASSWORD non défini}"

# Définir les variables PostgreSQL
export POSTGRES_DB="$AUTH_DB_NAME"
export POSTGRES_USER="$AUTH_DB_USER"
export POSTGRES_PASSWORD="$AUTH_DB_PASSWORD"

# Lancer PostgreSQL
exec docker-entrypoint.sh postgres
