# Utiliser une image de base Python
FROM python:3.11-slim

# Installer le client PostgreSQL
RUN apt-get update && apt-get install -y postgresql-client && apt-get clean


# Définir le répertoire de travail
WORKDIR /app

# Copier le fichier requirements.txt
COPY requirements.txt .

# Installer les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copier le reste des fichiers de l'application
COPY . .

# Exposer le port de l'application
EXPOSE 8000
