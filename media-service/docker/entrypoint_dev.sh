#!/bin/sh

# Fonction pour attendre que la base de données soit prête
wait_for_db() {
    echo "Attente de la base de données..."
    until pg_isready -h ${DB_HOST} -p 5432; do
        sleep 1
    done
    echo "Base de données prête."
}

# Attendre que la base de données soit opérationnelle
wait_for_db

# # Exécute les migrations
echo "Exécution des migrations..."
python manage.py makemigrations media
python manage.py migrate

# Crée un superutilisateur si aucun n'existe
echo "Création du superutilisateur..."
python manage.py shell << END
from django.contrib.auth import get_user_model

User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'admin')
    print("Superutilisateur créé avec succès !")
else:
    print("Le superutilisateur existe déjà.")
END

# Démarre le serveur de développement
echo "Démarrage du serveur de développement..."
exec python manage.py runserver 0.0.0.0:8000