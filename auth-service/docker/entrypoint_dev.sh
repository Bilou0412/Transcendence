#!/bin/sh
set -e  # Arrêter le script en cas d'erreur

# Fonction pour attendre que la base de données PostgreSQL soit prête
wait_for_db() {
    echo "📌 Attente de la base de données..."
    until pg_isready -h db-auth -p 5432; do
        sleep 1
    done
    echo "✅ Base de données prête."
}

# Attendre que la base de données soit opérationnelle
wait_for_db

# Exécuter les migrations Django
echo "🔄 Exécution des migrations..."
python manage.py makemigrations authService
python manage.py migrate

# Créer un superutilisateur si aucun n'existe
echo "👤 Vérification du superutilisateur..."
python manage.py shell << END
from django.contrib.auth import get_user_model

User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'admin')
    print("✅ Superutilisateur créé avec succès !")
else:
    print("ℹ️ Le superutilisateur existe déjà.")
END

# Lancer le serveur Django
echo "🚀 Démarrage du serveur Django..."
exec python manage.py runserver 0.0.0.0:8000
