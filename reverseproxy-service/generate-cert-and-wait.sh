#!/bin/bash

# Vérifie si le certificat SSL existe déjà, sinon le crée
if [ ! -f /etc/nginx/ssl/certificate.crt ]; then
    echo "Génération du certificat SSL auto-signé..."

    # Générer un certificat SSL auto-signé
    openssl req -x509 -newkey rsa:4096 -keyout /etc/nginx/ssl/private.key -out /etc/nginx/ssl/certificate.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Company/CN=xpongo.ddns.net"

    echo "Certificat SSL généré avec succès !"
else
    echo "Le certificat SSL existe déjà, pas besoin de le régénérer."
fi

echo "En attente des services..."
/wait-for-it.sh auth:8000 --timeout=60 --strict -- echo "Auth prêt"
/wait-for-it.sh chat:8000 --timeout=60 --strict -- echo "Chat prêt"
/wait-for-it.sh media:8000 --timeout=60 --strict -- echo "Media prêt"
/wait-for-it.sh remote:8000 --timeout=60 --strict -- echo "Remote prêt"
/wait-for-it.sh usermanagement:8000 --timeout=60 --strict -- echo "Usermanagement prêt"
/wait-for-it.sh wsmanagement:8000 --timeout=60 --strict -- echo "Wsmanagement prêt"

# Démarrer Nginx après que tous les services soient prêts
echo "Tous les services sont prêts, démarrage de Nginx..."
nginx -g "daemon off;"