from django.conf import settings
from functools import wraps
from rest_framework.response import Response
from rest_framework import status
import requests

def authorize_user(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        # Extraction du token (supporte 'Bearer token' ou juste 'token')
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '') if auth_header else ''

        if not token:
            return Response({
                'error': 'No authorization token provided'
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            # Validation du token avec le service d'auth
            response = requests.post(
                'http://auth:8000/auth/token/validate/',
                headers={'Authorization': f'Bearer {token}'},
                timeout=5  # Timeout de 5 secondes
            )

            if response.status_code != 200:
                return Response({
                    'error': 'Invalid or expired token',
                    'status': response.status_code
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Le token est valide, on récupère l'ID utilisateur
            user_data = response.json()
            request.id = user_data['id']
            
            # Appel de la vue protégée
            return view_func(request, *args, **kwargs)

        except requests.exceptions.RequestException as e:
            # En cas d'erreur de connexion avec le service d'auth
            return Response({
                'error': 'Authentication service unavailable',
                'details': str(e)
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

    return wrapped_view

def authorize_remote_service(func):
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        # Vérifie la clé d'API dans les en-têtes
        api_key = request.headers.get("X-API-KEY")
        if api_key != settings.REMOTE_SERVICE_API_KEY:
            return Response({
                "error": "Unauthorized: Invalid API key"
            }, status=status.HTTP_401_UNAUTHORIZED)
        return func(request, *args, **kwargs)
    return wrapper
