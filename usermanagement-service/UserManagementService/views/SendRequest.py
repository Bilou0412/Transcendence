from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from ..models import UserProfile, Friendship
from ..decorators import authorize_user
from django.db.models import Q  # Assure-toi que ton décorateur est bien importé
import requests

@api_view(['POST'])
@authorize_user  # Appliquer le décorateur pour l'authentification
def SendRequest(request):
    """
    Envoie une demande d'amitié à un autre utilisateur.
    Si l'utilisateur ou l'ami n'existe pas, leurs profils seront créés automatiquement.
    """
    data = request.data
    print(data)
    required_fields = ['friend_id']
    missing_fields = [field for field in required_fields if field not in data]

    if missing_fields:
        return Response({
            "error": f"Missing required fields: {', '.join(missing_fields)}"
        }, status=status.HTTP_400_BAD_REQUEST)

    friend_id = data['friend_id']
    user_id = request.id  # Récupère l'ID utilisateur à partir de la requête

    try:
        # Récupérer ou créer les profils utilisateur
        user_profile, _ = UserProfile.objects.get_or_create(user_id=user_id)
        friend_profile, _ = UserProfile.objects.get_or_create(user_id=friend_id)

        # Vérifier si une demande d'amitié existe déjà
        existing_friendship = Friendship.objects.filter(
            (Q(user_1=user_profile) & Q(user_2=friend_profile)) |
            (Q(user_1=friend_profile) & Q(user_2=user_profile))
        ).first()

        if existing_friendship:
            if existing_friendship.status == 'pending':
                return Response({
                    "error": "A friendship request is already pending."
                }, status=status.HTTP_400_BAD_REQUEST)
            elif existing_friendship.status == 'accepted':
                return Response({
                    "error": "You are already friends."
                }, status=status.HTTP_400_BAD_REQUEST)
            elif existing_friendship.status == 'blocked':
                return Response({
                    "error": "You have been blocked by this user."
                }, status=status.HTTP_400_BAD_REQUEST)

        # Créer une nouvelle demande d'amitié
        friendship = Friendship.objects.create(
            user_1=user_profile,
            user_2=friend_profile,
            status='pending'
        )

        return Response({
            "message": "Friendship request sent successfully.",
            "friendship": str(friendship)
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({
            "error": f"An unexpected error occurred: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
