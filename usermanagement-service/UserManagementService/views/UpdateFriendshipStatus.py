from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from ..models import UserProfile, Friendship
from ..decorators import authorize_user
import requests
from django.db.models import Q  # Assure-toi que ton décorateur est bien importé


@api_view(['POST'])
@authorize_user  # Appliquer le décorateur pour l'authentification
def UpdateFriendshipStatus(request):
    """
    Met à jour le statut d'une demande d'amitié (acceptée, refusée ou bloquée).
    """
    data = request.data
    required_fields = ['friend_id', 'status']
    missing_fields = [field for field in required_fields if field not in data]

    if missing_fields:
        return Response({
            "error": f"Missing required fields: {', '.join(missing_fields)}"
        }, status=status.HTTP_400_BAD_REQUEST)

    friend_id = data['friend_id']
    status_choice = data['status']
    user_id = request.id  # L'ID de l'utilisateur est extrait du token

    # Vérifier si le statut est valide
    if status_choice not in ['accepted', 'refused']:
        return Response({
            "error": "Invalid status. Choose from 'accepted', 'refused'."
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Récupérer les profils des utilisateurs
        user_profile = UserProfile.objects.get(user_id=user_id)
        friend_profile = UserProfile.objects.get(user_id=friend_id)

        # Vérifier si une demande d'amitié est en attente
        friendship = Friendship.objects.filter(
            (Q(user_1=user_profile) & Q(user_2=friend_profile)) |
            (Q(user_1=friend_profile) & Q(user_2=user_profile))
        ).first()

        if not friendship:
            return Response({
                "error": "No pending friendship request found."
            }, status=status.HTTP_400_BAD_REQUEST)

        wsmanagement_url = 'http://wsmanagement:8000/friend-request/'  # Correct URL
        wsmanagement_data = {
            'receiver_id': friend_id,
            'sender_id': user_id
        }
        try:
            response = requests.post(wsmanagement_url, json=wsmanagement_data)
            response.raise_for_status()
        except requests.RequestException as e:
            return Response({
                "error": f"Failed to notify the receiver via WebSocket: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Mettre à jour le statut de la demande d'amitié
        if status_choice == 'refused':
            friendship.delete()
            return Response({
                "message": "Friendship request refused and deleted successfully."
            }, status=status.HTTP_200_OK)
        else:
            friendship.status = status_choice
            friendship.save()

        return Response({
            "message": f"Friendship request {status_choice} successfully.",
            "friendship": str(friendship)
        }, status=status.HTTP_200_OK)

    except UserProfile.DoesNotExist:
        return Response({
            "error": "User or friend not found."
        }, status=status.HTTP_404_NOT_FOUND)
