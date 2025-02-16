from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from channels.layers import get_channel_layer
from django.core.cache import cache
import json
from asgiref.sync import async_to_sync


@api_view(['POST'])
def FriendRequest(request):
    try:
        data = request.data
        receiver_id = data.get('receiver_id')
        sender_id = data.get('sender_id')
        print(f"Friend request data: {data}")
        # Validation de la requête
        if not receiver_id or not sender_id:
            return Response({'error': 'Receiver ID and Sender ID are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier si le receiver est connecté
        connected_user_ids = cache.get('connected_user_ids', set())
        if receiver_id not in connected_user_ids:
            return Response({'message': 'Receiver is not connected'},  status=status.HTTP_200_OK)

        # Obtenir le layer de canal pour envoyer un message à la connexion WebSocket
        channel_layer = get_channel_layer()
        print(f"Sending friend request to user_{receiver_id}")

        # Envoie d'une demande via WebSocket (envoie un message au groupe WebSocket de l'utilisateur invité)
        async_to_sync(channel_layer.group_send)(
            f"user_{receiver_id}",  # Groupe spécifique à l'utilisateur
            {
                'type': 'friend_request',  # This type should match the handler in the consumer
                'receiver_id': receiver_id,
                'sender_id': sender_id,
            }
        )
        print(f"Friend request sent to user_{receiver_id} via WebSocket")
        return Response({'message': 'Friend request sent successfully!'}, status=status.HTTP_200_OK)
    except json.JSONDecodeError:
        return Response({'error': 'Invalid JSON format'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        print(f"Error sending friend request: {str(e)}")
        return Response({'error': f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
