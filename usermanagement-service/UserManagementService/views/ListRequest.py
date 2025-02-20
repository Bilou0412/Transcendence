from rest_framework.decorators import api_view
from rest_framework.response import Response
from ..models import Friendship, UserProfile
from ..decorators import authorize_user

@api_view(['GET'])
@authorize_user
def ListRequest(request):
    """
    Récupérer la liste des demandes d'amis en attente de l'utilisateur.
    """
    try:
        user_profile = UserProfile.objects.get(user_id=request.id)
        friendships = Friendship.objects.filter(user_2=user_profile, status='pending')
        pending_requests = [friendship.user_1.user_id for friendship in friendships]
        return Response({ "user_id": request.id, "pending_requests": pending_requests })
    except UserProfile.DoesNotExist:
        return Response({"message": "User not found"}, status=200)