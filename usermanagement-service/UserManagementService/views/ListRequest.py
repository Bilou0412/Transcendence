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
        friendships = Friendship.objects.filter(user_1=user_profile) | Friendship.objects.filter(user_2=user_profile)
        pending_requests = []
        for friendship in friendships:
            if friendship.status == 'pending':
                friend = friendship.user_1 if friendship.user_2 == user_profile else friendship.user_2
                pending_requests.append(friend.user_id)
                print(friend.user_id)
        return Response({ "user_id": request.id, "pending_requests": pending_requests })
    except UserProfile.DoesNotExist:
        return Response({"message": "User not found"}, status=404)