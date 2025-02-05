from rest_framework.decorators import api_view
from rest_framework.response import Response
from ..models import Friendship, UserProfile, BlockedUser
from ..decorators import authorize_user

@api_view(['GET'])
@authorize_user
def ListFriends(request):
    """
    Récupérer la liste des amis de l'utilisateur.
    """
    try:
        user_profile = UserProfile.objects.get(user_id=request.id)
        blocked_users = BlockedUser.objects.filter(blocker=user_profile).values_list('blocked', flat=True)
        friendships = Friendship.objects.filter(user_1=user_profile) | Friendship.objects.filter(user_2=user_profile)
        friends = []
        for friendship in friendships:
            if friendship.status == 'accepted':
                friend = friendship.user_1 if friendship.user_2 == user_profile else friendship.user_2
                if friend.user_id not in blocked_users:
                    friends.append(friend.user_id)
        return Response({ "user_id": request.id, "friends": friends })
    except UserProfile.DoesNotExist:
        return Response({"message": "User not found"}, status=404)