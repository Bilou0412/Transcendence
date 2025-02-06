from rest_framework.decorators import api_view
from rest_framework.response import Response
from ..models import Friendship, UserProfile, BlockedUser
from ..decorators import authorize_user

@api_view(['GET'])
@authorize_user
def ListFriends(request):
    """
    Récupérer la liste des amis de l'utilisateur.
    - L'utilisateur voit tous ses amis, même ceux qu'il a bloqués.
    - Un utilisateur bloqué ne voit plus celui qui l'a bloqué.
    """
    try:
        user_profile = UserProfile.objects.get(user_id=request.id)

        # Liste des utilisateurs bloqués par cet utilisateur
        blocked_users = list(BlockedUser.objects.filter(blocker=user_profile).values_list('blocked', flat=True))

        # Liste des utilisateurs qui ont bloqué cet utilisateur
        blocked_by_users = list(BlockedUser.objects.filter(blocked=user_profile).values_list('blocker', flat=True))

        # Récupérer les amitiés de l'utilisateur
        friendships = Friendship.objects.filter(user_1=user_profile) | Friendship.objects.filter(user_2=user_profile)

        friends = []
        for friendship in friendships:
            if friendship.status == 'accepted':
                friend = friendship.user_1 if friendship.user_2 == user_profile else friendship.user_2
                
                # L'utilisateur bloqué ne voit plus celui qui l'a bloqué
                if friend.user_id not in blocked_by_users:
                    friends.append(friend.user_id)

        return Response({ "user_id": request.id, "friends": friends })

    except UserProfile.DoesNotExist:
        return Response({"message": "User not found"}, status=404)
