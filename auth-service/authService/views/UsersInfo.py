from ..models import User
from ..serializers import UserInfoSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import api_view ,permission_classes
from rest_framework import status

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def UsersInfo(request):
    """
    Récupère les informations des utilisateurs en fonction de leurs IDs.
    """
    # Récupérer les `user_ids` du corps de la requête
    print("use infos in")
    user_ids = request.data.get('user_ids', [])
    
    if not user_ids:
        return Response({"detail": "No user_ids provided"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Filtrer les utilisateurs en fonction des IDs fournis
    users = User.objects.filter(id__in=user_ids)
    
    if not users.exists():
        return Response({"detail": "No users found with the provided IDs"}, status=status.HTTP_404_NOT_FOUND)
    
    # Sérialiser les utilisateurs
    serializer = UserInfoSerializer(users, many=True)

    user_data = {str(user['id']): user for user in serializer.data}
    
    # Add 2fa information
    for user in user_data.values():
        user_instance = users.get(id=user['id'])
        user['2fa'] = bool(user_instance.otp_secret)
    
    return Response(user_data, status=status.HTTP_200_OK)