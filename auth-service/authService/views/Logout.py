from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken ,BlacklistedToken


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def Logout(request):
    try:
        # Obtenez le refresh token de la requête
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Obtenez l'objet OutstandingToken
        outstanding_token = OutstandingToken.objects.get(token=refresh_token)

        # Vérifiez si le token est déjà blacklisté
        if BlacklistedToken.objects.filter(token=outstanding_token).exists():
            return Response({"detail": "Token already blacklisted or invalid."}, status=status.HTTP_400_BAD_REQUEST)

        # Blacklistez le token
        BlacklistedToken.objects.create(token=outstanding_token)

        return Response({"detail": "Successfully logged out."}, status=status.HTTP_205_RESET_CONTENT)

    except OutstandingToken.DoesNotExist:
        return Response({"detail": "Token already blacklisted or invalid."}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"detail": "An error occurred during logout."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)