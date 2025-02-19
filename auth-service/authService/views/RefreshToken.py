from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings

@api_view(['POST'])
@permission_classes([AllowAny])
def Refresh(request):
    """
    View to refresh an access token using a refresh token.
    """
    refresh_token = request.COOKIES.get('refresh_token')

    if not refresh_token:
        return Response(
            {"detail": "Refresh token is required"}, 
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        refresh = RefreshToken(refresh_token)
        access_token = str(refresh.access_token)

        response = Response(status=status.HTTP_200_OK)
        response.set_cookie(
            'access_token',
            access_token,
            max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(),
            secure=True,
            httponly=True,
            samesite='Strict'
        )
        return response
        # return Response({"access": access_token}, status=status.HTTP_200_OK)
        
    except Exception:
        return Response(
            {"detail": "Invalid or expired refresh token"}, 
            status=status.HTTP_401_UNAUTHORIZED
        )