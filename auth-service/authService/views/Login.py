from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
import pyotp
from ..responseGenCookie import ResponseCookie
# from django.conf import settings


@api_view(['POST'])
@permission_classes([AllowAny])
def Login(request):
    """
    View to obtain JWT token pair for a user.
    """
    email = request.data.get('email')
    password = request.data.get('password')
    otp_code = request.data.get('otp')

    if not email or not password:
        return Response(
            {"detail": "Both email and password are required"},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Use the built-in Django authentication function
    user = authenticate(request, username=email, password=password)

    if not user:
        return Response(
            {"detail": "Invalid credentials"},
            status=status.HTTP_401_UNAUTHORIZED
        )

    if not user.is_active:
        return Response(
            {"detail": "This account is inactive"},
            status=status.HTTP_403_FORBIDDEN
        )

    if user.otp_secret:  # Si l'utilisateur a configuré la 2FA
        if not otp_code:
            return Response(
                {"detail": "OTP code is required for this account"},
                status=status.HTTP_400_BAD_REQUEST
            )

        totp = pyotp.TOTP(user.otp_secret)
        if not totp.verify(otp_code):  # Vérification du code OTP
            return Response(
                {"detail": "Invalid OTP code"},
                status=status.HTTP_401_UNAUTHORIZED
            )

    # Generate JWT tokens
    refresh = RefreshToken.for_user(user)

    # Set the JWT tokens in HTTP-only cookies
    # response = Response(
    #     {
    #         "user": {
    #             "id": user.id,
    #             "username": user.username,
    #             "email": user.email,
    #         }
    #     }, status=status.HTTP_200_OK
    # )
    
    # response.set_cookie(
    #     'access_token',
    #     str(refresh.access_token),
    #     max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(),
    #     secure=True,
    #     httponly=True,
    #     samesite='Strict'
    # )
    # response.set_cookie(
    #     'refresh_token',
    #     str(refresh),
    #     max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds(),
    #     secure=True,
    #     httponly=True,
    #     samesite='Strict'
    # )
    return ResponseCookie(refresh, user, status.HTTP_200_OK)
