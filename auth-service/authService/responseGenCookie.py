from django.conf import settings
from rest_framework.response import Response

def ResponseCookie(tokens, user, responseStatus):
    response = Response(
        {
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            }
        }, status=responseStatus
    )
    
    response.set_cookie(
        'access_token',
        str(tokens.access_token),
        max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(),
        secure=True,
        httponly=True,
        samesite='Strict'
    )
    response.set_cookie(
        'refresh_token',
        str(tokens),
        max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds(),
        secure=True,
        httponly=True,
        samesite='Strict'
    )
    return response