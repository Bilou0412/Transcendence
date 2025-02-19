from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.tokens import AccessToken
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import User

class JWTCookieAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Read the token from cookies
		print(f"token: {token}")
        token = request.COOKIES.get('access_token')
        if token:
            try:
                # Verify the token and get the user
                validated_token = AccessToken(token)
                user_id = validated_token.payload.get('user_id')
                request.user = User.objects.get(id=user_id)
            except Exception:
                request.user = AnonymousUser()
        else:
            request.user = AnonymousUser()