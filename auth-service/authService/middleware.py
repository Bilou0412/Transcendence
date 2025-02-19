# from django.contrib.auth.models import AnonymousUser
# from rest_framework_simplejwt.tokens import AccessToken
# from django.utils.deprecation import MiddlewareMixin
# from .models import User

# class JWTCookieAuthenticationMiddleware(MiddlewareMixin):
#     def process_request(self, request):
#         # Read the token from cookies
#         token = request.COOKIES.get('access_token')
#         print(f"Token: {token}")
#         if token:
#             try:
#                 # Verify the token and get the user
#                 validated_token = AccessToken(token)
#                 user_id = validated_token.payload.get('user_id')
#                 print(f"User ID: {user_id}")
#                 request.user = User.objects.get(id=user_id)
#                 print(f"Authenticated User: {request.user}")
#             except Exception as e:
#                 print(f"Invalid token: {e}")
#                 request.user = AnonymousUser()
#         else:
#             print("No token found")
#             request.user = AnonymousUser()

# Custom JWT Authentication class
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.utils import get_user_id_from_payload_handler, get_user_from_payload
from rest_framework.authentication import BaseAuthentication
from django.utils.translation import gettext_lazy as _

class JWTAuthenticationFromCookiesMiddleware(BaseAuthentication):
    """
    An authentication plugin that authenticates requests through a JSON web
    token provided in a cookie.
    """

    www_authenticate_realm = 'api'

    def authenticate(self, request):
        raw_token = request.COOKIES.get('access_token')
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)

        return self.get_user(validated_token), validated_token

    def authenticate_header(self, request):
        return '{} realm="{}"'.format(api_settings.AUTH_HEADER_TYPES[0], self.www_authenticate_realm)

    def get_raw_token_from_cookie(self, request):
        """
        Extracts an unvalidated JSON web token from the given cookie.
        """
        return 

    def get_validated_token(self, raw_token):
        """
        Validates an encoded JSON web token and returns a validated token
        wrapper object.
        """
        messages = []

        for AuthToken in api_settings.AUTH_TOKEN_CLASSES:
            try:
                return AuthToken(raw_token)
            except InvalidToken as e:
                messages.append({'token_class': AuthToken.__name__, 'token': raw_token, 'message': e.args[0]})

        raise InvalidToken({
            'detail': _('Given token not valid for any token type'),
            'messages': messages,
        })

    def get_user(self, validated_token):
        """
        Attempts to find and return a user using the given validated token.
        """
        try:
            user_id = validated_token.payloads.get('user_id')
        except KeyError:
            raise InvalidToken(_('Token contained no recognizable user identification'))

        try:
            user = get_user_from_payload(validated_token)
        except User.DoesNotExist:
            raise AuthenticationFailed(_('User not found'), code='user_not_found')

        if not user.is_active:
            raise AuthenticationFailed(_('User is inactive'), code='user_inactive')

        return user