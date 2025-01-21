from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
import requests
import os
from ..models import User
from ..serializers import UserSerializerOAuth

@api_view(['GET'])
@permission_classes([AllowAny])
def OAuth(request):
    """
    View to create or update a user based on OAuth with 42 API and return JWT tokens.
    """
    code = request.GET.get('code')
    print(code)
    if not code:
        return Response({"error": "Code not provided"}, status=status.HTTP_400_BAD_REQUEST)
    try:
        # Obtain the access token from 42 API
        access_token = get_access_token(code)
        if not access_token:
            return Response({"error": "Failed to obtain access token"}, status=status.HTTP_400_BAD_REQUEST)

        # Retrieve user information from 42 API
        user_data = get_user_info_from_42(access_token)
        if not user_data:
            return Response({"error": "Failed to obtain user information"}, status=status.HTTP_400_BAD_REQUEST)

        user_data['username'] = user_data.get('login')

        # Check if a user already exists based on email (ensuring uniqueness)
        user = User.objects.filter(email=user_data['email']).first()

        if user:
            # User exists, create JWT tokens
            tokens = create_tokens_for_user(user)
            return Response({
                "access": tokens['access'],
                "refresh": tokens['refresh'],
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email
                }
            }, status=status.HTTP_200_OK)

        # User doesn't exist, create or update user with the serializer
        serializer = UserSerializerOAuth(data=user_data)
        if serializer.is_valid():
            user = serializer.save(is_active=True)  # Ensure the user is active
            tokens = create_tokens_for_user(user)
            
            return Response({
                "access": tokens['access'],
                "refresh": tokens['refresh'],
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email
                }
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except requests.RequestException as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def get_access_token(code):
    """Helper function to get the access token from the 42 API."""
    token_url = 'https://api.intra.42.fr/oauth/token'
    redirect_uri = 'http://127.0.0.1:3000/zTestTools/succes.html'
    response = requests.post(token_url, data={
        'grant_type': 'authorization_code',
        'client_id': os.environ.get('CLIENT_ID'),
        'client_secret': os.environ.get('CLIENT_SECRET'),
        'code': code,
        'redirect_uri': redirect_uri,
    })

    if response.status_code == 200:
        print(response.json())
        return response.json().get('access_token')
    return None

def get_user_info_from_42(access_token):
    """Helper function to get user information from the 42 API."""
    user_info_url = 'https://api.intra.42.fr/v2/me'
    response = requests.get(user_info_url, headers={'Authorization': f'Bearer {access_token}'})

    if response.status_code == 200:
        print(response.json())
        return response.json()
    return None

def create_tokens_for_user(user):
    """Generate JWT tokens for the authenticated user."""
    refresh = RefreshToken.for_user(user)
    access = refresh.access_token
    return {
        "access": str(access),
        "refresh": str(refresh)
    }
