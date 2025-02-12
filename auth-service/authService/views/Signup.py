from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from ..serializers import UserSerializer
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User

@api_view(['POST'])
@permission_classes([AllowAny])
def Signup(request):
    """
    View to register a new user.
    """
    serializer = UserSerializer(data=request.data)
    
    if serializer.is_valid():
        try:
            user = serializer.save()

            # Generate the verification token
            refresh = RefreshToken.for_user(user)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Use the frontend URL from the Nginx configuration
            frontend_url = "https://xpongo.ddns.net:8443"
            verification_url = f"{frontend_url}/verify-email/?uid={uid}&token={token}"      

            # Send the verification email
            send_verification_email(user.email, verification_url)

            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                }
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({"detail": "An error occurred during registration", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def send_verification_email(email, verification_url):
    """Send the verification email."""
    try:
        send_mail(
            subject="Email Verification",
            message=f'Please click the following link to verify your email address: {verification_url}',
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[email],
            fail_silently=False,
        )
    except Exception as e:
        raise Exception(f"Error sending verification email: {str(e)}")
