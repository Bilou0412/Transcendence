import os
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings
from ..serializers import PassResetSerializer
from ..models import User

@api_view(['POST'])
@permission_classes([AllowAny])
def PassReset(request):
    serializer = PassResetSerializer(data=request.data)
    
    if serializer.is_valid():
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
            
            # Generate password reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # Build reset URL
            reset_url = f"https://{os.getenv('DNS_URL')}:8443/password-reset/confirm?uid={uid}&token={token}"

            # Send email
            send_mail(
                subject="Password Reset Request",
                message=f'Click the following link to reset your password: {reset_url}',
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[user.email],
                fail_silently=False,
            )

        except User.DoesNotExist:
            # For security, return success even if email doesn't exist
            pass

        return Response(
            {"detail": "Password reset email has been sent"}, 
            status=status.HTTP_200_OK
        )
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
