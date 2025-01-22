from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from ..models import User
from rest_framework import status
from rest_framework.response import Response
from django.utils.encoding import force_str
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny

@api_view(['GET'])
@permission_classes([AllowAny])
def EmailActivate(request, uidb64, token):
    """
    View to verify email and activate user.
    """
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({'detail': 'Invalid verification link'}, status=status.HTTP_400_BAD_REQUEST)

    if default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return Response({"detail": "Email successfully verified."}, status=status.HTTP_200_OK)
    else:
        return Response({'detail': 'Invalid verification link or expired token'}, status=status.HTTP_400_BAD_REQUEST)
