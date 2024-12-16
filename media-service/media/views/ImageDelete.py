import os
import requests
from rest_framework.decorators import api_view
from ..decorators import authorize_user
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from ..models import UserProfileImage, CustomUser
from django.core.exceptions import ObjectDoesNotExist

@api_view(['DELETE'])
@authorize_user
def	ImageDelete(request):
    id = getattr(request, 'id')
    try:
        user = CustomUser.objects.get(id=id)
        profileImage = UserProfileImage.objects.get(user=user)
        
        if not os.path.exists(profileImage.image.path):
            return Response(
                {'error': 'Image file not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        os.remove(profileImage.image.path)
        profileImage.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    except ObjectDoesNotExist:
        return Response(
            {'error': 'User does not have an image'},
            status=status.HTTP_404_NOT_FOUND
        )

    except UserProfileImage.DoesNotExist:
        return Response(
            {'error': 'Image file not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {'error': 'An error occurred', 'details': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )