import requests
from rest_framework.decorators import api_view, parser_classes
from ..decorators import authorize_user
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
# from django.contrib.auth.models import User
from ..serializers import UserProfileImageSerializer
from ..models import UserProfileImage, CustomUser

@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
@authorize_user
def ImageUpload(request):
    try:      
        id = getattr(request, 'id')
        user, created = CustomUser.objects.get_or_create(id=id, defaults={'is_active': True})
        serializer = UserProfileImageSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        profile_image, created = UserProfileImage.objects.get_or_create(user=user)
        profile_image.image = serializer.validated_data['image']
        profile_image.save()
        response_serializer = UserProfileImageSerializer(profile_image)
        return Response(
            {'message': 'Image uploaded successfully', 'data': response_serializer.data},
            status=status.HTTP_201_CREATED
        )

    except Exception as e:
        return Response(
            {'error': 'An error occurred', 'details': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
