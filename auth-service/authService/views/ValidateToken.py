from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import  IsAuthenticated
from rest_framework.response import Response


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def Validate(request):
    print('l')
    user = request.user 
    if user:
        return Response({'detail': 'Valid token.', 'id': user.id}, status=status.HTTP_200_OK)
    return Response({'detail': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)