from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from authService.models import User  # Assuming you have a User model

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def SearchUser(request):
    username = request.GET.get('username')
    if not username:
        return JsonResponse({'error': 'Username is required'}, status=400)

    users = User.objects.filter(username__istartswith=username)
    if users.exists():
        user_list = [{'id': user.id, 'username': user.username} for user in users]
        return JsonResponse({'users': user_list}, status=200)
    else:
        return JsonResponse({'error': 'No users found'}, status=404)

# ...existing code...
