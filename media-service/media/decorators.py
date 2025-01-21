from functools import wraps
from rest_framework.response import Response
from rest_framework import status
import requests

def authorize_user(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        token = request.headers.get('Authorization', '')
        if not token:
            return Response({'error': 'No token'}, status=status.HTTP_401_UNAUTHORIZED)
        response = requests.post('http://auth:8000/auth/token/validate/', headers={'Authorization': token})
        if response.status_code != 200:
            return Response({'error': 'Invalid token', 'status': response.status_code}, status=status.HTTP_401_UNAUTHORIZED)
        request.id = response.json()['id']
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view