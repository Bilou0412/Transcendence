from django.urls import re_path
from .consumers import LobbyConsumer

websocket_urlpatterns = [
	re_path(r'wsmanagement/lobby/$', LobbyConsumer.as_asgi()),
]
