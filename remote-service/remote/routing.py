from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'remote/(?P<room_name>\w+)/$', consumers.PongConsumer.as_asgi()),
]
