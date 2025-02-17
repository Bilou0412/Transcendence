from django.urls import re_path
from .consumers import PongConsumer

websocket_urlpatterns = [
    re_path(r'^remote/(?P<room_name>\w+)/$', PongConsumer.as_asgi()),
]