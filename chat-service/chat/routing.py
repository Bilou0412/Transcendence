from django.urls import re_path
from .consumers import ChatConsumer

websocket_urlpatterns = [
    re_path(r'chat/(?P<chat_id>\w+)/$', ChatConsumer.as_asgi()),
]