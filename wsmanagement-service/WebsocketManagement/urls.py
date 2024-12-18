
from django.contrib import admin
from django.urls import path
from .views import FriendRequest

urlpatterns = [
    path('wsmanagement/admin/', admin.site.urls),
    path('wsmanagement/', FriendRequest, name="friendrequest"),
]
