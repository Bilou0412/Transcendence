from django.contrib import admin
from django.urls import path
from .views.UpdateFriendshipStatus import UpdateFriendshipStatus
from .views.CreateMatch import CreateMatch
from .views.MatchHistory import MatchHistory
from .views.ListFriends import ListFriends
from .views.BlockUser import BlockUser
from .views.SendRequest import SendRequest
from .views.UserStats import UserStats
from .views.ListBlocked import ListBlocked
from .views.UnblockUser import UnblockUser
from .views.ListRequest import ListRequest

urlpatterns = [
    path('admin/', admin.site.urls),
    path('usermanagement/stats/', UserStats, name='userstats'),

    # Match History
    path('usermanagement/matches/create/', CreateMatch, name='creatematch'),
    path('usermanagement/<int:user_id>/matches/', MatchHistory,
         name='get_user_match_history'),
    # path('usermanagement/matches/', MatchHistory, name='matchhistory'),

    # Friendship
    path('usermanagement/friends/request/', SendRequest, name='sendrequest'),
    path('usermanagement/friends/update/', UpdateFriendshipStatus, name='acceptrequest'),
    path('usermanagement/friends/', ListFriends, name='listfriends'),
    path('usermanagement/friends/listrequests/', ListRequest, name='listrequests'),

    # Block
    path('usermanagement/block/request/', BlockUser, name='blockuser'),
    path('usermanagement/block/', ListBlocked, name='listblocked'),
    path('usermanagement/unblock/', UnblockUser, name='unblockuser'),
]
