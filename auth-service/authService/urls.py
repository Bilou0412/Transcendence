from .views.Signup import Signup
from .views.EmailActivate import EmailActivate
from .views.OAuth import OAuth
from .views.Login import Login
from .views.RefreshToken import Refresh
from .views.ValidateToken import Validate
from .views.Logout import Logout
from .views.PassReset import PassReset
from .views.EmailPassReset import PassResetConfirm
from .views.PassUpdate import PassUpdate
from .views.EmailUpdateInfo import EmailUpdateInfo
from .views.UpdateUserInfo import UpdateUserInfo
from .views.UsersInfo import UsersInfo
from .views.Mfa import enable_2fa, verify_2fa, disable_2fa
from .views.SearchUser import SearchUser  # Import the search_user view
from django.contrib import admin
from django.urls import path, include  # Import include to use with blueprint

urlpatterns = [
    path('auth/admin/', admin.site.urls),

    # API Authentication endpoints
    path('auth/signup/', Signup, name='signup'),
    path('auth/login/', Login, name='login'),
    path('auth/logout/', Logout, name='logout'),

    # API Update info endpoints
    path('auth/update/', UpdateUserInfo, name='updateuserinfo'),

    # API 42OAuth endpoints
    path('auth/oauth/', OAuth, name='oauth'),
    path('auth/token/refresh/', Refresh, name='refresh'),
    path('auth/token/validate/', Validate, name='validate'),

    # API Password Management endpoints
    path('auth/password/reset/', PassReset, name='passreset'),
    path('auth/password/update/', PassUpdate, name='passupdate'),

    # API 2FA
    path('auth/2fa/enable/', enable_2fa, name='enable2fa'),
    path('auth/2fa/disable/', disable_2fa, name='disable2fa'),
    path('auth/2fa/verify/', verify_2fa, name='verify2fa'),

    # API Email verification endpoint
    path('auth/email/verification/<uidb64>/<token>/',EmailActivate, name='emailactivate'),
    path('auth/email/update/<uidb64>/<token>/',EmailUpdateInfo, name='emailupdateinfo'),
    path('auth/password/reset/confirm/<uidb64>/<token>/',PassResetConfirm, name='passresetconfirm'),

    # API Users Info endpoint
    path('auth/users/info/', UsersInfo, name='usersinfo'),

    # API Search User endpoint
    path('auth/search_user/', SearchUser, name='search_user'),  # Add the search user endpoint
]
