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
    path('admin/', admin.site.urls),

    # API Authentication endpoints
    path('auth/api/auth/signup/', Signup, name='signup'),
    path('api/auth/login/', Login, name='login'),
    path('api/auth/logout/', Logout, name='logout'),

    # API Update info endpoints
    path('api/auth/update/', UpdateUserInfo, name='updateuserinfo'),

    # API 42OAuth endpoints
    path('api/auth/oauth/', OAuth, name='oauth'),
    path('api/auth/token/refresh/', Refresh, name='refresh'),
    path('api/auth/token/validate/', Validate, name='validate'),

    # API Password Management endpoints
    path('api/auth/password/reset/', PassReset, name='passreset'),
    path('api/auth/password/update/', PassUpdate, name='passupdate'),

    # API 2FA
    path('api/auth/2fa/enable/', enable_2fa, name='enable2fa'),
    path('api/auth/2fa/disable/', disable_2fa, name='disable2fa'),
    path('api/auth/2fa/verify/', verify_2fa, name='verify2fa'),

    # API Email verification endpoint
    path('api/auth/email/verification/<uidb64>/<token>/',EmailActivate, name='emailactivate'),
    path('api/auth/email/update/<uidb64>/<token>/',EmailUpdateInfo, name='emailupdateinfo'),
    path('api/auth/password/reset/confirm/<uidb64>/<token>/',PassResetConfirm, name='passresetconfirm'),

    # API Users Info endpoint
    path('api/auth/users/info/', UsersInfo, name='usersinfo'),

    # API Search User endpoint
    path('api/auth/search_user/', SearchUser, name='search_user'),  # Add the search user endpoint
]
