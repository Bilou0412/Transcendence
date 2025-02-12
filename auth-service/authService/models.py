from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib.auth.validators import UnicodeUsernameValidator

class User(AbstractUser):
    username = models.CharField(
        max_length=150,
        validators=[UnicodeUsernameValidator()],
        help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.',
        verbose_name='username',
        unique=False,  # Username non unique
        blank=False,   # Username obligatoire
        null=False
    )
    email = models.EmailField(unique=True)  # Email unique pour chaque utilisateur
    new_email = models.EmailField(null=True, blank=True)  # Email pour vérification
    Student = models.BooleanField(default=False)
    otp_secret = models.CharField(max_length=32, blank=True, null=True)
    
    # Email est l'identifiant unique
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']  # Username est requis, mais non unique
    
    def has_2fa_enabled(self):
        return bool(self.otp_secret)
