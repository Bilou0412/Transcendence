from rest_framework import serializers
from django.core.exceptions import ValidationError
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.conf import settings

import re
from .models import User

def validate_password_strength(value):
    """Checks if the password meets strength requirements."""
    password_regex = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    if not re.match(password_regex, value):
        raise ValidationError("Password must be at least 8 characters long, contain at least one uppercase letter, one digit, and one special character (@, $, !, %, *, ?, &).")
    return value

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password_strength])
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'password', 'password2', 'email', 'new_email', 'Student']

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email address is already in use.")
        return value

    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError({"password":["Passwords do not match."]})
        return data

    def create(self, validated_data):
        validated_data.pop('password2')  
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            is_active=False
        )
        return user

class UserSerializerOAuth(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'new_email', 'Student']

    def create(self, validated_data):
        """Create a new user or update existing user by email."""
        user, created = User.objects.get_or_create(
            email=validated_data['email'],
            defaults={
                'username': validated_data['username'],
                'is_active': True,
                'Student': True,
            }
        )
        if not created:
            user.username = validated_data['username']
            user.is_active = True
            user.Student = True
            user.save()
        return user
    

class PassResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
            if not user.is_active:
                raise serializers.ValidationError("This account is not active.")
            if user.Student:
                raise serializers.ValidationError("Password reset is only allowed for non-student users.")
        except User.DoesNotExist:
            pass
        return value
    
class PassResetConfirmSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, validators=[validate_password_strength])

    def validate(self, data):
        try:
            uid = force_str(urlsafe_base64_decode(data['uidb64']))
            self.user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid reset link")

        if not self.user.is_active:
            raise serializers.ValidationError("This account is inactive")

        if not default_token_generator.check_token(self.user, data['token']):
            raise serializers.ValidationError("Invalid or expired reset token")

        return data

    def save(self):
        new_password = self.validated_data['new_password']
        self.user.set_password(new_password)
        self.user.save()
        return self.user
    
class PassUpdateSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, validators=[validate_password_strength])

    def validate_old_password(self, value):
        user = self.context['request'].user
        if user.Student:
                raise serializers.ValidationError("Password update is only allowed for non-student users.")
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value

    def save(self):
        user = self.context['request'].user
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
        return user


class UpdateUserInfoSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False)
    username = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = ['email', 'username']

    def validate(self, data):
        user = self.context['request'].user
        # Ensure only non-students can update information
        if user.Student:
            raise serializers.ValidationError("Only non-student users can update information.")
        return data

    def validate_email(self, value):
        user = self.context['request'].user
        # Ensure email is unique across users
        if value and value != user.email and User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email address is already in use.")
        return value

    def save(self):
        user = self.context['request'].user
        email = self.validated_data.get('email')
        username = self.validated_data.get('username')

        # Update email if provided and different
        if email and email != user.email:
            user.new_email = email
            user.save()

            # Generate verification link
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            verification_url = self.context['request'].build_absolute_uri(
                reverse('emailupdateinfo', kwargs={'uidb64': uid, 'token': token})
            )

            # Send verification email
            send_mail(
                subject="Verify your new e-mail address",
                message=f'Please click on the following link to verify your new e-mail address : {verification_url}',
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[user.new_email],
                fail_silently=False,
            )

        # Update username if provided
        if username:
            user.username = username
            user.save()
        
        return user

class UserInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = User  # Utilise le modèle d'utilisateur personnalisé si tu en as un
        fields = ['id','username', 'email']  # Ajoute ici les champs que tu veux renvoyer
