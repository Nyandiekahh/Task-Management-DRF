# authentication/serializers.py

from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import UserPermission

User = get_user_model()

class UserPermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserPermission
        fields = ('permission_name',)

class UserSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'role', 'permissions', 'first_name', 'last_name')
        read_only_fields = ('id',)

    def get_permissions(self, obj):
        permissions = obj.custom_permissions.all()
        return [perm.permission_name for perm in permissions]

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)