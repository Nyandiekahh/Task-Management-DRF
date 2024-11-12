from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email
from .models import Role, Permission, RolePermission, UserPermission, Task, ActivityLog

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'role', 'first_name', 'last_name', 'permissions')
        read_only_fields = ('id',)

    def get_permissions(self, obj):
        return [perm.permission_name for perm in obj.custom_permissions.all()]

class CreateUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    role = serializers.ChoiceField(choices=User.ROLES, default='user')

    class Meta:
        model = User
        fields = ('email', 'role', 'first_name', 'last_name')

    def validate_email(self, value):
        if not value:
            raise serializers.ValidationError("Email is required")
        try:
            validate_email(value)
        except:
            raise serializers.ValidationError("Invalid email address")

        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists")
        
        return value.lower()

    def validate_first_name(self, value):
        if not value:
            raise serializers.ValidationError("First name is required")
        return value.strip()

    def validate_last_name(self, value):
        if not value:
            raise serializers.ValidationError("Last name is required")
        return value.strip()
        
    def create(self, validated_data):
        # Generate username from email
        email = validated_data['email']
        username = email.split('@')[0]
        base_username = username
        counter = 1
        
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1
        
        try:
            user = User.objects.create_user(
                username=username,
                email=validated_data['email'],
                role=validated_data.get('role', 'user'),
                first_name=validated_data['first_name'],
                last_name=validated_data['last_name'],
                is_active=False
            )
            return user
        except Exception as e:
            raise serializers.ValidationError(f"Error creating user: {str(e)}")

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(min_length=6, max_length=6)
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({
                "password": "Password fields didn't match."
            })

        try:
            validate_password(data['password'])
        except Exception as e:
            raise serializers.ValidationError({
                "password": list(e.messages)
            })

        if not User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError({
                "email": "No user found with this email address."
            })

        if not data['otp'].isdigit():
            raise serializers.ValidationError({
                "otp": "OTP must contain only numbers."
            })

        return data

class RoleSerializer(serializers.ModelSerializer):
    permissions = serializers.StringRelatedField(many=True, read_only=True)

    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'permissions', 'created_at', 'updated_at']

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'description']

class UserListSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'role', 'first_name', 'last_name', 
                 'permissions', 'date_joined', 'is_active')

    def get_permissions(self, obj):
        return [perm.permission_name for perm in obj.custom_permissions.all()]
    
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

# New serializers for Task functionality
class TaskSerializer(serializers.ModelSerializer):
    assigned_by_name = serializers.SerializerMethodField()
    assigned_to_name = serializers.SerializerMethodField()

    class Meta:
        model = Task
        fields = [
            'id', 'title', 'description', 'assigned_by', 'assigned_to',
            'assigned_by_name', 'assigned_to_name', 'status', 'priority',
            'due_date', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at', 'assigned_by_name', 'assigned_to_name']

    def get_assigned_by_name(self, obj):
        return f"{obj.assigned_by.first_name} {obj.assigned_by.last_name}"

    def get_assigned_to_name(self, obj):
        return f"{obj.assigned_to.first_name} {obj.assigned_to.last_name}"

class ActivityLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    task = TaskSerializer(read_only=True)

    class Meta:
        model = ActivityLog
        fields = ['id', 'user', 'task', 'action', 'details', 'timestamp']
        read_only_fields = ['timestamp']