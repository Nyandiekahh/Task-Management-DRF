from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404
import logging

from .models import Role, Permission, UserPermission
from .serializers import (
    RoleSerializer, 
    PermissionSerializer, 
    CreateUserSerializer, 
    UserListSerializer,
    LoginSerializer,
    UserSerializer,
    VerifyOTPSerializer
)

logger = logging.getLogger(__name__)
User = get_user_model()

class LoginView(APIView):
    permission_classes = []
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            
            if user:
                refresh = RefreshToken.for_user(user)
                user_serializer = UserSerializer(user)
                
                return Response({
                    'userData': user_serializer.data,
                    'token': str(refresh.access_token),
                    'refresh': str(refresh)
                })
                
            return Response(
                {'error': 'Invalid credentials'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class IsAdminUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role == 'admin'

class UserViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAdminUser]
    
    def get_serializer_class(self):
        if self.action == 'create':
            return CreateUserSerializer
        return UserListSerializer
    
    def get_queryset(self):
        return User.objects.all().order_by('-date_joined')

    def create(self, request):
        logger.info(f"Creating user with data: {request.data}")
        
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"Validation errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            # Create user without password, inactive until verified
            user = serializer.save(is_active=False)
            
            # Generate OTP
            otp = user.generate_otp()
            
            try:
                # Send email with OTP to the new user's email
                email_message = f"""
                Hello {user.first_name},

                Your account has been created in {settings.COMPANY_NAME}. 
                Please use the following OTP to verify your account and set your password:

                {otp}

                This OTP will expire in 10 minutes.

                If you did not expect this account creation, please ignore this email.

                Best regards,
                {settings.COMPANY_NAME} Team
                """
                
                send_mail(
                    'Verify Your Account',
                    email_message,
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                
                logger.info(f"Successfully created user and sent OTP to {user.email}")
                
                return Response({
                    'message': f'User created successfully. OTP sent to {user.email}',
                    'user': serializer.data
                }, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                logger.error(f"Failed to send email: {str(e)}")
                user.delete()
                return Response({
                    'error': f'Failed to send verification email: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except Exception as e:
            logger.error(f"Failed to create user: {str(e)}")
            return Response({
                'error': f'Failed to create user: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def verify_otp(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = get_object_or_404(User, email=serializer.validated_data['email'])
                
                if user.verify_otp(serializer.validated_data['otp']):
                    user.set_password(serializer.validated_data['password'])
                    user.is_active = True
                    user.otp = None
                    user.otp_created_at = None
                    user.save()
                    
                    logger.info(f"Successfully verified and activated user: {user.email}")
                    
                    return Response({
                        'message': 'Account verified and activated successfully. You can now login.'
                    })
                
                return Response(
                    {'error': 'Invalid or expired OTP'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            except Exception as e:
                logger.error(f"OTP verification failed: {str(e)}")
                return Response(
                    {'error': f'Verification failed: {str(e)}'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def set_permissions(self, request, pk=None):
        user = self.get_object()
        permissions = request.data.get('permissions', [])
        
        user.custom_permissions.all().delete()
        
        for perm in permissions:
            UserPermission.objects.create(user=user, permission_name=perm)
        
        return Response({'status': 'permissions updated'})

    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        user = self.get_object()
        user.is_active = True
        user.save()
        return Response({'status': 'user activated'})

    @action(detail=True, methods=['post'])
    def deactivate(self, request, pk=None):
        user = self.get_object()
        user.is_active = False
        user.save()
        return Response({'status': 'user deactivated'})

class RoleViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAdminUser]
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    @action(detail=True, methods=['post'])
    def set_permissions(self, request, pk=None):
        role = self.get_object()
        permissions = request.data.get('permissions', [])
        
        role.permissions.all().delete()
        
        for perm_name in permissions:
            permission, _ = Permission.objects.get_or_create(name=perm_name)
            role.permissions.add(permission)
        
        return Response({'status': 'permissions updated'})

class PermissionViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAdminUser]
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer