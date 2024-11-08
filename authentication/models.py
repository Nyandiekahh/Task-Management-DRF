from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import secrets

class User(AbstractUser):
    ROLES = (
        ('admin', 'Admin'),
        ('manager', 'Manager'),
        ('user', 'User'),
    )
    
    role = models.CharField(max_length=20, choices=ROLES, default='user')
    email = models.EmailField(unique=True)
    password_setup_token = models.CharField(max_length=64, null=True, blank=True)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    
    def generate_otp(self):
        """Generate a new OTP and save it"""
        self.otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        self.otp_created_at = timezone.now()
        self.save()
        return self.otp
    
    def verify_otp(self, otp):
        """Verify if the provided OTP is valid and not expired"""
        if not self.otp or not self.otp_created_at:
            return False
            
        # Check if OTP is expired (valid for 10 minutes)
        if timezone.now() > self.otp_created_at + timezone.timedelta(minutes=10):
            return False
            
        return self.otp == otp
    
    class Meta:
        db_table = 'auth_user'

class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

class Permission(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(null=True, blank=True)
    
    def __str__(self):
        return self.name

class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='permissions')
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
    
    class Meta:
        unique_together = ('role', 'permission')
        
class UserPermission(models.Model):
    user = models.ForeignKey(
        User, 
        related_name='custom_permissions',
        on_delete=models.CASCADE
    )
    permission_name = models.CharField(max_length=100)
    
    class Meta:
        unique_together = ('user', 'permission_name')