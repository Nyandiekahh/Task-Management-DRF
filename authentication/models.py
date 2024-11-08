# authentication/models.py

from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLES = (
        ('admin', 'Admin'),
        ('manager', 'Manager'),
        ('user', 'User'),
    )
    
    role = models.CharField(max_length=20, choices=ROLES, default='user')
    email = models.EmailField(unique=True)
    
    def __str__(self):
        return f"{self.username} ({self.role})"
    
    class Meta:
        db_table = 'auth_user'
        
class UserPermission(models.Model):
    user = models.ForeignKey(
        User, 
        related_name='custom_permissions',
        on_delete=models.CASCADE
    )
    permission_name = models.CharField(max_length=100)
    
    class Meta:
        unique_together = ('user', 'permission_name')
    
    def __str__(self):
        return f"{self.user.username} - {self.permission_name}"