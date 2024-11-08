# authentication/management/commands/setup_permissions.py

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from authentication.models import UserPermission

User = get_user_model()

class Command(BaseCommand):
    help = 'Setup initial permissions for admin user'

    def handle(self, *args, **kwargs):
        try:
            admin_user = User.objects.get(username='nyandieka')
            # Set role to admin
            admin_user.role = 'admin'
            admin_user.save()
            
            # Define admin permissions
            admin_permissions = [
                'all',
                'create_task',
                'edit_task',
                'delete_task',
                'assign_task',
                'view_all_tasks',
                'manage_users',
                'view_reports'
            ]
            
            # Add permissions
            for permission in admin_permissions:
                UserPermission.objects.get_or_create(
                    user=admin_user,
                    permission_name=permission
                )
                self.stdout.write(
                    self.style.SUCCESS(f'Created permission: {permission}')
                )
                
            self.stdout.write(
                self.style.SUCCESS(f'Successfully set up permissions for {admin_user.username}')
            )
            
        except User.DoesNotExist:
            self.stdout.write(
                self.style.ERROR('Admin user not found')
            )