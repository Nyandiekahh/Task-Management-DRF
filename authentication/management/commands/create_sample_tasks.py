from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth import get_user_model
from authentication.models import Task, ActivityLog
from datetime import timedelta

User = get_user_model()

class Command(BaseCommand):
    help = 'Creates sample tasks for testing'

    def handle(self, *args, **options):
        # Get or create users
        try:
            admin_user = User.objects.filter(role='admin').first()
            if not admin_user:
                self.stdout.write('No admin user found. Creating one...')
                admin_user = User.objects.create_user(
                    username='admin',
                    email='admin@example.com',
                    password='admin123',
                    role='admin',
                    first_name='Admin',
                    last_name='User',
                    is_active=True
                )
            else:
                self.stdout.write(f'Using existing admin user: {admin_user.username}')

            regular_user = User.objects.filter(role='user').first()
            if not regular_user:
                self.stdout.write('No regular user found. Creating one...')
                regular_user = User.objects.create_user(
                    username='user',
                    email='user@example.com',
                    password='user123',
                    role='user',
                    first_name='Regular',
                    last_name='User',
                    is_active=True
                )
            else:
                self.stdout.write(f'Using existing regular user: {regular_user.username}')

            # Sample tasks data
            tasks = [
                {
                    'title': 'Complete Q4 Financial Report',
                    'description': 'Review and finalize the Q4 financial statements and prepare presentation for stakeholders.',
                    'priority': 'high',
                    'status': 'pending',
                    'due_date': timezone.now().date() + timedelta(days=5),
                    'assigned_by': admin_user,
                    'assigned_to': regular_user
                },
                {
                    'title': 'Update Company Website',
                    'description': 'Update the company website with new product features and team members.',
                    'priority': 'medium',
                    'status': 'in_progress',
                    'due_date': timezone.now().date() + timedelta(days=3),
                    'assigned_by': admin_user,
                    'assigned_to': regular_user
                },
                {
                    'title': 'Employee Training Session',
                    'description': 'Organize and conduct training session for new software tools.',
                    'priority': 'medium',
                    'status': 'pending',
                    'due_date': timezone.now().date() + timedelta(days=7),
                    'assigned_by': regular_user,
                    'assigned_to': admin_user
                },
                {
                    'title': 'Client Meeting Preparation',
                    'description': 'Prepare presentation and documentation for upcoming client meeting.',
                    'priority': 'high',
                    'status': 'in_progress',
                    'due_date': timezone.now().date() + timedelta(days=1),
                    'assigned_by': admin_user,
                    'assigned_to': regular_user
                },
                {
                    'title': 'System Maintenance',
                    'description': 'Perform routine system maintenance and updates.',
                    'priority': 'low',
                    'status': 'completed',
                    'due_date': timezone.now().date() - timedelta(days=1),
                    'assigned_by': regular_user,
                    'assigned_to': admin_user
                },
                {
                    'title': 'Team Building Event',
                    'description': 'Plan and organize team building activity for next month.',
                    'priority': 'low',
                    'status': 'pending',
                    'due_date': timezone.now().date() + timedelta(days=14),
                    'assigned_by': admin_user,
                    'assigned_to': regular_user
                }
            ]

            # Delete existing tasks and their logs
            current_tasks_count = Task.objects.count()
            current_logs_count = ActivityLog.objects.count()
            
            ActivityLog.objects.all().delete()
            Task.objects.all().delete()
            
            self.stdout.write(f'Deleted {current_tasks_count} existing tasks and {current_logs_count} activity logs')

            # Create new tasks and activity logs
            for task_data in tasks:
                task = Task.objects.create(
                    title=task_data['title'],
                    description=task_data['description'],
                    assigned_by=task_data['assigned_by'],
                    assigned_to=task_data['assigned_to'],
                    priority=task_data['priority'],
                    status=task_data['status'],
                    due_date=task_data['due_date']
                )
                
                ActivityLog.objects.create(
                    user=task_data['assigned_by'],
                    task=task,
                    action='created_task',
                    details=f"Created task: {task.title}"
                )

            self.stdout.write(self.style.SUCCESS(f'Successfully created {len(tasks)} sample tasks'))
            self.stdout.write('\nYou can use the following users:')
            self.stdout.write(f'Admin User: {admin_user.username}')
            self.stdout.write(f'Regular User: {regular_user.username}')

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error: {str(e)}'))