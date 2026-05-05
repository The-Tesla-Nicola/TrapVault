from django.core.management.base import BaseCommand, CommandError
from core.models import MonitorUser


class Command(BaseCommand):
    help = 'Create a monitor dashboard user with a specific role.'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='Login username')
        parser.add_argument('password', type=str, help='Login password')
        parser.add_argument(
            '--role',
            type=str,
            default='analyst',
            choices=['admin', 'analyst', 'viewer'],
            help='User role (default: analyst)',
        )
        parser.add_argument('--email', type=str, default='', help='Email address (optional)')

    def handle(self, *args, **options):
        username = options['username']
        password = options['password']
        role     = options['role']
        email    = options['email']

        if MonitorUser.objects.filter(username=username).exists():
            self.stdout.write(
                self.style.WARNING('User "{}" already exists. No changes made.'.format(username))
            )
            return

        if len(password) < 8:
            raise CommandError('Password must be at least 8 characters.')

        user = MonitorUser.objects.create_user(
            username=username,
            password=password,
            email=email,
            role=role,
        )

        self.stdout.write(
            self.style.SUCCESS(
                'Created monitor user "{}" with role "{}".'.format(user.username, user.role)
            )
        )
