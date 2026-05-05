"""
Creates seed legitimate bank users so the transparent proxy has real
credentials to verify against.  Use only in development / staging.
"""

import random
import string

import bcrypt
from django.core.management.base import BaseCommand
from core.models import RealBankUser


DEMO_USERS = [
    ('michael.scott',  'michael@securebank.com',  'Michael Scott',  '4001-2345-6789', 'Michael$c0tt!123'),
    ('dwight.schrute', 'dwight@securebank.com',   'Dwight Schrute', '4001-3456-7890', 'B3etsBearsB$G'),
    ('jim.halpert',    'jim@securebank.com',      'Jim Halpert',    '4001-4567-8901', 'Pam!1234567'),
    ('pam.beesly',     'pam@securebank.com',      'Pam Beesly',     '4001-5678-9012', 'Art$chool1'),
    ('angela.martin',  'angela@securebank.com',   'Angela Martin',  '4001-6789-0123', 'Recepti0n!T'),
]


class Command(BaseCommand):
    help = 'Seed the database with demo legitimate bank users for testing.'

    def handle(self, *args, **options):
        created = 0
        for username, email, full_name, account, password in DEMO_USERS:
            if RealBankUser.objects.filter(username=username).exists():
                self.stdout.write(f'  skip  {username} (already exists)')
                continue
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
            RealBankUser.objects.create(
                username=username,
                password_hash=pw_hash,
                email=email,
                full_name=full_name,
                account_number=account,
            )
            self.stdout.write(self.style.SUCCESS(f'  created  {username}'))
            created += 1

        self.stdout.write(self.style.SUCCESS(
            f'\nDone. {created} user(s) created.'
        ))
        self.stdout.write(
            '\nTest credentials (development only — never use in production):\n'
        )
        for username, _, _, _, password in DEMO_USERS:
            self.stdout.write(f'  {username:20s}  {password}')
