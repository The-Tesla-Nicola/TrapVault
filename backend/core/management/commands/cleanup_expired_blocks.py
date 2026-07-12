"""
Management Command: Cleanup Expired Blocks
===========================================
Usage: python manage.py cleanup_expired_blocks
"""

from django.core.management.base import BaseCommand
from core.soar.automation import soar_engine


class Command(BaseCommand):
    help = "Remove expired blocks from database and cache"

    def handle(self, *args, **options):
        self.stdout.write("Cleaning up expired blocks...")

        count = soar_engine.cleanup_expired_blocks()

        if count > 0:
            self.stdout.write(
                self.style.SUCCESS(f"✓ Cleaned up {count} expired blocks")
            )
        else:
            self.stdout.write(self.style.SUCCESS("✓ No expired blocks found"))
