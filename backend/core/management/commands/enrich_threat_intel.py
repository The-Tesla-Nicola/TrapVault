"""
Management Command: Enrich Threat Intelligence
===============================================
Usage: python manage.py enrich_threat_intel [--all]
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from core.models import AttackerSession
from core.siem.threat_intel import threat_intel


class Command(BaseCommand):
    help = "Enrich sessions with threat intelligence data"

    def add_arguments(self, parser):
        parser.add_argument(
            "--all",
            action="store_true",
            help="Enrich all sessions (default: only unenriched sessions)",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=100,
            help="Maximum number of sessions to process (default: 100)",
        )

    def handle(self, *args, **options):
        enrich_all = options["all"]
        limit = options["limit"]

        self.stdout.write("=" * 60)
        self.stdout.write(self.style.WARNING("Threat Intelligence Enrichment"))
        self.stdout.write("=" * 60)

        # Query for sessions to enrich
        if enrich_all:
            sessions = AttackerSession.objects.all().order_by("-created_at")[:limit]
        else:
            sessions = AttackerSession.objects.filter(country="Unknown").order_by(
                "-created_at"
            )[:limit]

        total = sessions.count()
        self.stdout.write(f"\nProcessing {total} sessions...")

        if total == 0:
            self.stdout.write(self.style.SUCCESS("\n✓ No sessions need enrichment"))
            return

        success_count = 0
        error_count = 0

        for idx, session in enumerate(sessions, 1):
            try:
                enrichment = threat_intel.enrich_session(session)
                success_count += 1

                if idx % 10 == 0:
                    self.stdout.write(
                        f"  [{idx}/{total}] {session.ip_address} -> "
                        f"{enrichment['geolocation']['country']} "
                        f"(Threat: {enrichment['threat_level']})"
                    )
            except Exception as e:
                error_count += 1
                self.stdout.write(
                    self.style.ERROR(f"  ✗ Failed to enrich {session.ip_address}: {e}")
                )

        self.stdout.write("\n" + "=" * 60)
        self.stdout.write(self.style.SUCCESS(f"✓ Enriched {success_count} sessions"))
        if error_count > 0:
            self.stdout.write(self.style.ERROR(f"✗ Failed: {error_count}"))
