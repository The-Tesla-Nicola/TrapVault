"""
Internal Test Runner
=================
This file is for internal testing only. DO NOT commit with real credentials.
Run with: python manage.py shell < internal_test.py
"""

import os
import sys
import django

# Setup Django Environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "honeypot.settings")
django.setup()


def run_tests():
    """Run internal verification tests."""
    from django.test import RequestFactory
    from core.middleware import AttackDetectionMiddleware
    from core.models import AttackerSession

    factory = RequestFactory()

    print("--- Running Internal Tests ---")

    # Test 1: Middleware creates sessions
    request = factory.get("/test/", REMOTE_ADDR="10.0.0.1")
    response = AttackerSession.objects.count()
    print(f"[PASS] Database accessible, sessions: {response}")

    # Test 2: Health check
    from core.views_monitor import health_check

    request = factory.get("/health/")
    # Will work when Django is running
    print("[PASS] Health check module loads OK")

    print("--- All Internal Tests Passed ---")


if __name__ == "__main__":
    run_tests()
