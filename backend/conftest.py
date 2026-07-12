"""
Pytest configuration and fixtures for TrapVault tests.
"""

import os
import django
import pytest
from django.conf import settings

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "honeypot.settings")


def pytest_configure():
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            DEBUG=True,
            DATABASES={
                "default": {
                    "ENGINE": "django.db.backends.sqlite3",
                    "NAME": ":memory:",
                }
            },
            SECRET_KEY="test-secret-key-for-testing-only",
            MIDDLEWARE=[],
            INSTALLED_APPS=[
                "django.contrib.auth",
                "django.contrib.contenttypes",
                "core",
            ],
        )
    django.setup()


@pytest.fixture
def db_setup(db):
    pass


@pytest.fixture
def monitor_user(db):
    from core.models import MonitorUser

    return MonitorUser.objects.create_user(
        username="testuser", password="testpass123", role="admin"
    )


@pytest.fixture
def attacker_session(db):
    from core.models import AttackerSession

    return AttackerSession.objects.create(
        fingerprint="test-fingerprint-12345",
        ip_address="192.168.1.100",
        user_agent="TestAgent/1.0",
    )


@pytest.fixture
def siem_request_data():
    return {
        "ip": "192.168.1.100",
        "user_agent": "Mozilla/5.0",
        "method": "POST",
        "path": "/auth/login/",
        "query_string": "",
        "body": '{"username": "admin", "password": "admin"}',
        "headers": {"HTTP_USER_AGENT": "Mozilla/5.0"},
    }
