"""
Core App Configuration
====================
Django app configuration for the honeypot SIEM core.
"""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Configuration for the Honeypot SIEM Core application."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "core"
    verbose_name = "Honeypot SIEM Core"

    def ready(self):
        """Initialize app when Django starts."""
        pass
