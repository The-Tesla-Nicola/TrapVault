"""
Core App Configuration — TrapVault SIEM Core
"""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"
    verbose_name = "TrapVault SIEM Core"

    def ready(self):
        pass
