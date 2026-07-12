"""
Creates a standard set of SIEM alert rules covering the most important
threat scenarios. Safe to run multiple times (skips existing rules).
"""

from django.core.management.base import BaseCommand
from core.models import AlertRule

DEFAULT_RULES = [
    {
        "name": "Critical Severity – Immediate Notify",
        "description": "Fire for any critical-severity alert with confidence above 80%.",
        "match_severity": "critical",
        "match_attack_type": "",
        "min_confidence": 0.80,
        "min_session_score": 0,
        "notification_channel": "both",
        "auto_block": True,
        "cooldown_seconds": 120,
    },
    {
        "name": "Web Shell Detection",
        "description": "Web shell upload or access attempt.",
        "match_severity": "critical",
        "match_attack_type": "web_shell",
        "min_confidence": 0.70,
        "min_session_score": 0,
        "notification_channel": "both",
        "auto_block": True,
        "cooldown_seconds": 60,
    },
    {
        "name": "Command Injection",
        "description": "OS command injection payload detected.",
        "match_severity": "critical",
        "match_attack_type": "command_injection",
        "min_confidence": 0.75,
        "min_session_score": 0,
        "notification_channel": "both",
        "auto_block": True,
        "cooldown_seconds": 60,
    },
    {
        "name": "SQL Injection – High Confidence",
        "description": "SQL injection attempt with confidence above 85%.",
        "match_severity": "high",
        "match_attack_type": "sql_injection",
        "min_confidence": 0.85,
        "min_session_score": 0,
        "notification_channel": "slack",
        "auto_block": False,
        "cooldown_seconds": 300,
    },
    {
        "name": "SSRF Attempt",
        "description": "Server-Side Request Forgery payload targeting metadata endpoints.",
        "match_severity": "critical",
        "match_attack_type": "ssrf",
        "min_confidence": 0.80,
        "min_session_score": 0,
        "notification_channel": "both",
        "auto_block": True,
        "cooldown_seconds": 120,
    },
    {
        "name": "Brute Force Escalation",
        "description": "Session score crossed 60 due to brute force activity.",
        "match_severity": "high",
        "match_attack_type": "brute_force",
        "min_confidence": 0.0,
        "min_session_score": 60,
        "notification_channel": "slack",
        "auto_block": False,
        "cooldown_seconds": 600,
    },
    {
        "name": "Deserialization Exploit",
        "description": "Java/PHP/Python deserialization payload detected.",
        "match_severity": "critical",
        "match_attack_type": "deserialization",
        "min_confidence": 0.70,
        "min_session_score": 0,
        "notification_channel": "both",
        "auto_block": True,
        "cooldown_seconds": 60,
    },
    {
        "name": "High Session Score Warning",
        "description": "Any session that accumulates a score over 80.",
        "match_severity": "",
        "match_attack_type": "",
        "min_confidence": 0.0,
        "min_session_score": 80,
        "notification_channel": "slack",
        "auto_block": False,
        "cooldown_seconds": 900,
    },
]


class Command(BaseCommand):
    help = "Seed the database with default SIEM alert rules."

    def handle(self, *args, **options):
        created = 0
        for rule_data in DEFAULT_RULES:
            if AlertRule.objects.filter(name=rule_data["name"]).exists():
                self.stdout.write(f'  skip  {rule_data["name"]}')
                continue
            AlertRule.objects.create(**rule_data)
            self.stdout.write(self.style.SUCCESS(f'  created  {rule_data["name"]}'))
            created += 1

        self.stdout.write(self.style.SUCCESS(f"\nDone. {created} rule(s) created."))
