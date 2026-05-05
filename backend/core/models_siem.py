"""
Additional models for the transparent proxy + SIEM layer.
"""

import uuid
import bcrypt
from django.db import models
from django.utils import timezone


class RealBankUserManager(models.Manager):
    def create_user(
        self,
        username,
        password=None,
        email="",
        full_name="",
        account_number=None,
        **extra_fields,
    ):
        if not username:
            raise ValueError("The Username field must be set")
        if not password:
            raise ValueError("The Password field must be set")

        password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt(rounds=12)
        ).decode("utf-8")

        if not account_number:
            import random

            account_number = f"RB{random.randint(1000000000, 9999999999)}"

        user = self.model(
            username=username,
            password_hash=password_hash,
            email=email,
            full_name=full_name,
            account_number=account_number,
            **extra_fields,
        )
        user.save(using=self._db)
        return user


class RealBankUser(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=150, unique=True, db_index=True)
    password_hash = models.CharField(max_length=256)
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=200)
    account_number = models.CharField(max_length=20, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)

    objects = RealBankUserManager()

    class Meta:
        db_table = "real_bank_users"

    def __str__(self):
        return f"{self.username} ({self.account_number})"

    def check_password(self, raw_password):
        if not raw_password:
            return False
        return bcrypt.checkpw(
            raw_password.encode("utf-8"), self.password_hash.encode("utf-8")
        )

    @property
    def first_name(self):
        parts = self.full_name.split(" ", 1)
        return parts[0] if parts else ""

    @property
    def last_name(self):
        parts = self.full_name.split(" ", 1)
        return parts[1] if len(parts) > 1 else ""

    @property
    def date_joined(self):
        return self.created_at


class SiemAlert(models.Model):
    SEVERITY_CHOICES = [
        ("info", "Info"),
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    DECISION_CHOICES = [
        ("ALLOW", "Allowed to real app"),
        ("DECEIVE", "Routed to honeypot"),
        ("BLOCK", "Blocked"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    fingerprint = models.CharField(max_length=64, db_index=True, blank=True)
    session = models.ForeignKey(
        "AttackerSession",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="siem_alerts",
    )

    attack_type = models.CharField(max_length=60, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    confidence = models.FloatField(default=0.0)
    session_score = models.IntegerField(default=0)
    routing_decision = models.CharField(max_length=10, choices=DECISION_CHOICES)

    patterns_matched = models.JSONField(default=list)
    iocs = models.JSONField(default=list)
    is_brute_force = models.BooleanField(default=False)
    is_burst = models.BooleanField(default=False)

    is_acknowledged = models.BooleanField(default=False, db_index=True)
    acknowledged_by = models.ForeignKey(
        "MonitorUser",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="acknowledged_alerts",
    )
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    analyst_note = models.TextField(blank=True)

    class Meta:
        db_table = "siem_alerts"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["severity", "timestamp"]),
            models.Index(fields=["attack_type", "timestamp"]),
            models.Index(fields=["is_acknowledged", "severity"]),
        ]

    def __str__(self):
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} {self.severity} {self.attack_type}"


class LoginAttempt(models.Model):
    OUTCOME_CHOICES = [
        ("routed_real", "Routed to real application"),
        ("routed_honeypot", "Routed to honeypot"),
        ("blocked", "Blocked"),
        ("real_success", "Successful real login"),
        ("real_failure", "Failed real login"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    fingerprint = models.CharField(max_length=64, blank=True, db_index=True)
    username = models.CharField(max_length=500)
    user_agent = models.TextField(blank=True)
    outcome = models.CharField(max_length=30, choices=OUTCOME_CHOICES)
    siem_score_delta = models.IntegerField(default=0)
    session_score = models.IntegerField(default=0)
    attack_type = models.CharField(max_length=60, default="none")
    confidence = models.FloatField(default=0.0)

    class Meta:
        db_table = "login_attempts"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["ip_address", "timestamp"]),
            models.Index(fields=["outcome", "timestamp"]),
        ]

    def __str__(self):
        return f"{self.ip_address} {self.username} → {self.outcome}"


class AlertRule(models.Model):
    CHANNEL_CHOICES = [
        ("slack", "Slack"),
        ("email", "Email"),
        ("both", "Slack + Email"),
        ("db", "Database only"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)

    match_severity = models.CharField(
        max_length=20, blank=True, help_text="Leave blank to match all severities."
    )
    match_attack_type = models.CharField(
        max_length=60, blank=True, help_text="Leave blank to match all types."
    )
    min_confidence = models.FloatField(default=0.0)
    min_session_score = models.IntegerField(default=0)

    notification_channel = models.CharField(
        max_length=10, choices=CHANNEL_CHOICES, default="db"
    )
    auto_block = models.BooleanField(
        default=False, help_text="Automatically block matching sessions."
    )
    cooldown_seconds = models.IntegerField(default=300)

    created_at = models.DateTimeField(default=timezone.now)
    created_by = models.ForeignKey("MonitorUser", null=True, on_delete=models.SET_NULL)

    class Meta:
        db_table = "alert_rules"
        ordering = ["-created_at"]

    def __str__(self):
        return self.name

    def matches(self, alert: SiemAlert) -> bool:
        if self.match_severity and alert.severity != self.match_severity:
            return False
        if self.match_attack_type and alert.attack_type != self.match_attack_type:
            return False
        if alert.confidence < self.min_confidence:
            return False
        if alert.session_score < self.min_session_score:
            return False
        return True
