import uuid
import hashlib
import json

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.conf import settings

from .models_siem import RealBankUser, SiemAlert, LoginAttempt, AlertRule

__all__ = [
    "MonitorUser",
    "AttackerSession",
    "AttackEvent",
    "CapturedCredential",
    "DeceptionAsset",
    "DeceptionInteraction",
    "MonitorAuditLog",
    "RealBankUser",
    "SiemAlert",
    "LoginAttempt",
    "AlertRule",
    "SOARAction",
    "MLTrainingData",
    "ThreatIntelCache",
    "AttackerActivity",
]


class MonitorUser(AbstractUser):
    """
    Custom user model for monitoring dashboard access.
    Extends AbstractUser with role-based access control and security fields.
    """

    ROLE_CHOICES = [
        ("admin", "Administrator"),
        ("analyst", "Security Analyst"),
        ("viewer", "Viewer"),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="viewer")
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=64, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "monitor_users"
        verbose_name = "Monitor User"
        verbose_name_plural = "Monitor Users"

    def has_permission(self, permission):
        """
        Check if user has a specific permission based on their role.
        """
        # Administrators and Guests (for testing) get everything
        if self.role in ["admin", "guest"]:
            return True

        role_permissions = {
            "analyst": ["view", "analyze", "export"],
            "viewer": ["view"],
        }
        return permission in role_permissions.get(self.role, [])

    def is_locked(self):
        if self.locked_until and self.locked_until > timezone.now():
            return True
        return False


# =============================================================================
# ATTACKER SESSION
# =============================================================================


class AttackerSession(models.Model):
    """
    Tracks a unique attacker session identified by a fingerprint derived
    from IP address, User-Agent, and HTTP header characteristics.
    Stores cumulative threat scoring and behavioural metadata.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    fingerprint = models.CharField(max_length=64, unique=True, db_index=True)

    # Network identity
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.TextField(blank=True)

    # Browser fingerprint components
    browser_fingerprint = models.JSONField(default=dict, blank=True)
    tls_fingerprint = models.CharField(max_length=64, blank=True)

    # Geolocation (populated asynchronously)
    country_code = models.CharField(max_length=2, blank=True)
    country_name = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    asn = models.CharField(max_length=50, blank=True)
    asn_org = models.CharField(max_length=200, blank=True)
    isp = models.CharField(max_length=255, default="Unknown")

    # Anonymisation indicators
    is_tor = models.BooleanField(default=False)
    is_vpn = models.BooleanField(default=False)
    is_proxy = models.BooleanField(default=False)

    # Temporal metrics
    first_seen = models.DateTimeField(default=timezone.now, db_index=True)
    last_seen = models.DateTimeField(default=timezone.now)
    total_requests = models.IntegerField(default=0)
    total_time_wasted_seconds = models.IntegerField(default=0)

    # Threat assessment
    threat_score = models.IntegerField(default=0, db_index=True)
    threat_level = models.CharField(
        max_length=20,
        choices=[
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("minimal", "Minimal"),
            ("unknown", "Unknown"),
        ],
        default="minimal",
        db_index=True,
    )
    abuse_confidence_score = models.IntegerField(
        default=0, help_text="AbuseIPDB score 0-100"
    )
    attack_vectors_used = models.JSONField(default=list, blank=True)

    # Block status
    is_blocked = models.BooleanField(default=False, db_index=True)
    blocked_at = models.DateTimeField(null=True, blank=True)
    block_reason = models.TextField(blank=True)
    block_expires_at = models.DateTimeField(null=True, blank=True, db_index=True)

    # Analyst annotations
    analyst_notes = models.TextField(blank=True)
    tags = models.JSONField(default=list, blank=True)

    class Meta:
        db_table = "attacker_sessions"
        ordering = ["-last_seen"]
        indexes = [
            models.Index(fields=["ip_address", "first_seen"]),
            models.Index(fields=["threat_score"]),
            models.Index(fields=["is_blocked", "last_seen"]),
        ]

    def __str__(self):
        return "{} ({}) score={}".format(
            self.ip_address, self.threat_level, self.threat_score
        )

    def update_threat_score(self, attack_type):
        weights = settings.HONEYPOT_CONFIG["THREAT_WEIGHTS"]
        delta = weights.get(attack_type, 2)
        self.threat_score += delta

        if attack_type not in self.attack_vectors_used:
            self.attack_vectors_used = self.attack_vectors_used + [attack_type]

        # Recalculate threat level
        if self.threat_score >= 100:
            self.threat_level = "critical"
        elif self.threat_score >= 70:
            self.threat_level = "high"
        elif self.threat_score >= 40:
            self.threat_level = "medium"
        elif self.threat_score >= 10:
            self.threat_level = "low"
        else:
            self.threat_level = "minimal"

        # Auto-block
        threshold = settings.HONEYPOT_CONFIG.get("AUTO_BLOCK_THRESHOLD", 100)
        if self.threat_score >= threshold and not self.is_blocked:
            self.is_blocked = True
            self.blocked_at = timezone.now()
            self.block_reason = "Auto-blocked: threat score {}".format(
                self.threat_score
            )

        self.last_seen = timezone.now()
        self.save()
        # Increment total_requests atomically after save to avoid F() + save() conflict
        AttackerSession.objects.filter(pk=self.pk).update(
            total_requests=models.F("total_requests") + 1
        )

    def add_wasted_time(self, seconds):
        AttackerSession.objects.filter(pk=self.pk).update(
            total_time_wasted_seconds=models.F("total_time_wasted_seconds") + seconds
        )


# =============================================================================
# ATTACK EVENT
# =============================================================================


class AttackEvent(models.Model):
    """
    A single HTTP request captured by the honeypot. Contains the full
    request payload, detected attack classification, patterns found,
    IOCs extracted, and the artificial response metadata.
    """

    SEVERITY_CHOICES = [
        ("info", "Info"),
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    ATTACK_TYPE_CHOICES = [
        ("login_attempt", "Login Attempt"),
        ("sql_injection", "SQL Injection"),
        ("xss", "Cross-Site Scripting"),
        ("command_injection", "Command Injection"),
        ("path_traversal", "Path Traversal"),
        ("ssrf", "Server-Side Request Forgery"),
        ("xxe", "XML External Entity"),
        ("brute_force", "Brute Force"),
        ("auth_bypass", "Authentication Bypass"),
        ("data_exfil", "Data Exfiltration"),
        ("reconnaissance", "Reconnaissance"),
        ("api_probe", "API Probing"),
        ("other", "Other"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(
        AttackerSession,
        on_delete=models.CASCADE,
        related_name="events",
        db_index=True,
    )
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    # Request data
    method = models.CharField(max_length=10)
    path = models.TextField()
    query_string = models.TextField(blank=True)
    headers = models.JSONField(default=dict, blank=True)
    body = models.TextField(blank=True)
    body_json = models.JSONField(null=True, blank=True)

    # Classification results
    attack_type = models.CharField(
        max_length=50, choices=ATTACK_TYPE_CHOICES, default="other", db_index=True
    )
    severity = models.CharField(
        max_length=20, choices=SEVERITY_CHOICES, default="info", db_index=True
    )
    confidence = models.FloatField(default=0.0)
    detected_patterns = models.JSONField(default=list, blank=True)
    rules_matched = models.JSONField(default=list, blank=True)
    ioc_extracted = models.JSONField(default=list, blank=True)

    # Response metadata
    response_status = models.IntegerField(default=200)
    response_delay_ms = models.IntegerField(default=0)

    class Meta:
        db_table = "attack_events"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["session", "timestamp"]),
            models.Index(fields=["attack_type", "timestamp"]),
            models.Index(fields=["severity", "timestamp"]),
        ]

    def __str__(self):
        return "{} {} {} ({})".format(
            self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            self.method,
            self.path[:60],
            self.attack_type,
        )


# =============================================================================
# CAPTURED CREDENTIAL
# =============================================================================


class CapturedCredential(models.Model):
    """
    Stores every username/password pair submitted to honeypot login endpoints.
    Includes credential analysis results (default creds, strength, type).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(
        AttackerSession,
        on_delete=models.CASCADE,
        related_name="credentials",
    )
    event = models.ForeignKey(
        AttackEvent,
        on_delete=models.CASCADE,
        related_name="credentials",
        null=True,
        blank=True,
    )
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    username = models.CharField(max_length=500)
    password = models.CharField(max_length=500)

    # Analysis
    is_default_credential = models.BooleanField(default=False)
    is_common_password = models.BooleanField(default=False)
    password_strength = models.CharField(max_length=20, default="unknown")
    credential_type = models.CharField(max_length=50, default="unknown")

    class Meta:
        db_table = "captured_credentials"
        ordering = ["-timestamp"]

    def __str__(self):
        return "{}:{} @ {}".format(
            self.username[:30],
            self.password[:30],
            self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        )


# =============================================================================
# DECEPTION ASSET
# =============================================================================


class DeceptionAsset(models.Model):
    """
    Represents a configured deception asset (honeytoken, fake file, fake
    endpoint, breadcrumb, canary token). Tracks how many times it has been
    accessed and by whom.
    """

    ASSET_TYPE_CHOICES = [
        ("endpoint", "Fake API Endpoint"),
        ("file", "Fake File"),
        ("credential", "Fake Credential"),
        ("token", "Canary Token"),
        ("breadcrumb", "Breadcrumb"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    asset_type = models.CharField(max_length=50, choices=ASSET_TYPE_CHOICES)
    description = models.TextField(blank=True)
    path = models.CharField(max_length=500, blank=True)
    content = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    access_count = models.IntegerField(default=0)

    class Meta:
        db_table = "deception_assets"
        ordering = ["-access_count"]

    def __str__(self):
        return "{} ({})".format(self.name, self.asset_type)


class DeceptionInteraction(models.Model):
    """
    Records each time an attacker interacts with a deception asset.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(
        DeceptionAsset, on_delete=models.CASCADE, related_name="interactions"
    )
    session = models.ForeignKey(
        AttackerSession, on_delete=models.CASCADE, related_name="deception_interactions"
    )
    timestamp = models.DateTimeField(default=timezone.now)
    interaction_type = models.CharField(max_length=50, default="access")
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "deception_interactions"
        ordering = ["-timestamp"]


# =============================================================================
# MONITOR AUDIT LOG
# =============================================================================


class MonitorAuditLog(models.Model):
    """
    Immutable audit trail of all actions performed by monitoring dashboard
    users. Supports compliance requirements (SOC 2, ISO 27001).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    user = models.ForeignKey(
        MonitorUser,
        on_delete=models.SET_NULL,
        null=True,
        related_name="audit_logs",
    )
    action = models.CharField(max_length=100, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    resource_type = models.CharField(max_length=50, blank=True)
    resource_id = models.CharField(max_length=100, blank=True)
    details = models.JSONField(default=dict, blank=True)
    success = models.BooleanField(default=True)

    class Meta:
        db_table = "monitor_audit_logs"
        ordering = ["-timestamp"]

    def __str__(self):
        username = self.user.username if self.user else "unknown"
        return "{} {} {}".format(
            self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            username,
            self.action,
        )


# =============================================================================
# SOAR ACTION LOG
# =============================================================================


class SOARAction(models.Model):
    """
    Audit log of all SOAR actions (automated and manual).
    Required for compliance and incident analysis.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(
        "AttackerSession", on_delete=models.CASCADE, related_name="soar_actions"
    )
    action_type = models.CharField(
        max_length=20,
        choices=[
            ("block", "Block"),
            ("unblock", "Unblock"),
            ("quarantine", "Quarantine"),
            ("alert", "Alert"),
        ],
    )
    reason = models.CharField(
        max_length=500, help_text="Human-readable reason for action"
    )
    automated = models.BooleanField(
        default=False, help_text="True if triggered by SOAR automation"
    )
    duration_hours = models.IntegerField(
        null=True, blank=True, help_text="Duration for time-limited actions"
    )
    ip_address = models.GenericIPAddressField()
    metadata = models.JSONField(
        default=dict, blank=True, help_text="Additional action metadata"
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "SOAR Action"
        verbose_name_plural = "SOAR Actions"
        indexes = [
            models.Index(fields=["-created_at", "action_type"]),
            models.Index(fields=["automated", "-created_at"]),
        ]

    def __str__(self):
        action_prefix = "🤖" if self.automated else "👤"
        return f"{action_prefix} {self.action_type.upper()}: {self.ip_address} ({self.reason})"


# =============================================================================
# ML TRAINING DATA
# =============================================================================


class MLTrainingData(models.Model):
    """
    Store feature vectors for ML model training.
    Allows periodic retraining with new data.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(
        "AttackerSession", on_delete=models.CASCADE, related_name="ml_features"
    )

    # Feature vector (6 dimensions)
    request_frequency = models.FloatField(help_text="Requests per minute")
    payload_length_avg = models.FloatField(help_text="Average payload size in bytes")
    payload_length_std = models.FloatField(help_text="Payload size standard deviation")
    unique_paths = models.IntegerField(help_text="Number of unique paths accessed")
    error_rate = models.FloatField(help_text="Proportion of 4xx/5xx responses")
    suspicious_rate = models.FloatField(
        help_text="Proportion of requests with attack signatures"
    )

    # ML prediction results
    anomaly_score = models.FloatField(
        null=True, blank=True, help_text="ML anomaly score 0-100"
    )
    is_anomaly = models.BooleanField(default=False)
    model_version = models.CharField(max_length=50, default="v1.0")

    # Label for supervised learning (optional)
    is_malicious = models.BooleanField(
        null=True, blank=True, help_text="Ground truth label"
    )

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "ML Training Data"
        verbose_name_plural = "ML Training Data"


# =============================================================================
# THREAT INTELLIGENCE CACHE
# =============================================================================


class ThreatIntelCache(models.Model):
    """
    Cache threat intelligence data to reduce API calls.
    Stores enrichment data for IPs.
    """

    ip_address = models.GenericIPAddressField(unique=True, db_index=True)

    # GeoIP data
    country = models.CharField(max_length=100, default="Unknown")
    country_code = models.CharField(max_length=2, default="XX")
    city = models.CharField(max_length=100, default="Unknown")
    latitude = models.FloatField(default=0.0)
    longitude = models.FloatField(default=0.0)
    isp = models.CharField(max_length=255, default="Unknown")

    # AbuseIPDB data
    abuse_confidence_score = models.IntegerField(default=0)
    total_reports = models.IntegerField(default=0)
    last_reported = models.DateTimeField(null=True, blank=True)

    # Computed threat level
    threat_level = models.CharField(max_length=20, default="unknown")
    risk_score = models.FloatField(default=0.0)

    # Flags
    is_tor = models.BooleanField(default=False)
    is_vpn = models.BooleanField(default=False)
    is_proxy = models.BooleanField(default=False)

    # Cache metadata
    cached_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        verbose_name = "Threat Intelligence Cache"
        verbose_name_plural = "Threat Intelligence Cache"
        indexes = [
            models.Index(fields=["expires_at"]),
            models.Index(fields=["threat_level", "-cached_at"]),
        ]

    def is_expired(self):
        from django.utils import timezone

        return timezone.now() > self.expires_at

    def __str__(self):
        return f"{self.ip_address} ({self.country}, Threat: {self.threat_level})"


# =============================================================================
# ATTACKER ACTIVITY (Telemetry)
# =============================================================================


class AttackerActivity(models.Model):
    """
    High-fidelity behavioral telemetry (keystrokes, mouse movements, clicks).
    Used for session replay and advanced forensics.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(
        AttackerSession, on_delete=models.CASCADE, related_name="activity_logs"
    )
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    event_type = models.CharField(
        max_length=20,
        choices=[
            ("keystroke", "Keystroke"),
            ("mouse_move", "Mouse Movement"),
            ("click", "Click"),
            ("scroll", "Scroll"),
            ("focus", "Focus"),
        ],
        db_index=True,
    )

    # Data payload (e.g., {x: 10, y: 20} or {key: 'Enter'})
    data = models.JSONField(default=dict, blank=True)

    # Context (e.g., '/api/login', 'password_field')
    path = models.CharField(max_length=500, blank=True)
    element_id = models.CharField(max_length=255, blank=True)

    class Meta:
        db_table = "attacker_activity"
        ordering = ["timestamp"]
        indexes = [
            models.Index(fields=["session", "timestamp"]),
            models.Index(fields=["event_type", "timestamp"]),
        ]

    def __str__(self):
        return f"{self.session_id} | {self.event_type} @ {self.timestamp}"
