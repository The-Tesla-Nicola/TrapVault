from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import (
    MonitorUser,
    AttackerSession,
    AttackEvent,
    CapturedCredential,
    DeceptionAsset,
    DeceptionInteraction,
    MonitorAuditLog,
    RealBankUser,
    SiemAlert,
    LoginAttempt,
    AlertRule,
)


@admin.register(MonitorUser)
class MonitorUserAdmin(UserAdmin):
    list_display = [
        "username",
        "email",
        "role",
        "is_active",
        "last_login",
        "last_login_ip",
    ]
    list_filter = ["role", "is_active", "mfa_enabled"]
    fieldsets = UserAdmin.fieldsets + (
        (
            "Security Role",
            {
                "fields": (
                    "role",
                    "mfa_enabled",
                    "last_login_ip",
                    "failed_login_attempts",
                    "locked_until",
                )
            },
        ),
    )


@admin.register(RealBankUser)
class RealBankUserAdmin(admin.ModelAdmin):
    list_display = [
        "username",
        "full_name",
        "email",
        "account_number",
        "is_active",
        "last_login",
    ]
    list_filter = ["is_active"]
    search_fields = ["username", "email", "full_name", "account_number"]
    readonly_fields = [
        "id",
        "password_hash",
        "created_at",
        "last_login",
        "last_login_ip",
    ]


@admin.register(SiemAlert)
class SiemAlertAdmin(admin.ModelAdmin):
    list_display = [
        "timestamp",
        "attack_type",
        "severity",
        "confidence",
        "session_score",
        "routing_decision",
        "is_acknowledged",
    ]
    list_filter = [
        "severity",
        "attack_type",
        "routing_decision",
        "is_acknowledged",
        "is_brute_force",
        "is_burst",
    ]
    search_fields = ["fingerprint", "attack_type"]
    readonly_fields = ["id", "timestamp", "fingerprint", "patterns_matched", "iocs"]
    ordering = ["-timestamp"]

    def has_add_permission(self, request):
        return False


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = [
        "timestamp",
        "ip_address",
        "username",
        "outcome",
        "attack_type",
        "session_score",
        "confidence",
    ]
    list_filter = ["outcome", "attack_type"]
    search_fields = ["ip_address", "username", "fingerprint"]
    readonly_fields = ["id", "timestamp"]
    ordering = ["-timestamp"]

    def has_add_permission(self, request):
        return False


@admin.register(AlertRule)
class AlertRuleAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "match_severity",
        "match_attack_type",
        "notification_channel",
        "auto_block",
        "is_active",
    ]
    list_filter = ["is_active", "notification_channel", "auto_block"]
    search_fields = ["name", "description"]


@admin.register(AttackerSession)
class AttackerSessionAdmin(admin.ModelAdmin):
    list_display = [
        "ip_address",
        "country_code",
        "threat_level",
        "threat_score",
        "total_requests",
        "is_blocked",
        "first_seen",
    ]
    list_filter = ["threat_level", "is_blocked", "country_code", "is_tor", "is_vpn"]
    search_fields = ["ip_address", "fingerprint"]
    readonly_fields = ["id", "fingerprint", "first_seen", "browser_fingerprint"]
    ordering = ["-threat_score"]


@admin.register(AttackEvent)
class AttackEventAdmin(admin.ModelAdmin):
    list_display = ["timestamp", "session", "method", "attack_type", "severity", "path"]
    list_filter = ["attack_type", "severity", "method"]
    search_fields = ["path", "body", "session__ip_address"]
    readonly_fields = ["id", "timestamp", "detected_patterns", "ioc_extracted"]
    ordering = ["-timestamp"]


@admin.register(CapturedCredential)
class CapturedCredentialAdmin(admin.ModelAdmin):
    list_display = [
        "timestamp",
        "session",
        "username",
        "credential_type",
        "is_default_credential",
        "password_strength",
    ]
    list_filter = ["credential_type", "is_default_credential", "is_common_password"]
    search_fields = ["username"]
    readonly_fields = ["id", "timestamp", "password"]


@admin.register(MonitorAuditLog)
class MonitorAuditLogAdmin(admin.ModelAdmin):
    list_display = ["timestamp", "user", "action", "ip_address", "success"]
    list_filter = ["action", "success"]
    readonly_fields = [f.name for f in MonitorAuditLog._meta.get_fields()]
    ordering = ["-timestamp"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
