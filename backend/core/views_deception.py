"""
Deception Views
"""

import json
import random
import string
import time
import logging

from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import CapturedCredential, AttackerSession
from .threat_analyzer import ThreatAnalyzer

logger = logging.getLogger("honeypot")
_analyzer = ThreatAnalyzer()


def _add_delay(min_ms: int = None, max_ms: int = None) -> int:
    """Sleep for a random interval and return the number of ms slept."""
    cfg = settings.HONEYPOT_CONFIG
    lo = min_ms if min_ms is not None else cfg.get("DELAY_MIN_MS", 100)
    hi = max_ms if max_ms is not None else cfg.get("DELAY_MAX_MS", 3000)
    delay_ms = random.randint(lo, hi)
    time.sleep(delay_ms / 1000.0)
    return delay_ms


def _fake_token(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choices(alphabet, k=length))


def _fake_api_key() -> str:
    prefix = random.choice(["sk_live_", "sk_prod_", "api_", "key_"])
    return prefix + _fake_token(32)


def _fake_jwt() -> str:
    header = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
    payload = (
        "eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluaXN0cmF0b3IifQ"
    )
    sig = _fake_token(43)
    return "{}.{}.{}".format(header, payload, sig)


def _get_session(request):
    """Return the AttackerSession attached by middleware (may be None)."""
    return getattr(request, "_hp_session", None)


def _save_credentials(request, username: str, password: str, event=None):
    """Persist captured credentials for later analysis."""
    session = _get_session(request)
    if not session:
        return
    analysis = _analyzer.analyze_credentials(username, password)
    try:
        CapturedCredential.objects.create(
            session=session,
            event=event,
            username=str(username)[:500],
            password=str(password)[:500],
            is_default_credential=analysis["is_default"],
            is_common_password=analysis["is_common_password"],
            password_strength=analysis["password_strength"],
            credential_type=analysis["credential_type"],
        )
    except Exception as exc:
        logger.error("Failed to save credential: %s", exc)


@csrf_exempt
@api_view(["POST", "GET"])
@permission_classes([AllowAny])
def fake_login_stage1(request):
    """
    Primary login endpoint. Returns fabricated SQL error fragments for
    injection attempts to encourage deeper probing, or a fake JWT for
    common default credentials.
    """
    _add_delay(200, 1800)

    data = request.data or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))

    _save_credentials(request, username, password)

    sqli_markers = ["'", '"', "--", "#", "/*", "or 1=1", "union", "select", "drop"]
    has_sqli = any(m in username.lower() + password.lower() for m in sqli_markers)

    if has_sqli:
        return Response(
            {
                "status": "error",
                "code": 500,
                "message": "Internal server error: database query failed.",
                "debug": (
                    "Query: SELECT id, username, role FROM users "
                    "WHERE username='{}' AND password_hash=MD5('{}') LIMIT 1"
                ).format(username, password),
                "hint": "Database error logged. Contact support.",
            },
            status=500,
        )

    if (username.lower(), password.lower()) in [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "root"),
        ("administrator", "administrator"),
    ]:
        return Response(
            {
                "status": "success",
                "message": "Authentication successful.",
                "access_token": _fake_jwt(),
                "refresh_token": _fake_token(64),
                "expires_in": 900,
                "user": {
                    "id": 1,
                    "username": username,
                    "role": "administrator",
                    "email": "{}@securebank.internal".format(username),
                    "permissions": ["read", "write", "admin"],
                    "last_login": "2024-01-14T23:47:12Z",
                },
                "mfa_required": True,
                "mfa_token": _fake_token(16),
            }
        )

    return Response(
        {
            "status": "error",
            "code": 401,
            "message": "Invalid username or password.",
            "attempts_remaining": random.randint(2, 4),
            "lockout_warning": True,
        },
        status=401,
    )


@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def fake_mfa_verify(request):
    """Fake MFA verification step. Keeps the attacker engaged."""
    _add_delay(500, 2000)
    code = str(request.data.get("code", ""))
    mfa_token = str(request.data.get("mfa_token", ""))

    if code in ["000000", "123456", "999999"]:
        return Response(
            {
                "status": "success",
                "message": "MFA verification successful.",
                "session_token": _fake_jwt(),
                "redirect": "/dashboard/",
            }
        )

    return Response(
        {
            "status": "error",
            "message": "Invalid verification code.",
            "attempts_remaining": random.randint(1, 3),
        },
        status=401,
    )


@csrf_exempt
@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def fake_admin_dashboard(request, *args, **kwargs):
    """Fake admin dashboard – API response variant."""
    _add_delay(300, 1200)

    auth = request.headers.get("Authorization", "")

    if "Bearer" in auth or "Token" in auth:
        return Response(
            {
                "status": "success",
                "dashboard": {
                    "total_users": 14823,
                    "active_sessions": 347,
                    "revenue_today": "$128,442.00",
                    "pending_transactions": 23,
                    "system_alerts": 0,
                    "last_backup": "2024-01-15T03:00:00Z",
                },
                "quick_links": [
                    "/api/admin/users/",
                    "/api/admin/settings/",
                    "/api/admin/database/",
                    "/api/admin/api-keys/",
                    "/api/admin/backup/",
                ],
                "system_info": {
                    "version": "3.1.4",
                    "build": "20240115",
                    "environment": "production",
                    "debug_mode": True,
                },
            }
        )

    return Response(
        {
            "status": "error",
            "message": "Authentication required.",
            "hint": "POST credentials to /api/auth/login/ to obtain a Bearer token.",
        },
        status=401,
    )


@csrf_exempt
@api_view(["GET", "POST", "DELETE"])
@permission_classes([AllowAny])
def fake_admin_users(request, *args, **kwargs):
    """Fake user management endpoint. Appears to expose the user database."""
    _add_delay(400, 1500)

    fake_users = [
        {
            "id": 1,
            "username": "admin",
            "email": "admin@securebank.internal",
            "role": "administrator",
            "status": "active",
            "created": "2020-01-01",
        },
        {
            "id": 2,
            "username": "john.doe",
            "email": "jdoe@securebank.internal",
            "role": "manager",
            "status": "active",
            "created": "2021-03-14",
        },
        {
            "id": 3,
            "username": "jane.smith",
            "email": "jsmith@securebank.internal",
            "role": "analyst",
            "status": "active",
            "created": "2021-06-22",
        },
        {
            "id": 4,
            "username": "backup_admin",
            "email": "backup@securebank.internal",
            "role": "administrator",
            "status": "inactive",
            "created": "2019-11-01",
        },
        {
            "id": 5,
            "username": "svc_account",
            "email": "svc@securebank.internal",
            "role": "service",
            "status": "active",
            "created": "2020-05-30",
        },
    ]

    return Response(
        {
            "status": "success",
            "data": fake_users,
            "total": len(fake_users),
            "page": 1,
            "per_page": 50,
            "_debug": {
                "query": "SELECT * FROM auth_users ORDER BY id LIMIT 50 OFFSET 0",
                "execution_time_ms": round(random.uniform(1.2, 8.9), 3),
            },
        }
    )


@csrf_exempt
@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def fake_admin_settings(request, *args, **kwargs):
    """Fake system settings – API variant."""
    _add_delay(300, 1000)
    return Response(
        {
            "status": "success",
            "config": {
                "maintenance_mode": False,
                "allow_registration": False,
                "mfa_enforced": True,
                "session_timeout": 3600,
                "encryption_level": "AES-256-GCM",
            },
        }
    )


@csrf_exempt
@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def fake_admin_api_keys(request, *args, **kwargs):
    """Fake API key management."""
    _add_delay(300, 1500)
    return Response(
        {
            "status": "success",
            "api_keys": [
                {
                    "id": "key_live_7f3a",
                    "name": "Production Secret",
                    "created": "2023-12-01",
                },
                {
                    "id": "key_test_2b91",
                    "name": "Staging Sandbox",
                    "created": "2024-01-10",
                },
            ],
        }
    )


@csrf_exempt
@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def fake_admin_db_console(request, *args, **kwargs):
    """Fake SQL console."""
    _add_delay(500, 2000)
    return Response(
        {
            "status": "success",
            "query_executed": request.data.get("query", "SELECT 1"),
            "rows": 1,
            "data": [{"result": 1}],
        }
    )


@csrf_exempt
@api_view(["GET"])
@permission_classes([AllowAny])
def fake_admin_file_browser(request, *args, **kwargs):
    """Fake file browser."""
    _add_delay(200, 800)
    return Response(
        {"status": "success", "files": [".env", "config.php", "database.sql"]}
    )


@csrf_exempt
@api_view(["GET"])
@permission_classes([AllowAny])
def fake_admin_download(request):
    """Fake file download."""
    filename = request.GET.get("file", ".env")
    if "../" in filename:
        return Response({"error": "Path traversal detected"}, status=403)
    return Response(
        {"status": "success", "content": "FAKE FILE CONTENT FOR " + filename}
    )


@csrf_exempt
@api_view(["GET"])
@permission_classes([AllowAny])
def fake_admin_backup(request, *args, **kwargs):
    """Fake backup listing."""
    return Response(
        {"status": "success", "backups": ["backup_20240101.sql", "backup_20240115.sql"]}
    )


@csrf_exempt
@api_view(["GET"])
@permission_classes([AllowAny])
def fake_internal_config(request, *args, **kwargs):
    """
    Fake internal configuration endpoint. Returns fabricated secrets
    designed to look like real credentials; all values are dummy data.
    """
    _add_delay(1000, 3000)

    return Response(
        {
            "status": "success",
            "config": {
                "app": {
                    "name": "SecureBank",
                    "version": "3.1.4",
                    "environment": "production",
                    "debug": True,
                },
                "database": {
                    "primary": {
                        "host": "db-primary.internal.securebank.local",
                        "port": 5432,
                        "name": "securebank_prod",
                        "user": "app_user",
                        "password": "Pr0d_Db_P@ssw0rd_2024!",
                    },
                    "replica": {
                        "host": "db-replica.internal.securebank.local",
                        "port": 5432,
                    },
                },
                "redis": {
                    "host": "redis.internal.securebank.local",
                    "port": 6379,
                    "password": "R3d1s_Str0ng_P@ss_2024",
                },
                "aws": {
                    "region": "us-east-1",
                    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "s3_bucket": "securebank-prod-data-7f3a",
                },
                "secrets": {
                    "jwt_secret": "super_secret_jwt_key_2024_production_DO_NOT_SHARE",
                    "encryption_key": "AES256_KEY_" + _fake_token(32),
                    "api_master_key": _fake_api_key(),
                    "webhook_secret": _fake_token(40),
                },
                "internal_services": {
                    "user_service": "http://user-svc.internal:8080",
                    "payment_service": "http://payment-svc.internal:8081",
                    "notification_service": "http://notify-svc.internal:8082",
                    "reporting_service": "http://report-svc.internal:8083",
                },
            },
            "_warning": "INTERNAL CONFIGURATION – DO NOT EXPOSE TO EXTERNAL NETWORKS",
        }
    )


@csrf_exempt
@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def fake_api_keys(request):
    """Fake API key management. Generates plausible-looking keys on POST."""
    _add_delay(300, 1500)

    if request.method == "POST":
        return Response(
            {
                "status": "success",
                "api_key": {
                    "id": "key_" + _fake_token(16),
                    "secret": _fake_api_key(),
                    "created_at": "2024-01-15T12:00:00Z",
                    "permissions": ["read", "write", "admin"],
                },
                "warning": "Store this secret securely – it will not be shown again.",
            }
        )

    return Response(
        {
            "status": "success",
            "api_keys": [
                {
                    "id": "key_prod_001",
                    "name": "Production API Key",
                    "prefix": "sk_live_xxxx",
                    "created_at": "2023-06-15",
                    "last_used": "2024-01-15",
                    "permissions": ["all"],
                },
                {
                    "id": "key_dev_001",
                    "name": "Development Key",
                    "prefix": "sk_test_xxxx",
                    "created_at": "2023-08-20",
                    "last_used": "2024-01-10",
                    "permissions": ["read"],
                },
            ],
        }
    )


@csrf_exempt
@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def fake_database_console(request):
    """Fake database query interface. Echoes SQL back with fake results."""
    _add_delay(500, 2500)

    query = ""
    if request.method == "POST":
        query = str(request.data.get("query", request.data.get("q", "")))
    else:
        query = request.GET.get("q", request.GET.get("query", "SELECT 1"))

    fake_result = [
        {
            "id": 1,
            "username": "admin",
            "email": "admin@securebank.internal",
            "role": "admin",
        },
        {
            "id": 2,
            "username": "john.doe",
            "email": "jdoe@securebank.internal",
            "role": "user",
        },
    ]

    return Response(
        {
            "status": "success",
            "query_executed": query,
            "rows_returned": len(fake_result),
            "execution_time_ms": round(random.uniform(0.8, 12.4), 3),
            "data": fake_result,
            "_connection": {
                "host": "db-primary.internal.securebank.local",
                "database": "securebank_prod",
                "user": "app_user",
            },
        }
    )


@csrf_exempt
@api_view(["GET"])
@permission_classes([AllowAny])
def fake_file_browser(request):
    """Fake file browser listing. Includes enticing file names."""
    _add_delay(300, 1000)

    path = request.GET.get("path", "/var/www/securebank/")

    fake_listing = [
        {
            "name": "config.php",
            "type": "file",
            "size": "4.2 KB",
            "modified": "2024-01-10",
        },
        {
            "name": "database_backup.sql.gz",
            "type": "file",
            "size": "2.1 GB",
            "modified": "2024-01-15",
        },
        {"name": ".env", "type": "file", "size": "1.1 KB", "modified": "2024-01-01"},
        {
            "name": "users_export.csv",
            "type": "file",
            "size": "156 MB",
            "modified": "2024-01-14",
        },
        {
            "name": "ssl_certificates/",
            "type": "dir",
            "size": "-",
            "modified": "2023-12-01",
        },
        {"name": "logs/", "type": "dir", "size": "-", "modified": "2024-01-15"},
        {"name": "private_keys/", "type": "dir", "size": "-", "modified": "2023-06-15"},
    ]

    return Response(
        {
            "status": "success",
            "path": path,
            "files": fake_listing,
            "total": len(fake_listing),
        }
    )


@csrf_exempt
@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def fake_file_download(request, name=None):
    """
    Fake file download endpoint. Returns plausible-looking config content.
    Path traversal attempts receive a misleading 'error' to encourage retries.
    """
    _add_delay(800, 2000)

    filename = (
        name
        or request.GET.get("file", "")
        or request.GET.get("path", "")
        or request.GET.get("name", ".env")
    )

    if "../" in filename or ".." in filename:
        return Response(
            {
                "status": "error",
                "message": "Error reading file: {}".format(filename),
                "error": "Permission denied: /var/www/securebank/../../{}".format(
                    filename.replace("../", "")
                ),
                "_debug": "Path traversal not blocked – access control misconfigured.",
            },
            status=403,
        )

    if filename.endswith(".env") or filename == ".env":
        content = (
            "# SecureBank Production Environment\n"
            "APP_ENV=production\n"
            "APP_KEY={}\n"
            "DB_HOST=db-primary.internal.securebank.local\n"
            "DB_DATABASE=securebank_prod\n"
            "DB_USERNAME=app_user\n"
            "DB_PASSWORD=Pr0d_Db_P@ssw0rd_2024!\n"
            "REDIS_PASSWORD=R3d1s_Str0ng_P@ss_2024\n"
            "STRIPE_SECRET=sk_live_{}\n"
            "SENDGRID_API_KEY=SG.{}\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        ).format(_fake_token(32), _fake_token(24), _fake_token(40))

        return Response({"status": "success", "filename": filename, "content": content})

    return Response(
        {
            "status": "success",
            "filename": filename,
            "content": "# File content for {}".format(filename),
            "download_url": "/api/admin/download/?file={}".format(filename),
        }
    )


@csrf_exempt
@api_view(["GET"])
@permission_classes([AllowAny])
def fake_backup_list(request):
    """Lists fake database backups with enticing download URLs."""
    _add_delay(500, 1500)

    return Response(
        {
            "status": "success",
            "backups": [
                {
                    "id": "bak_20240115_001",
                    "filename": "securebank_full_20240115.sql.gz",
                    "size": "2.4 GB",
                    "created_at": "2024-01-15T03:00:00Z",
                    "type": "full",
                    "download_url": "/api/admin/download/?file=securebank_full_20240115.sql.gz",
                },
                {
                    "id": "bak_20240114_001",
                    "filename": "securebank_full_20240114.sql.gz",
                    "size": "2.3 GB",
                    "created_at": "2024-01-14T03:00:00Z",
                    "type": "full",
                    "download_url": "/api/admin/download/?file=securebank_full_20240114.sql.gz",
                },
                {
                    "id": "bak_users_20240115",
                    "filename": "users_export_20240115.csv",
                    "size": "156 MB",
                    "created_at": "2024-01-15T06:00:00Z",
                    "type": "users_export",
                    "download_url": "/api/admin/download/?file=users_export_20240115.csv",
                },
            ],
            "storage_used": "47.2 GB",
            "storage_limit": "100 GB",
        }
    )


@csrf_exempt
@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def fake_search(request, *args, **kwargs):
    """Reflects the search query back to simulate an unsanitised endpoint."""
    _add_delay(200, 800)

    query = (
        request.data.get("q", "")
        or request.GET.get("q", "")
        or request.data.get("query", "")
        or request.GET.get("query", "")
    )

    return Response(
        {
            "status": "success",
            "query": query,
            "results": [
                {
                    "id": 1,
                    "title": "Result for: {}".format(query),
                    "snippet": "Lorem ipsum dolor sit amet...",
                },
                {
                    "id": 2,
                    "title": "SecureBank Account Services",
                    "snippet": "Manage your account settings...",
                },
                {
                    "id": 3,
                    "title": "Transaction History",
                    "snippet": "View all your transactions...",
                },
            ],
            "total": 3,
            "_sql": "SELECT * FROM content WHERE title LIKE '%{}%' OR body LIKE '%{}%'".format(
                query, query
            ),
        }
    )


@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def fake_password_reset(request, *args, **kwargs):
    """Captures email addresses submitted for password reset."""
    _add_delay(1000, 3000)
    email = str(request.data.get("email", ""))
    return Response(
        {
            "status": "success",
            "message": "If {} is registered, a reset link has been sent.".format(email),
            "token_preview": "reset_{}".format(_fake_token(12)),
            "expires_in": 3600,
        }
    )


@csrf_exempt
@api_view(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
@permission_classes([AllowAny])
def catch_all_api(request, path=""):
    """
    Handles any API path not matched by a specific trap.
    Returns a realistic 404 with a list of 'available' endpoints to
    guide attackers toward the real traps.
    """
    _add_delay(100, 600)

    return Response(
        {
            "status": "error",
            "code": 404,
            "message": "Endpoint not found: /api/{}".format(path),
            "available_endpoints": [
                "/api/auth/login/",
                "/api/auth/verify/",
                "/api/admin/dashboard/",
                "/api/admin/users/",
                "/api/admin/settings/",
                "/api/admin/database/",
                "/api/admin/api-keys/",
                "/api/admin/backup/",
                "/api/admin/files/",
                "/api/internal/config/",
                "/api/search/",
                "/api/password-reset/",
            ],
        },
        status=404,
    )
