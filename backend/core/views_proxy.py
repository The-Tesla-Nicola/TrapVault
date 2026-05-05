"""
Transparent Authentication Proxy
"""

import json
import time
import logging
import random
import string

import bcrypt

from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.utils import timezone

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from core.models import RealBankUser, LoginAttempt, AttackerSession
from core.siem.engine import siem, ROUTE_ALLOW, ROUTE_DECEIVE, ROUTE_BLOCK
from core.siem.alerts import alert_manager
from core.siem.signatures import fingerprint_session

logger = logging.getLogger("honeypot.proxy")

_DUMMY_HASH = b"$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8oDr1Iy.fWd4lW/OsaW"

_FAKE_JWT = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
    ".eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluaXN0cmF0b3IifQ"
    ".FAKE_SIGNATURE_HONEYPOT_DO_NOT_USE"
)


def _get_ip(request) -> str:
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "0.0.0.0")


def _extract_headers(request) -> dict:
    h = {}
    for k, v in request.META.items():
        if k.startswith("HTTP_") or k in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            h[k] = str(v)
    return h


def _verify_password(plain: str, stored_hash: str) -> bool:
    """bcrypt verify – returns False on any exception."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), stored_hash.encode("utf-8"))
    except Exception:
        return False


def _issue_real_jwt(user: RealBankUser) -> str:
    """Issue a short-lived JWT for authenticated real-bank users."""
    import jwt as pyjwt
    from datetime import datetime, timedelta

    secret = settings.HONEYPOT_CONFIG.get("REAL_BANK_JWT_SECRET", settings.SECRET_KEY)
    now = datetime.utcnow()
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "account": user.account_number,
        "type": "real_bank_access",
        "iat": now,
        "exp": now + timedelta(hours=8),
    }
    return pyjwt.encode(payload, secret, algorithm="HS256")


@csrf_exempt
@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def proxy_login(request):
    """
    Transparent authentication proxy.
    GET requests return the login page metadata (for SPA bootstrapping).
    POST requests are classified and routed.
    """
    if request.method == "GET":
        return Response(
            {
                "app": "SecureBank Online Banking",
                "version": "4.2.1",
                "csrf_required": False,
                "mfa_enabled": True,
            }
        )

    ip = _get_ip(request)
    ua = request.META.get("HTTP_USER_AGENT", "")
    fp = fingerprint_session(
        ip,
        ua,
        request.META.get("HTTP_ACCEPT_LANGUAGE", ""),
        request.META.get("HTTP_ACCEPT_ENCODING", ""),
    )

    username = request.data.get("username", "").strip()
    password = request.data.get("password", "")

    siem_result = siem.evaluate_login(
        ip=ip,
        ua=ua,
        username=username,
        password=password,
        path=request.path,
    )
    siem_result["headers"] = _extract_headers(request)

    decision = siem_result["decision"]
    score = siem_result["session_score"]

    try:
        session_obj = AttackerSession.objects.filter(fingerprint=fp).first()
        alert_manager.process(siem_result, str(session_obj.id) if session_obj else None)
    except Exception as exc:
        logger.debug("_fire_alert suppressed: %s", exc)

    if decision == ROUTE_BLOCK:
        _record_attempt(ip, fp, username, ua, "blocked", siem_result)
        return Response(
            {"error": "Too many requests. Please try again later."}, status=429
        )

    if decision == ROUTE_DECEIVE:
        _record_attempt(ip, fp, username, ua, "routed_honeypot", siem_result)

        delay = 0.8 + (score % 10) * 0.15
        time.sleep(min(delay, 4.0))

        sqli_markers = ["'", '"', "--", "or 1=1", "union", "select"]
        if any(m in username.lower() + password.lower() for m in sqli_markers):
            return Response(
                {
                    "status": "error",
                    "code": 500,
                    "message": "Internal server error: database query failed.",
                    "debug": (
                        f"Query: SELECT id, username, role FROM bank_users "
                        f"WHERE username='{username}' AND password_hash=MD5('{password}') LIMIT 1"
                    ),
                    "trace": "MySQLSyntaxErrorException at line 47",
                },
                status=500,
            )

        common = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("administrator", "administrator"),
        ]
        if (username.lower(), password.lower()) in common:
            import string

            rand_token = "".join(
                random.choices(string.ascii_letters + string.digits, k=64)
            )
            return Response(
                {
                    "status": "success",
                    "message": "Authentication successful.",
                    "access_token": _FAKE_JWT,
                    "refresh_token": rand_token,
                    "expires_in": 900,
                    "user": {
                        "id": 1,
                        "username": username,
                        "role": "administrator",
                        "email": f"{username}@securebank.internal",
                        "permissions": ["read", "write", "admin", "export"],
                        "last_login": "2024-01-14T23:47:12Z",
                    },
                    "mfa_required": True,
                    "mfa_token": rand_token[:16],
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

    _record_attempt(ip, fp, username, ua, "routed_real", siem_result)

    try:
        user = RealBankUser.objects.get(username__iexact=username, is_active=True)
        password_ok = _verify_password(password, user.password_hash)
    except RealBankUser.DoesNotExist:
        bcrypt.checkpw(b"dummy", _DUMMY_HASH)
        password_ok = False
        user = None

    if not password_ok:
        fail_count = siem.record_failed_login(fp)
        if fail_count >= int(getattr(settings, "SIEM_BRUTE_LIMIT", 8)):
            siem.force_deceive(fp)

        _update_attempt_outcome(ip, fp, username, "real_failure")
        return Response(
            {
                "status": "error",
                "message": "Invalid username or password.",
            },
            status=401,
        )

    user.last_login = timezone.now()
    user.last_login_ip = ip
    user.save(update_fields=["last_login", "last_login_ip"])
    _update_attempt_outcome(ip, fp, username, "real_success")

    return Response(
        {
            "status": "success",
            "message": "Authentication successful.",
            "access_token": _issue_real_jwt(user),
            "expires_in": 28800,
            "user": {
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "name": user.full_name,
                "account": user.account_number,
            },
            "redirect": "L3JlYWwtc2l0ZS8=",
        }
    )


def _record_attempt(ip, fp, username, ua, outcome, siem_result):
    try:
        LoginAttempt.objects.create(
            ip_address=ip,
            fingerprint=fp,
            username=username[:500],
            user_agent=ua[:500],
            outcome=outcome,
            siem_score_delta=siem_result.get("delta", 0),
            session_score=siem_result.get("session_score", 0),
            attack_type=siem_result.get("attack_type", "none"),
            confidence=siem_result.get("confidence", 0.0),
        )
    except Exception as exc:
        logger.error("Failed to record login attempt: %s", exc)


def _update_attempt_outcome(ip: str, fp: str, username: str, outcome: str) -> None:
    try:
        updated = (
            LoginAttempt.objects.filter(
                ip_address=ip,
                fingerprint=fp,
                username=username,
                outcome="routed_real",
            )
            .order_by("-timestamp")
            .first()
        )

        if updated:
            updated.outcome = outcome
            updated.save(update_fields=["outcome"])
    except Exception as exc:
        logger.error("Failed to update attempt outcome: %s", exc)
