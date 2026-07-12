"""
Monitor Views
"""

import jwt
import logging
from datetime import datetime, timedelta
from functools import wraps

from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.db.models import Count, Sum, Avg, Q
from django.db.models.functions import TruncDate, TruncHour
from django.utils import timezone
from django.core.paginator import Paginator

from rest_framework.decorators import (
    api_view,
    permission_classes,
    authentication_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import (
    MonitorUser,
    AttackerSession,
    AttackEvent,
    CapturedCredential,
    DeceptionAsset,
    DeceptionInteraction,
    MonitorAuditLog,
    LoginAttempt,
)

logger = logging.getLogger("honeypot")


@api_view(["GET"])
@permission_classes([AllowAny])
def api_metrics(request):
    """
    Exports system metrics in Prometheus format (OpenMetrics).
    """
    from .models import AttackerSession, AttackEvent, CapturedCredential, LoginAttempt
    from django.db.models import Count, Avg

    metrics = [
        "# HELP honeypot_total_sessions Total number of attacker sessions tracked.",
        "# TYPE honeypot_total_sessions counter",
        f"honeypot_total_sessions {AttackerSession.objects.count()}",
        "# HELP honeypot_blocked_sessions Number of sessions currently blocked.",
        "# TYPE honeypot_blocked_sessions counter",
        f"honeypot_blocked_sessions {AttackerSession.objects.filter(is_blocked=True).count()}",
        "# HELP honeypot_total_events Total number of threat events captured.",
        "# TYPE honeypot_total_events counter",
        f"honeypot_total_events {AttackEvent.objects.count()}",
        "# HELP honeypot_captured_creds Total number of credentials captured.",
        "# TYPE honeypot_captured_creds counter",
        f"honeypot_captured_creds {CapturedCredential.objects.count()}",
    ]

    metrics.append(
        "# HELP honeypot_events_by_type Number of events by attack category."
    )
    metrics.append("# TYPE honeypot_events_by_type counter")
    type_counts = AttackEvent.objects.values("attack_type").annotate(count=Count("id"))
    for entry in type_counts:
        t = entry["attack_type"]
        c = entry["count"]
        metrics.append(f'honeypot_events_by_type{{type="{t}"}} {c}')

    metrics.append(
        "# HELP honeypot_events_by_severity Number of events by severity level."
    )
    metrics.append("# TYPE honeypot_events_by_severity counter")
    sev_counts = AttackEvent.objects.values("severity").annotate(count=Count("id"))
    for entry in sev_counts:
        s = entry["severity"]
        c = entry["count"]
        metrics.append(f'honeypot_events_by_severity{{severity="{s}"}} {c}')

    metrics.append(
        "# HELP honeypot_login_outcomes Distribution of login routing decisions."
    )
    metrics.append("# TYPE honeypot_login_outcomes counter")
    outcome_counts = LoginAttempt.objects.values("outcome").annotate(count=Count("id"))
    for entry in outcome_counts:
        o = entry["outcome"]
        c = entry["count"]
        metrics.append(f'honeypot_login_outcomes{{outcome="{o}"}} {c}')

    avg_delay = (
        AttackEvent.objects.order_by("-timestamp")[:100].aggregate(
            Avg("response_delay_ms")
        )["response_delay_ms__avg"]
        or 0
    )
    metrics.append(
        "# HELP honeypot_response_time_ms_avg Average artificial response delay in ms (last 100 events)."
    )
    metrics.append("# TYPE honeypot_response_time_ms_avg gauge")
    metrics.append(f"honeypot_response_time_ms_avg {avg_delay}")

    max_score = AttackerSession.objects.aggregate(max_s=Count("threat_score"))["max_s"]

    return Response("\n".join(metrics) + "\n", content_type="text/plain; version=0.0.4")


def _generate_tokens(user):
    cfg = settings.HONEYPOT_CONFIG
    secret = cfg["MONITOR_JWT_SECRET"]
    now = datetime.utcnow()

    access_payload = {
        "user_id": str(user.id),
        "username": user.username,
        "role": user.role,
        "type": "access",
        "iat": now,
        "exp": now + cfg["MONITOR_ACCESS_TOKEN_LIFETIME"],
    }

    refresh_payload = {
        "user_id": str(user.id),
        "type": "refresh",
        "iat": now,
        "exp": now + cfg["MONITOR_REFRESH_TOKEN_LIFETIME"],
    }

    return {
        "access_token": jwt.encode(access_payload, secret, algorithm="HS256"),
        "refresh_token": jwt.encode(refresh_payload, secret, algorithm="HS256"),
        "expires_in": int(cfg["MONITOR_ACCESS_TOKEN_LIFETIME"].total_seconds()),
        "role": user.role,
    }


def _verify_access_token(token: str):
    try:
        secret = settings.HONEYPOT_CONFIG["MONITOR_JWT_SECRET"]
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        if payload.get("type") != "access":
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def _get_token_from_request(request) -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.COOKIES.get("monitor_token", "")


def monitor_auth_required(view_func):
    """Decorator that enforces monitor JWT authentication."""

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        token = _get_token_from_request(request)
        path = request.path
        is_api = "/api/" in path or "/auth/" in path

        if not token:
            if path == "/monitor/" or path == "/monitor":
                return redirect("/monitor/login/")

            if "/auth/" in path:
                if request.method == "GET":
                    return redirect("/monitor/login/")
                return JsonResponse({"error": "Authentication required."}, status=401)

            if is_api:
                return JsonResponse({"error": "Authentication required."}, status=401)

            return redirect("/monitor/login/")

        payload = _verify_access_token(token)
        if not payload:
            if not is_api and request.accepts("text/html"):
                return redirect("/monitor/login/")
            return JsonResponse(
                {
                    "error": "Invalid or expired token.",
                    "detail": "The provided JWT could not be decoded or has expired.",
                },
                status=401,
            )

        try:
            from .models import MonitorUser

            request.monitor_user = MonitorUser.objects.get(id=payload["user_id"])
        except MonitorUser.DoesNotExist:
            return JsonResponse(
                {
                    "error": "User not found.",
                    "detail": f"MonitorUser with ID {payload.get('user_id')} does not exist.",
                },
                status=401,
            )

        return view_func(request, *args, **kwargs)

    return wrapper


def _log_audit(
    user, action, request, resource_type="", resource_id="", details=None, success=True
):
    try:
        ip = request.META.get(
            "HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "")
        )
        if "," in ip:
            ip = ip.split(",")[0].strip()
        MonitorAuditLog.objects.create(
            user=user,
            action=action,
            ip_address=ip or None,
            resource_type=resource_type,
            resource_id=str(resource_id),
            details=details or {},
            success=success,
        )
    except Exception as exc:
        logger.error("Audit log failed: %s", exc)


@csrf_exempt
@api_view(["POST", "GET"])
@permission_classes([AllowAny])
def monitor_login(request):
    """Authenticate a monitor user and return JWT tokens."""
    if request.method == "GET":
        from django.http import HttpResponseRedirect

        return HttpResponseRedirect("/monitor/login/")

    username = request.data.get("username", "").strip()
    password = request.data.get("password", "")

    if not username or not password:
        return Response({"error": "Username and password are required."}, status=400)

    try:
        user = MonitorUser.objects.get(username=username)
    except MonitorUser.DoesNotExist:
        return Response({"error": "Invalid credentials."}, status=401)

    if user.is_locked():
        return Response(
            {"error": "Account locked. Try again later."},
            status=403,
        )

    if not user.check_password(password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 10:
            user.locked_until = timezone.now() + timedelta(minutes=30)
        user.save(update_fields=["failed_login_attempts", "locked_until"])
        _log_audit(user, "login_failed", request, success=False)
        return Response({"error": "Invalid credentials."}, status=401)

    user.failed_login_attempts = 0
    user.locked_until = None
    ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", ""))
    user.last_login_ip = ip.split(",")[0].strip() if ip else None
    user.save(update_fields=["failed_login_attempts", "locked_until", "last_login_ip"])

    tokens = _generate_tokens(user)
    _log_audit(user, "login_success", request)
    return Response(tokens)


@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def monitor_refresh_token(request):
    """Issue a new access token from a valid refresh token."""
    refresh_token = request.data.get("refresh_token", "")
    if not refresh_token:
        return Response({"error": "refresh_token required."}, status=400)

    try:
        secret = settings.HONEYPOT_CONFIG["MONITOR_JWT_SECRET"]
        payload = jwt.decode(refresh_token, secret, algorithms=["HS256"])
        if payload.get("type") != "refresh":
            raise ValueError("Not a refresh token.")
        user = MonitorUser.objects.get(id=payload["user_id"])
    except Exception:
        return Response({"error": "Invalid or expired refresh token."}, status=401)

    tokens = _generate_tokens(user)
    return Response(tokens)


@api_view(["POST"])
@authentication_classes([])
@monitor_auth_required
def monitor_logout(request):
    _log_audit(request.monitor_user, "logout", request)
    return Response({"status": "ok"})


@monitor_auth_required
def monitor_dashboard_view(request):
    """Render the monitoring dashboard HTML template."""
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    stats = {
        "total_events": AttackEvent.objects.count(),
        "events_24h": AttackEvent.objects.filter(timestamp__gte=last_24h).count(),
        "unique_sessions": AttackerSession.objects.count(),
        "total_time_wasted": AttackerSession.objects.aggregate(
            t=Sum("total_time_wasted_seconds")
        )["t"]
        or 0,
        "credentials_captured": CapturedCredential.objects.count(),
        "blocked_attackers": AttackerSession.objects.filter(is_blocked=True).count(),
    }

    critical_events = (
        AttackEvent.objects.select_related("session")
        .filter(severity__in=["critical", "high"])
        .order_by("-timestamp")[:30]
    )

    attack_distribution = (
        AttackEvent.objects.values("attack_type")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )

    top_attackers = AttackerSession.objects.order_by("-threat_score")[:15]

    recent_credentials = CapturedCredential.objects.select_related("session").order_by(
        "-timestamp"
    )[:20]

    daily_trend = (
        AttackEvent.objects.filter(timestamp__gte=last_7d)
        .annotate(date=TruncDate("timestamp"))
        .values("date")
        .annotate(count=Count("id"))
        .order_by("date")
    )

    _log_audit(request.monitor_user, "view_dashboard", request)

    context = {
        "user": request.monitor_user,
        "stats": stats,
        "critical_events": critical_events,
        "attack_distribution": attack_distribution,
        "top_attackers": top_attackers,
        "recent_credentials": recent_credentials,
        "daily_trend": list(daily_trend),
    }
    return render(request, "monitor/dashboard.html", context)


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def api_stats_overview(request):
    """Return a JSON summary of current honeypot statistics."""
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    hourly = (
        AttackEvent.objects.filter(timestamp__gte=now - timedelta(hours=24))
        .annotate(hour=TruncHour("timestamp"))
        .values("hour")
        .annotate(count=Count("id"))
        .order_by("hour")
    )

    severity_dist = AttackEvent.objects.values("severity").annotate(count=Count("id"))

    _log_audit(request.monitor_user, "view_stats", request)

    return Response(
        {
            "totals": {
                "total_events": AttackEvent.objects.count(),
                "events_24h": AttackEvent.objects.filter(
                    timestamp__gte=last_24h
                ).count(),
                "events_7d": AttackEvent.objects.filter(timestamp__gte=last_7d).count(),
                "unique_attackers": AttackerSession.objects.count(),
                "blocked_attackers": AttackerSession.objects.filter(
                    is_blocked=True
                ).count(),
                "credentials_captured": CapturedCredential.objects.count(),
                "total_time_wasted_s": AttackerSession.objects.aggregate(
                    t=Sum("total_time_wasted_seconds")
                )["t"]
                or 0,
            },
            "hourly_trend": list(hourly),
            "severity_distribution": list(severity_dist),
            "top_attack_types": list(
                AttackEvent.objects.values("attack_type")
                .annotate(count=Count("id"))
                .order_by("-count")[:10]
            ),
        }
    )


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def api_events_list(request):
    """Paginated, filterable list of attack events."""
    page = int(request.GET.get("page", 1))
    per_page = min(int(request.GET.get("per_page", 50)), 200)

    severity = request.GET.get("severity")
    attack_type = request.GET.get("attack_type")
    session_id = request.GET.get("session_id")
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")
    search = request.GET.get("search", "").strip()

    qs = AttackEvent.objects.select_related("session").order_by("-timestamp")

    if severity:
        qs = qs.filter(severity=severity)
    if attack_type:
        qs = qs.filter(attack_type=attack_type)
    if session_id:
        qs = qs.filter(session_id=session_id)
    if start_date:
        qs = qs.filter(timestamp__gte=start_date)
    if end_date:
        qs = qs.filter(timestamp__lte=end_date)
    if search:
        qs = qs.filter(
            Q(path__icontains=search)
            | Q(body__icontains=search)
            | Q(session__ip_address__icontains=search)
        )

    paginator = Paginator(qs, per_page)
    page_obj = paginator.get_page(page)

    events = []
    for ev in page_obj:
        events.append(
            {
                "id": str(ev.id),
                "timestamp": ev.timestamp.isoformat(),
                "session_id": str(ev.session_id),
                "ip_address": ev.session.ip_address,
                "country": ev.session.country_code,
                "method": ev.method,
                "path": ev.path,
                "attack_type": ev.attack_type,
                "severity": ev.severity,
                "confidence": ev.confidence,
                "detected_patterns": ev.detected_patterns,
                "response_status": ev.response_status,
            }
        )

    return Response(
        {
            "events": events,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": paginator.count,
                "total_pages": paginator.num_pages,
            },
        }
    )


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def api_sessions_list(request):
    """Paginated, filterable list of attacker sessions."""
    page = int(request.GET.get("page", 1))
    per_page = min(int(request.GET.get("per_page", 25)), 100)

    threat_level = request.GET.get("threat_level")
    is_blocked = request.GET.get("is_blocked")
    country = request.GET.get("country")

    qs = AttackerSession.objects.order_by("-threat_score", "-last_seen")

    if threat_level:
        qs = qs.filter(threat_level=threat_level)
    if is_blocked is not None:
        qs = qs.filter(is_blocked=is_blocked.lower() == "true")
    if country:
        qs = qs.filter(country_code=country.upper())

    paginator = Paginator(qs, per_page)
    page_obj = paginator.get_page(page)

    sessions = []
    for s in page_obj:
        sessions.append(
            {
                "id": str(s.id),
                "fingerprint": s.fingerprint,
                "ip_address": s.ip_address,
                "country_code": s.country_code,
                "country_name": s.country_name,
                "city": s.city,
                "first_seen": s.first_seen.isoformat(),
                "last_seen": s.last_seen.isoformat(),
                "total_requests": s.total_requests,
                "threat_score": s.threat_score,
                "threat_level": s.threat_level,
                "attack_vectors": s.attack_vectors_used,
                "time_wasted_seconds": s.total_time_wasted_seconds,
                "is_blocked": s.is_blocked,
                "is_tor": s.is_tor,
                "is_vpn": s.is_vpn,
            }
        )

    return Response(
        {
            "sessions": sessions,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": paginator.count,
                "total_pages": paginator.num_pages,
            },
        }
    )


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def api_session_detail(request, session_id):
    """Full detail for a single attacker session including timeline."""
    try:
        session = AttackerSession.objects.get(id=session_id)
    except AttackerSession.DoesNotExist:
        return Response({"error": "Session not found."}, status=404)

    events = AttackEvent.objects.filter(session=session).order_by("timestamp")
    credentials = CapturedCredential.objects.filter(session=session).order_by(
        "-timestamp"
    )
    deception = DeceptionInteraction.objects.filter(session=session).order_by(
        "-timestamp"
    )

    timeline = [
        {
            "timestamp": ev.timestamp.isoformat(),
            "type": "request",
            "method": ev.method,
            "path": ev.path,
            "attack_type": ev.attack_type,
            "severity": ev.severity,
            "patterns": ev.detected_patterns,
        }
        for ev in events[:200]
    ]

    _log_audit(
        request.monitor_user,
        "view_session_detail",
        request,
        resource_type="session",
        resource_id=str(session_id),
    )

    return Response(
        {
            "session": {
                "id": str(session.id),
                "fingerprint": session.fingerprint,
                "ip_address": session.ip_address,
                "user_agent": session.user_agent,
                "browser_fingerprint": session.browser_fingerprint,
                "country_code": session.country_code,
                "country_name": session.country_name,
                "city": session.city,
                "latitude": session.latitude,
                "longitude": session.longitude,
                "asn": session.asn,
                "asn_org": session.asn_org,
                "is_tor": session.is_tor,
                "is_vpn": session.is_vpn,
                "is_proxy": session.is_proxy,
                "abuse_confidence_score": session.abuse_confidence_score,
                "isp": session.isp,
                "first_seen": session.first_seen.isoformat(),
                "last_seen": session.last_seen.isoformat(),
                "total_requests": session.total_requests,
                "threat_score": session.threat_score,
                "threat_level": session.threat_level,
                "attack_vectors_used": session.attack_vectors_used,
                "time_wasted_seconds": session.total_time_wasted_seconds,
                "is_blocked": session.is_blocked,
                "blocked_at": (
                    session.blocked_at.isoformat() if session.blocked_at else None
                ),
                "block_expires_at": (
                    session.block_expires_at.isoformat()
                    if session.block_expires_at
                    else None
                ),
                "block_reason": session.block_reason,
                "analyst_notes": session.analyst_notes,
                "tags": session.tags,
                "ml_result": _get_ml_info(str(session.id)),
            },
            "timeline": timeline,
            "credentials": [
                {
                    "timestamp": c.timestamp.isoformat(),
                    "username": c.username,
                    "password": c.password,
                    "credential_type": c.credential_type,
                    "is_default": c.is_default_credential,
                    "strength": c.password_strength,
                }
                for c in credentials
            ],
            "deception_interactions": [
                {
                    "timestamp": d.timestamp.isoformat(),
                    "asset_name": d.asset.name,
                    "interaction_type": d.interaction_type,
                }
                for d in deception
            ],
            "statistics": {
                "total_events": events.count(),
                "attack_types": list(
                    events.values("attack_type").annotate(count=Count("id"))
                ),
                "top_paths": list(
                    events.values("path")
                    .annotate(count=Count("id"))
                    .order_by("-count")[:10]
                ),
            },
        }
    )


@api_view(["POST"])
@authentication_classes([])
@monitor_auth_required
def api_session_action(request, session_id):
    """Perform analyst actions on a session."""
    try:
        session = AttackerSession.objects.get(id=session_id)
    except AttackerSession.DoesNotExist:
        return Response({"error": "Session not found."}, status=404)

    if not request.monitor_user.has_permission("analyze"):
        return Response({"error": "Insufficient permissions."}, status=403)

    action = request.data.get("action", "")

    if action == "block":
        session.is_blocked = True
        session.blocked_at = timezone.now()
        session.block_reason = request.data.get(
            "reason", "Manually blocked by analyst."
        )
        session.save(update_fields=["is_blocked", "blocked_at", "block_reason"])
        _log_audit(
            request.monitor_user,
            "block_session",
            request,
            resource_type="session",
            resource_id=str(session_id),
            details={"reason": session.block_reason},
        )

    elif action == "unblock":
        session.is_blocked = False
        session.blocked_at = None
        session.block_reason = ""
        session.save(update_fields=["is_blocked", "blocked_at", "block_reason"])
        _log_audit(
            request.monitor_user,
            "unblock_session",
            request,
            resource_type="session",
            resource_id=str(session_id),
        )

    elif action == "add_tag":
        tag = request.data.get("tag", "").strip()
        if tag and tag not in session.tags:
            session.tags = session.tags + [tag]
            session.save(update_fields=["tags"])

    elif action == "remove_tag":
        tag = request.data.get("tag", "")
        if tag in session.tags:
            session.tags = [t for t in session.tags if t != tag]
            session.save(update_fields=["tags"])

    elif action == "add_note":
        note = request.data.get("note", "").strip()
        if note:
            prefix = "[{}] {}: ".format(
                timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
                request.monitor_user.username,
            )
            session.analyst_notes = (session.analyst_notes or "") + "\n" + prefix + note
            session.save(update_fields=["analyst_notes"])

    else:
        return Response({"error": "Unknown action: {}".format(action)}, status=400)

    return Response({"status": "ok", "action": action})


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def api_credentials_list(request):
    """Paginated list of captured credentials."""
    page = int(request.GET.get("page", 1))
    per_page = min(int(request.GET.get("per_page", 50)), 200)

    qs = CapturedCredential.objects.select_related("session").order_by("-timestamp")
    paginator = Paginator(qs, per_page)
    page_obj = paginator.get_page(page)

    creds = [
        {
            "id": str(c.id),
            "timestamp": c.timestamp.isoformat(),
            "ip_address": c.session.ip_address,
            "username": c.username,
            "password": c.password,
            "is_default": c.is_default_credential,
            "is_common": c.is_common_password,
            "strength": c.password_strength,
            "credential_type": c.credential_type,
        }
        for c in page_obj
    ]

    _log_audit(request.monitor_user, "view_credentials", request)

    return Response(
        {
            "credentials": creds,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": paginator.count,
                "total_pages": paginator.num_pages,
            },
        }
    )


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def api_threat_intel(request):
    """Aggregated threat intelligence: trends, geo, IOCs, top credentials."""
    now = timezone.now()
    last_7d = now - timedelta(days=7)

    daily_trend = (
        AttackEvent.objects.filter(timestamp__gte=last_7d)
        .annotate(date=TruncDate("timestamp"))
        .values("date")
        .annotate(
            count=Count("id"),
            critical=Count("id", filter=Q(severity="critical")),
            high=Count("id", filter=Q(severity="high")),
        )
        .order_by("date")
    )

    top_vectors = (
        AttackEvent.objects.values("attack_type")
        .annotate(count=Count("id"), unique_sources=Count("session", distinct=True))
        .order_by("-count")[:10]
    )

    geo_data = (
        AttackerSession.objects.exclude(country_code="")
        .values("country_code", "country_name")
        .annotate(
            sessions=Count("id"),
            avg_threat=Avg("threat_score"),
        )
        .order_by("-sessions")[:20]
    )

    common_creds = (
        CapturedCredential.objects.values("username")
        .annotate(count=Count("id"))
        .order_by("-count")[:20]
    )

    recent_iocs = []
    for ev in AttackEvent.objects.exclude(ioc_extracted=[]).order_by("-timestamp")[
        :100
    ]:
        for ioc in (ev.ioc_extracted or [])[:5]:
            recent_iocs.append(
                {
                    "type": ioc.get("type"),
                    "value": ioc.get("value"),
                    "source_event": str(ev.id),
                    "timestamp": ev.timestamp.isoformat(),
                }
            )
        if len(recent_iocs) >= 100:
            break

    return Response(
        {
            "daily_trend": list(daily_trend),
            "top_attack_vectors": list(top_vectors),
            "geographic_distribution": list(geo_data),
            "common_usernames": list(common_creds),
            "recent_iocs": recent_iocs[:100],
            "summary": {
                "total_sessions": AttackerSession.objects.count(),
                "total_events": AttackEvent.objects.count(),
                "total_credentials": CapturedCredential.objects.count(),
                "blocked_attackers": AttackerSession.objects.filter(
                    is_blocked=True
                ).count(),
                "countries_observed": AttackerSession.objects.values("country_code")
                .distinct()
                .count(),
            },
        }
    )


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def api_realtime_events(request):
    """Return events from the last N seconds for live-feed polling."""
    seconds = int(request.GET.get("seconds", 30))
    since = timezone.now() - timedelta(seconds=seconds)

    events = (
        AttackEvent.objects.filter(timestamp__gte=since)
        .select_related("session")
        .order_by("-timestamp")[:50]
    )

    return Response(
        {
            "events": [
                {
                    "id": str(e.id),
                    "timestamp": e.timestamp.isoformat(),
                    "ip": e.session.ip_address,
                    "country": e.session.country_code,
                    "method": e.method,
                    "path": e.path,
                    "attack_type": e.attack_type,
                    "severity": e.severity,
                }
                for e in events
            ],
            "count": events.count(),
            "since": since.isoformat(),
        }
    )


@api_view(["POST"])
@authentication_classes([])
@monitor_auth_required
def api_export_data(request):
    """Initiate a data export. Returns a download URL."""
    if not request.monitor_user.has_permission("export"):
        return Response({"error": "Insufficient permissions."}, status=403)

    export_type = request.data.get("type", "events")
    format_type = request.data.get("format", "json")

    _log_audit(
        request.monitor_user,
        "export_data",
        request,
        details={"type": export_type, "format": format_type},
    )

    filename = "{}_{}.{}".format(
        export_type,
        timezone.now().strftime("%Y%m%d_%H%M%S"),
        format_type,
    )

    return Response(
        {
            "status": "success",
            "message": "Export initiated.",
            "download_url": "/monitor/exports/{}".format(filename),
            "expires_at": (timezone.now() + timedelta(hours=1)).isoformat(),
        }
    )


@csrf_exempt
def health_check(request):
    """Simple liveness probe."""
    from django.http import JsonResponse as DJ

    return DJ({"status": "ok", "timestamp": timezone.now().isoformat()})


def real_bank_dashboard(request):
    """Serve the real, non-honeypot bank dashboard."""
    return render(request, "real_bank/dashboard.html")


def _get_ml_info(session_id):
    try:
        from core.siem.ml_anomaly import get_ml_score

        return get_ml_score(session_id)
    except Exception:
        return {"anomaly_score": 0, "is_anomaly": False, "status": "unavailable"}
