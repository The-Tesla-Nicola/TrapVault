"""
SIEM Dashboard API
"""

import json
import logging
from datetime import timedelta
from functools import wraps

from django.db.models import Count, Avg, Sum, Q, F
from django.db.models.functions import TruncDate, TruncHour, TruncMinute
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from rest_framework.decorators import (
    api_view,
    permission_classes,
    authentication_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from core.models import (
    AttackerSession,
    AttackEvent,
    CapturedCredential,
    SiemAlert,
    LoginAttempt,
    AlertRule,
    MonitorUser,
)
from core.views_monitor import monitor_auth_required, _log_audit

logger = logging.getLogger("honeypot.siem_api")


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def siem_overview(request):
    now = timezone.now()
    h1 = now - timedelta(hours=1)
    h24 = now - timedelta(hours=24)
    d7 = now - timedelta(days=7)
    d30 = now - timedelta(days=30)

    alerts_qs = SiemAlert.objects.all()

    kpis = {
        "total_alerts": alerts_qs.count(),
        "alerts_1h": alerts_qs.filter(timestamp__gte=h1).count(),
        "alerts_24h": alerts_qs.filter(timestamp__gte=h24).count(),
        "critical_unacked": alerts_qs.filter(
            severity="critical", is_acknowledged=False
        ).count(),
        "high_unacked": alerts_qs.filter(
            severity="high", is_acknowledged=False
        ).count(),
        "sessions_deceived": LoginAttempt.objects.filter(
            outcome="routed_honeypot", timestamp__gte=h24
        ).count(),
        "sessions_blocked": LoginAttempt.objects.filter(
            outcome="blocked", timestamp__gte=h24
        ).count(),
        "real_logins_24h": LoginAttempt.objects.filter(
            outcome="real_success", timestamp__gte=h24
        ).count(),
        "brute_force_24h": SiemAlert.objects.filter(
            is_brute_force=True, timestamp__gte=h24
        ).count(),
        "unique_attackers_24h": SiemAlert.objects.filter(timestamp__gte=h24)
        .values("fingerprint")
        .distinct()
        .count(),
        "avg_confidence": round(
            float(
                alerts_qs.filter(timestamp__gte=h24).aggregate(a=Avg("confidence"))["a"]
                or 0
            ),
            2,
        ),
        "top_attack_type": (
            alerts_qs.filter(timestamp__gte=h24)
            .values("attack_type")
            .annotate(c=Count("id"))
            .order_by("-c")
            .values_list("attack_type", flat=True)
            .first()
            or "none"
        ),
    }

    severity_dist = list(
        alerts_qs.filter(timestamp__gte=h24)
        .values("severity")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    hourly = list(
        alerts_qs.filter(timestamp__gte=h24)
        .annotate(hour=TruncHour("timestamp"))
        .values("hour")
        .annotate(
            total=Count("id"),
            critical=Count("id", filter=Q(severity="critical")),
            high=Count("id", filter=Q(severity="high")),
            medium=Count("id", filter=Q(severity="medium")),
        )
        .order_by("hour")
    )

    daily = list(
        alerts_qs.filter(timestamp__gte=d30)
        .annotate(date=TruncDate("timestamp"))
        .values("date")
        .annotate(count=Count("id"))
        .order_by("date")
    )

    attack_breakdown = list(
        alerts_qs.filter(timestamp__gte=d7)
        .values("attack_type")
        .annotate(
            count=Count("id"),
            avg_conf=Avg("confidence"),
            unique_fps=Count("fingerprint", distinct=True),
        )
        .order_by("-count")[:15]
    )

    funnel = {
        "total_logins": LoginAttempt.objects.filter(timestamp__gte=h24).count(),
        "routed_real": LoginAttempt.objects.filter(
            timestamp__gte=h24,
            outcome__in=["routed_real", "real_success", "real_failure"],
        ).count(),
        "routed_deceive": LoginAttempt.objects.filter(
            timestamp__gte=h24, outcome="routed_honeypot"
        ).count(),
        "blocked": LoginAttempt.objects.filter(
            timestamp__gte=h24, outcome="blocked"
        ).count(),
        "real_success": LoginAttempt.objects.filter(
            timestamp__gte=h24, outcome="real_success"
        ).count(),
        "real_failure": LoginAttempt.objects.filter(
            timestamp__gte=h24, outcome="real_failure"
        ).count(),
    }

    unacked = list(
        alerts_qs.filter(is_acknowledged=False, severity__in=["critical", "high"])
        .order_by("-timestamp")[:20]
        .values(
            "id",
            "timestamp",
            "attack_type",
            "severity",
            "confidence",
            "session_score",
            "routing_decision",
            "fingerprint",
            "is_brute_force",
            "is_burst",
        )
    )

    geo = list(
        AttackerSession.objects.exclude(country_code="")
        .values("country_code", "country_name")
        .annotate(
            sessions=Count("id"),
            avg_score=Avg("threat_score"),
        )
        .order_by("-sessions")[:30]
    )

    _log_audit(request.monitor_user, "siem_overview", request)

    return Response(
        {
            "kpis": kpis,
            "severity_dist": severity_dist,
            "hourly_trend": hourly,
            "daily_trend": daily,
            "attack_breakdown": attack_breakdown,
            "routing_funnel": funnel,
            "unacked_alerts": unacked,
            "geo_distribution": geo,
            "generated_at": now.isoformat(),
        }
    )


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def siem_alerts_list(request):
    since = timezone.now() - timedelta(hours=int(request.GET.get("hours", 24)))
    limit = min(int(request.GET.get("limit", 100)), 500)

    alerts = (
        SiemAlert.objects.filter(timestamp__gte=since)
        .select_related("session")
        .order_by("-timestamp")[:limit]
    )

    events = []
    for a in alerts:
        events.append(
            {
                "id": str(a.id),
                "timestamp": a.timestamp.isoformat(),
                "attack_type": a.attack_type,
                "severity": a.severity,
                "confidence": a.confidence,
                "session_score": a.session_score,
                "routing": a.routing_decision,
                "fingerprint": a.fingerprint[:12] + "…",
                "ip": a.session.ip_address if a.session else "—",
                "country": a.session.country_code if a.session else "",
                "is_brute": a.is_brute_force,
                "is_burst": a.is_burst,
                "patterns": a.patterns_matched[:5],
                "unacked": not a.is_acknowledged,
            }
        )

    return Response(
        {
            "events": events,
            "count": len(events),
            "since": since.isoformat(),
            "limit": limit,
        }
    )


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def siem_alert_queue(request):
    page = int(request.GET.get("page", 1))
    per_page = min(int(request.GET.get("per_page", 50)), 200)
    severity = request.GET.get("severity", "")
    attack_type = request.GET.get("attack_type", "")
    unacked_only = request.GET.get("unacked", "false").lower() == "true"
    routing = request.GET.get("routing", "")

    qs = SiemAlert.objects.select_related("session").order_by("-timestamp")
    if severity:
        qs = qs.filter(severity=severity)
    if attack_type:
        qs = qs.filter(attack_type=attack_type)
    if unacked_only:
        qs = qs.filter(is_acknowledged=False)
    if routing:
        qs = qs.filter(routing_decision=routing)

    from django.core.paginator import Paginator

    paginator = Paginator(qs, per_page)
    page_obj = paginator.get_page(page)

    alerts = []
    for a in page_obj:
        alerts.append(
            {
                "id": str(a.id),
                "timestamp": a.timestamp.isoformat(),
                "attack_type": a.attack_type,
                "severity": a.severity,
                "confidence": a.confidence,
                "session_score": a.session_score,
                "routing": a.routing_decision,
                "fingerprint": a.fingerprint,
                "ip": a.session.ip_address if a.session else "—",
                "country": a.session.country_code if a.session else "",
                "is_brute": a.is_brute_force,
                "is_burst": a.is_burst,
                "patterns": a.patterns_matched,
                "iocs": a.iocs,
                "acked": a.is_acknowledged,
                "analyst_note": a.analyst_note,
            }
        )

    return Response(
        {
            "alerts": alerts,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": paginator.count,
                "total_pages": paginator.num_pages,
            },
        }
    )


@api_view(["POST"])
@authentication_classes([])
@monitor_auth_required
def siem_acknowledge_alert(request, alert_id):
    """Acknowledge an alert with an optional analyst note."""
    if not request.monitor_user.has_permission("analyze"):
        return Response({"error": "Insufficient permissions."}, status=403)
    try:
        alert = SiemAlert.objects.get(id=alert_id)
    except SiemAlert.DoesNotExist:
        return Response({"error": "Alert not found."}, status=404)

    alert.is_acknowledged = True
    alert.acknowledged_by = request.monitor_user
    alert.acknowledged_at = timezone.now()
    alert.analyst_note = request.data.get("note", "")
    alert.save(
        update_fields=[
            "is_acknowledged",
            "acknowledged_by",
            "acknowledged_at",
            "analyst_note",
        ]
    )

    _log_audit(
        request.monitor_user,
        "ack_alert",
        request,
        resource_type="alert",
        resource_id=str(alert_id),
    )
    return Response({"status": "ok"})


@api_view(["POST"])
@authentication_classes([])
@monitor_auth_required
def siem_bulk_acknowledge(request):
    """Acknowledge multiple alerts at once."""
    if not request.monitor_user.has_permission("analyze"):
        return Response({"error": "Insufficient permissions."}, status=403)
    ids = request.data.get("ids", [])
    note = request.data.get("note", "Bulk acknowledged.")
    count = SiemAlert.objects.filter(id__in=ids).update(
        is_acknowledged=True,
        acknowledged_by=request.monitor_user,
        acknowledged_at=timezone.now(),
        analyst_note=note,
    )
    _log_audit(
        request.monitor_user, "bulk_ack_alerts", request, details={"count": count}
    )
    return Response({"acknowledged": count})


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def siem_login_funnel(request):
    """Detailed login attempt analytics for the funnel / sankey chart."""
    hours = int(request.GET.get("hours", 24))
    since = timezone.now() - timedelta(hours=hours)

    qs = LoginAttempt.objects.filter(timestamp__gte=since)

    by_outcome = dict(qs.values_list("outcome").annotate(c=Count("id")))

    by_hour = list(
        qs.annotate(hour=TruncHour("timestamp"))
        .values("hour", "outcome")
        .annotate(count=Count("id"))
        .order_by("hour")
    )

    top_usernames = list(
        qs.filter(outcome="routed_honeypot")
        .values("username")
        .annotate(count=Count("id"))
        .order_by("-count")[:20]
    )

    top_attacker_ips = list(
        qs.filter(outcome__in=["routed_honeypot", "blocked"])
        .values("ip_address")
        .annotate(count=Count("id"), max_score=Count("session_score"))
        .order_by("-count")[:15]
    )

    return Response(
        {
            "by_outcome": by_outcome,
            "hourly_breakdown": by_hour,
            "top_usernames": top_usernames,
            "top_attacker_ips": top_attacker_ips,
            "window_hours": hours,
        }
    )


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def siem_heatmap(request):
    """
    Returns a 7×24 matrix of alert counts for the heatmap chart.
    Rows = day of week (0=Mon … 6=Sun), Cols = hour (0–23).
    """
    days = int(request.GET.get("days", 30))
    since = timezone.now() - timedelta(days=days)

    alerts = SiemAlert.objects.filter(timestamp__gte=since).values_list(
        "timestamp", flat=True
    )

    matrix = [[0] * 24 for _ in range(7)]
    for ts in alerts:
        matrix[ts.weekday()][ts.hour] += 1

    return Response(
        {
            "matrix": matrix,
            "days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            "hours": list(range(24)),
            "window_days": days,
        }
    )


@api_view(["GET", "POST"])
@authentication_classes([])
@monitor_auth_required
def siem_alert_rules(request):
    if request.method == "GET":
        if not request.monitor_user.has_permission("configure"):
            return Response({"error": "Insufficient permissions."}, status=403)
        rules = list(
            AlertRule.objects.filter(is_active=True).values(
                "id",
                "name",
                "description",
                "match_severity",
                "match_attack_type",
                "min_confidence",
                "notification_channel",
                "auto_block",
                "cooldown_seconds",
            )
        )
        return Response({"rules": rules})

    if not request.monitor_user.has_permission("configure"):
        return Response({"error": "Insufficient permissions."}, status=403)

    d = request.data
    rule = AlertRule.objects.create(
        name=d.get("name", "Unnamed rule"),
        description=d.get("description", ""),
        match_severity=d.get("match_severity", ""),
        match_attack_type=d.get("match_attack_type", ""),
        min_confidence=float(d.get("min_confidence", 0.0)),
        notification_channel=d.get("notification_channel", "db"),
        auto_block=bool(d.get("auto_block", False)),
        cooldown_seconds=int(d.get("cooldown_seconds", 300)),
        created_by=request.monitor_user,
    )
    _log_audit(
        request.monitor_user,
        "create_alert_rule",
        request,
        resource_type="alert_rule",
        resource_id=str(rule.id),
    )
    return Response({"id": str(rule.id), "status": "created"}, status=201)


@api_view(["PUT", "DELETE"])
@authentication_classes([])
@monitor_auth_required
def siem_alert_rule_detail(request, rule_id):
    if not request.monitor_user.has_permission("configure"):
        return Response({"error": "Insufficient permissions."}, status=403)
    try:
        rule = AlertRule.objects.get(id=rule_id)
    except AlertRule.DoesNotExist:
        return Response({"error": "Not found."}, status=404)

    if request.method == "DELETE":
        rule.is_active = False
        rule.save(update_fields=["is_active"])
        return Response({"status": "deactivated"})

    d = request.data
    for field in (
        "name",
        "description",
        "match_severity",
        "match_attack_type",
        "notification_channel",
        "auto_block",
        "cooldown_seconds",
    ):
        if field in d:
            setattr(rule, field, d[field])
    if "min_confidence" in d:
        rule.min_confidence = float(d["min_confidence"])
    rule.save()
    return Response({"status": "updated"})


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def siem_session_timeline(request, fingerprint):
    """Per-fingerprint score accumulation over time for the drilldown chart."""
    alerts = (
        SiemAlert.objects.filter(fingerprint=fingerprint)
        .order_by("timestamp")
        .values(
            "timestamp",
            "attack_type",
            "severity",
            "session_score",
            "confidence",
            "routing_decision",
        )
    )
    events = list(alerts)
    return Response(
        {
            "fingerprint": fingerprint,
            "events": events,
            "total": len(events),
        }
    )


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def siem_ioc_feed(request):
    """Aggregate IOCs extracted from recent alerts."""
    hours = int(request.GET.get("hours", 48))
    since = timezone.now() - timedelta(hours=hours)

    all_iocs: dict = {}
    for a in SiemAlert.objects.filter(timestamp__gte=since).exclude(iocs=[]):
        for ioc in a.iocs or []:
            key = f"{ioc.get('type')}:{ioc.get('value')}"
            if key not in all_iocs:
                all_iocs[key] = {
                    "type": ioc.get("type"),
                    "value": ioc.get("value"),
                    "count": 0,
                    "first_seen": a.timestamp.isoformat(),
                    "last_seen": a.timestamp.isoformat(),
                }
            all_iocs[key]["count"] += 1
            if a.timestamp.isoformat() > all_iocs[key]["last_seen"]:
                all_iocs[key]["last_seen"] = a.timestamp.isoformat()

    iocs = sorted(all_iocs.values(), key=lambda x: -x["count"])[:200]
    return Response({"iocs": iocs, "total": len(iocs), "window_hours": hours})


@api_view(["GET", "POST"])
@authentication_classes([])
@monitor_auth_required
def real_bank_users(request):
    """List or create real bank users (legitimate customers)."""
    from core.models import RealBankUser
    import bcrypt

    if request.method == "GET":
        if not request.monitor_user.has_permission("configure"):
            return Response({"error": "Insufficient permissions."}, status=403)
        users = list(
            RealBankUser.objects.values(
                "id",
                "username",
                "email",
                "full_name",
                "account_number",
                "is_active",
                "created_at",
                "last_login",
            )
        )
        return Response({"users": users, "total": len(users)})

    if not request.monitor_user.has_permission("manage_users"):
        return Response({"error": "Insufficient permissions."}, status=403)

    d = request.data
    plain_pw = d.get("password", "")
    if len(plain_pw) < 10:
        return Response(
            {"error": "Password must be at least 10 characters."}, status=400
        )

    pw_hash = bcrypt.hashpw(plain_pw.encode(), bcrypt.gensalt(rounds=12)).decode()
    user = RealBankUser.objects.create(
        username=d.get("username", ""),
        password_hash=pw_hash,
        email=d.get("email", ""),
        full_name=d.get("full_name", ""),
        account_number=d.get("account_number", ""),
    )
    _log_audit(
        request.monitor_user,
        "create_real_user",
        request,
        resource_type="real_bank_user",
        resource_id=str(user.id),
    )
    return Response({"id": str(user.id), "status": "created"}, status=201)


from core.siem.ml_anomaly import get_ml_score
from core.siem.threat_intel import threat_intel
from core.soar.automation import soar_engine


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def get_ml_anomaly(request, session_id):
    """Get ML anomaly score for a session"""
    if not request.monitor_user.has_permission("view"):
        return Response({"error": "Insufficient permissions."}, status=403)
    result = get_ml_score(session_id)
    return Response(result)


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def get_threat_intel(request, ip_address):
    """Get threat intelligence for an IP"""
    if not request.monitor_user.has_permission("view"):
        return Response({"error": "Insufficient permissions."}, status=403)
    enrichment = threat_intel.enrich_ip(ip_address)
    return Response(enrichment)


@api_view(["POST"])
@authentication_classes([])
@monitor_auth_required
def block_session_api(request, session_id):
    """Manually block a session (SOAR action)"""
    if not request.monitor_user.has_permission("analyze"):
        return Response({"error": "Insufficient permissions."}, status=403)

    try:
        session = AttackerSession.objects.get(id=session_id)
        reason = request.data.get("reason", "manual_block")
        success = soar_engine.block_session(session, reason=reason, automated=False)

        _log_audit(
            request.monitor_user,
            "soar_block",
            request,
            resource_type="session",
            resource_id=str(session_id),
            details={"reason": reason},
        )

        return Response({"success": success})
    except AttackerSession.DoesNotExist:
        return Response({"error": "Session not found"}, status=404)


@api_view(["POST"])
@authentication_classes([])
@monitor_auth_required
def unblock_session_api(request, session_id):
    """Manually unblock a session"""
    if not request.monitor_user.has_permission("analyze"):
        return Response({"error": "Insufficient permissions."}, status=403)

    try:
        session = AttackerSession.objects.get(id=session_id)
        session.is_blocked = False
        session.blocked_at = None
        session.block_expires_at = None
        session.save(update_fields=["is_blocked", "blocked_at", "block_expires_at"])

        from django.core.cache import cache

        cache.delete(f"blacklist:ip:{session.ip_address}")

        _log_audit(
            request.monitor_user,
            "soar_unblock",
            request,
            resource_type="session",
            resource_id=str(session_id),
        )

        return Response({"success": True})
    except AttackerSession.DoesNotExist:
        return Response({"error": "Session not found"}, status=404)


@api_view(["GET"])
@authentication_classes([])
@monitor_auth_required
def get_soar_stats_api(request):
    """Get SOAR statistics"""
    if not request.monitor_user.has_permission("view"):
        return Response({"error": "Insufficient permissions."}, status=403)
    stats = soar_engine.get_soar_stats()
    return Response(stats)


from core.models import AttackerActivity


@api_view(["POST"])
@permission_classes([AllowAny])
def capture_telemetry(request):
    """
    Public endpoint for collecting silent telemetry from the decoy site.
    """
    session = getattr(request, "_hp_session", None)
    if not session:
        session_id = request.data.get("session_id")
        if session_id:
            try:
                session = AttackerSession.objects.get(id=session_id)
            except:
                pass

    if not session:
        return Response({"status": "ok"})

    activities = request.data.get("activities", [])
    if not isinstance(activities, list):
        activities = [request.data]

    created_logs = []
    for act in activities:
        event_type = act.get("event_type")
        if event_type:
            created_logs.append(
                AttackerActivity(
                    session=session,
                    event_type=event_type,
                    data=act.get("data", {}),
                    path=act.get("path", ""),
                    element_id=act.get("element_id", ""),
                )
            )

    if created_logs:
        AttackerActivity.objects.bulk_create(created_logs)

    return Response({"status": "ok"})
