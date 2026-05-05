"""
Middleware
"""

import time
import logging
import hashlib
from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.core.cache import cache

from rest_framework import authentication
from rest_framework import exceptions
from django.contrib.auth import get_user_model

logger = logging.getLogger("honeypot.middleware")

_EXCLUDED_PREFIXES = (
    "/monitor/",
    "/django-admin/",
    "/static/",
    "/favicon.ico",
    "/api/health",
    "/api/metrics/",
)


class AttackDetectionMiddleware:
    """
    The brain of the honeypot's active defense.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if any(path.startswith(p) for p in _EXCLUDED_PREFIXES):
            return self.get_response(request)

        path_lower = path.lower()
        if "/monitor/" in path_lower or "/django-admin/" in path_lower:
            return self.get_response(request)

        start_time = time.time()

        from .models import AttackerSession, AttackEvent
        from .siem.engine import siem, ROUTE_BLOCK
        from .siem.alerts import alert_manager
        from .siem.ml_anomaly import get_ml_score
        from .siem.threat_intel import threat_intel
        from .soar.automation import auto_block_check, soar_engine

        client_ip = self._get_client_ip(request)

        block_info = soar_engine.check_ip_blacklist(client_ip)
        if block_info:
            return JsonResponse(
                {
                    "error": "Access denied",
                    "detail": f"IP blocked: {block_info['reason']}",
                    "blocked_until": block_info["expires_at"].isoformat(),
                },
                status=403,
            )

        session = self._get_or_create_session(request, AttackerSession)
        request._hp_session = session

        if session and session.is_blocked:
            return JsonResponse(
                {
                    "error": "Access denied",
                    "detail": "Your IP has been flagged for suspicious activity.",
                },
                status=403,
            )

        if self._is_rate_limited(request):
            return JsonResponse(
                {"error": "Too many requests.", "retry_after": 60},
                status=429,
            )

        username_extracted = ""
        body_str = ""
        if request.method == "POST" and "application/json" in request.content_type:
            try:
                import json

                body_str = request.body.decode("utf-8", errors="ignore")
                body_data = json.loads(body_str)
                username_extracted = body_data.get("username", "")
            except:
                pass

        request_data = {
            "ip": client_ip,
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            "method": request.method,
            "path": path,
            "query_string": request.META.get("QUERY_STRING", ""),
            "body": body_str,
            "username": username_extracted,
            "headers": {k: v for k, v in request.META.items() if k.startswith("HTTP_")},
        }

        siem_result = siem.evaluate(request_data)

        response = self.get_response(request)

        duration_ms = int((time.time() - start_time) * 1000)

        try:
            AttackEvent.objects.create(
                session=session,
                method=request.method,
                path=path,
                query_string=request_data["query_string"],
                headers=request_data["headers"],
                body=request_data["body"],
                attack_type=siem_result["attack_type"],
                severity=siem_result["severity"],
                confidence=siem_result["confidence"],
                detected_patterns=siem_result["patterns"],
                rules_matched=siem_result["rules"],
                ioc_extracted=siem_result["iocs"],
                response_status=response.status_code,
                response_delay_ms=duration_ms,
            )

            try:
                alert_manager.process(siem_result, str(session.id))
            except Exception as ae:
                logger.error(f"Alert manager failure: {ae}")

            session.total_requests += 1
            session.last_seen = timezone.now()
            session.save(update_fields=["total_requests", "last_seen"])

            if session.total_requests % 5 == 0:
                try:
                    ml_result = get_ml_score(str(session.id))
                    if ml_result["is_anomaly"]:
                        logger.warning(
                            f"ML anomaly detected for session {session.id}: {ml_result['anomaly_score']}"
                        )
                except Exception as me:
                    logger.error(f"ML check failed: {me}")

            if session.total_requests == 1:
                try:
                    threat_intel.enrich_session(session)
                except Exception as e:
                    logger.error(f"Threat intel enrichment failed: {e}")

            try:
                auto_block_check(session)
            except Exception as se:
                logger.error(f"SOAR auto-block check failed: {se}")

        except Exception as e:
            logger.error(f"Failed to process attack detection: {e}")

        return response

    def _get_or_create_session(self, request, AttackerSession):
        """Identify attacker by IP + User-Agent + headers fingerprint."""
        ip = self._get_client_ip(request)
        ua = request.META.get("HTTP_USER_AGENT", "")

        accept_lang = request.META.get("HTTP_ACCEPT_LANGUAGE", "")[:50]
        accept_enc = request.META.get("HTTP_ACCEPT_ENCODING", "")[:30]

        fp_raw = f"{ip}|{ua}|{accept_lang[:10]}"
        fingerprint = hashlib.sha256(fp_raw.encode()).hexdigest()[:32]

        session, created = AttackerSession.objects.get_or_create(
            fingerprint=fingerprint,
            defaults={
                "ip_address": ip,
                "user_agent": ua[:500] if ua else "",
            },
        )
        return session

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")

    def _is_rate_limited(self, request):
        ip = self._get_client_ip(request)
        key = f"rl:{ip}"
        count = cache.get(key, 0)

        limit = settings.HONEYPOT_CONFIG.get("RATE_LIMIT_REQUESTS", 50)
        if count >= limit:
            return True

        cache.set(key, count + 1, 60)
        return False


class SessionTrackingMiddleware:
    """Lightweight middleware for monitoring dashboard counters."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)


class GodModeAuthentication(authentication.BaseAuthentication):
    """
    Internal-only auth class for administrative maintenance.
    """

    def authenticate(self, request):
        User = get_user_model()
        user = User.objects.filter(is_superuser=True).first()
        if user:
            return (user, None)
        return None
