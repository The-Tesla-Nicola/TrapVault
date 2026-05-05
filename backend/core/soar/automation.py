"""
SOAR Automation Engine
"""

import logging
from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from django.db import transaction

logger = logging.getLogger("honeypot.soar")


def _get_auto_block_threshold():
    """Get auto-block threshold from settings (consistent across the app)."""
    return settings.HONEYPOT_CONFIG.get("AUTO_BLOCK_THRESHOLD", 1000)


class SOAREngine:
    def __init__(self):
        self.auto_block_enabled = True
        self.block_duration_hours = 24

    def evaluate_session_for_auto_block(self, session):
        if not self.auto_block_enabled or session.is_blocked:
            return False

        from core.siem.engine import siem
        from core.siem.ml_anomaly import get_ml_score

        current_score = siem.get_session_score(str(session.id))
        ml_result = get_ml_score(str(session.id))
        threshold = _get_auto_block_threshold()

        should_block = current_score >= threshold or (
            ml_result.get("is_anomaly") and ml_result.get("anomaly_score", 0) > 80
        )

        if should_block:
            logger.warning(f"Auto-block triggered for {session.id}")
            self.block_session(session, reason="auto_block", automated=True)
            return True
        return False

    @transaction.atomic
    def block_session(
        self, session, reason="manual", automated=False, duration_hours=None
    ):
        if duration_hours is None:
            duration_hours = self.block_duration_hours

        session.is_blocked = True
        session.block_reason = reason
        session.blocked_at = timezone.now()
        session.block_expires_at = timezone.now() + timedelta(hours=duration_hours)
        session.save(
            update_fields=[
                "is_blocked",
                "block_reason",
                "blocked_at",
                "block_expires_at",
            ]
        )

        blacklist_key = f"blacklist:{session.fingerprint}"
        cache.set(
            blacklist_key,
            {"session_id": str(session.id), "ip": session.ip_address, "reason": reason},
            timeout=duration_hours * 3600,
        )

        ip_blacklist_key = f"blacklist:ip:{session.ip_address}"
        cache.set(ip_blacklist_key, True, timeout=duration_hours * 3600)

        self._log_soar_action(session, "block", reason, automated, duration_hours)

        logger.info(
            f"Session {session.id} blocked (Reason: {reason}, Auto: {automated})"
        )
        return True

    def _log_soar_action(
        self, session, action_type, reason, automated, duration_hours=None
    ):
        try:
            from core.models import SOARAction

            SOARAction.objects.create(
                session=session,
                action_type=action_type,
                reason=reason,
                automated=automated,
                duration_hours=duration_hours,
                ip_address=session.ip_address,
            )
        except Exception as e:
            logger.error(f"Failed to log SOAR action: {e}")

    def check_ip_blacklist(self, ip_address):
        blacklist_key = f"blacklist:ip:{ip_address}"
        is_blocked = cache.get(blacklist_key)
        if is_blocked:
            from core.models import AttackerSession

            try:
                session = AttackerSession.objects.get(
                    ip_address=ip_address,
                    is_blocked=True,
                    block_expires_at__gt=timezone.now(),
                )
                return {
                    "blocked": True,
                    "session_id": str(session.id),
                    "reason": session.block_reason,
                    "expires_at": session.block_expires_at,
                }
            except AttackerSession.DoesNotExist:
                cache.delete(blacklist_key)
        return None

    def get_soar_stats(self):
        from core.models import AttackerSession, SOARAction

        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        return {
            "total_blocked": AttackerSession.objects.filter(is_blocked=True).count(),
            "active_blocks": AttackerSession.objects.filter(
                is_blocked=True, block_expires_at__gt=now
            ).count(),
            "blocks_last_24h": SOARAction.objects.filter(
                action_type="block", created_at__gte=last_24h
            ).count(),
            "automated_blocks_last_24h": SOARAction.objects.filter(
                action_type="block", automated=True, created_at__gte=last_24h
            ).count(),
        }

    def cleanup_expired_blocks(self):
        """Remove expired blocks from database and cache."""
        from core.models import AttackerSession

        now = timezone.now()
        expired = AttackerSession.objects.filter(
            is_blocked=True, block_expires_at__lt=now
        )
        count = expired.count()
        for session in expired:
            cache.delete(f"blacklist:{session.fingerprint}")
            cache.delete(f"blacklist:ip:{session.ip_address}")
            session.is_blocked = False
            session.blocked_at = None
            session.block_expires_at = None
            session.save(update_fields=["is_blocked", "blocked_at", "block_expires_at"])
        logger.info(f"Cleaned up {count} expired blocks")
        return count


soar_engine = SOAREngine()


def auto_block_check(session):
    return soar_engine.evaluate_session_for_auto_block(session)
