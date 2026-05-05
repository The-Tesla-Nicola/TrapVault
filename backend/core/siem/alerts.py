"""
Alert Manager
"""

import json
import logging
import smtplib
from datetime import timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

import httpx
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger("honeypot.alerts")

ALERT_COOLDOWN_SECONDS = 300


class AlertLevel:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_TO_LEVEL = {
    "info": AlertLevel.INFO,
    "low": AlertLevel.LOW,
    "medium": AlertLevel.MEDIUM,
    "high": AlertLevel.HIGH,
    "critical": AlertLevel.CRITICAL,
}


class AlertManager:
    def process(self, siem_result: dict, session_id: Optional[str] = None) -> None:
        """
        Called after every SIEM evaluation. Creates database alert record
        and fires external notifications for high/critical severity.
        """
        severity = siem_result.get("severity", "info")
        attack_type = siem_result.get("attack_type", "other")
        fingerprint = siem_result.get("fingerprint", "")
        score = siem_result.get("session_score", 0)
        decision = siem_result.get("decision", "ALLOW")

        self._create_db_alert(siem_result, session_id)

        if severity in ("high", "critical"):
            if not self._is_duplicate(fingerprint, severity):
                self._notify(severity, attack_type, siem_result, session_id)
                self._mark_notified(fingerprint, severity)

    def _create_db_alert(self, result: dict, session_id: Optional[str]) -> None:
        try:
            from core.models import SiemAlert

            SiemAlert.objects.create(
                session_id=session_id,
                fingerprint=result.get("fingerprint", ""),
                attack_type=result.get("attack_type", "other"),
                severity=result.get("severity", "info"),
                confidence=result.get("confidence", 0.0),
                session_score=result.get("session_score", 0),
                routing_decision=result.get("decision", "ALLOW"),
                patterns_matched=result.get("patterns", []),
                iocs=result.get("iocs", []),
                is_brute_force=result.get("is_brute", False),
                is_burst=result.get("is_burst", False),
            )
        except Exception as exc:
            logger.error("Failed to create SIEM alert: %s", exc)

    def _notify(
        self, severity: str, attack_type: str, result: dict, session_id: Optional[str]
    ) -> None:
        cfg = getattr(settings, "ALERT_CONFIG", {})

        if cfg.get("SLACK_WEBHOOK_URL"):
            self._slack(
                severity, attack_type, result, session_id, cfg["SLACK_WEBHOOK_URL"]
            )

        if cfg.get("SMTP_HOST") and cfg.get("ALERT_EMAIL_TO"):
            self._email(severity, attack_type, result, session_id, cfg)

    def _slack(
        self,
        severity: str,
        attack_type: str,
        result: dict,
        session_id: Optional[str],
        webhook_url: str,
    ) -> None:
        colour = {"critical": "#d32f2f", "high": "#f57c00"}.get(severity, "#1976d2")
        text = (
            f"*{severity.upper()} SECURITY ALERT*\n"
            f"Attack Type: `{attack_type}`\n"
            f"Session Score: {result.get('session_score', 0)}\n"
            f"Confidence: {result.get('confidence', 0):.0%}\n"
            f"Routing: `{result.get('decision', 'ALLOW')}`\n"
            f"Patterns: {', '.join(result.get('patterns', [])[:5])}"
        )
        payload = {
            "attachments": [
                {
                    "color": colour,
                    "text": text,
                    "footer": "Honeypot SIEM",
                    "ts": int(timezone.now().timestamp()),
                }
            ]
        }
        try:
            httpx.post(webhook_url, json=payload, timeout=5)
        except Exception as exc:
            logger.warning("Slack alert failed: %s", exc)

    def _email(
        self,
        severity: str,
        attack_type: str,
        result: dict,
        session_id: Optional[str],
        cfg: dict,
    ) -> None:
        subject = f"[HONEYPOT SIEM] {severity.upper()} – {attack_type}"
        body = (
            f"Severity: {severity}\n"
            f"Attack Type: {attack_type}\n"
            f"Session Score: {result.get('session_score', 0)}\n"
            f"Confidence: {result.get('confidence', 0):.2f}\n"
            f"Routing Decision: {result.get('decision', 'ALLOW')}\n"
            f"Patterns Matched: {', '.join(result.get('patterns', []))}\n"
            f"IOCs: {json.dumps(result.get('iocs', []))}\n"
            f"Timestamp: {result.get('timestamp', '')}\n"
        )
        msg = MIMEMultipart()
        msg["From"] = cfg.get("ALERT_EMAIL_FROM", "siem@honeypot.local")
        msg["To"] = cfg.get("ALERT_EMAIL_TO", "")
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        try:
            with smtplib.SMTP(
                cfg.get("SMTP_HOST", "localhost"), int(cfg.get("SMTP_PORT", 587))
            ) as smtp:
                if cfg.get("SMTP_USER"):
                    smtp.starttls()
                    smtp.login(cfg["SMTP_USER"], cfg.get("SMTP_PASSWORD", ""))
                smtp.sendmail(msg["From"], msg["To"], msg.as_string())
        except Exception as exc:
            logger.warning("Email alert failed: %s", exc)

    def _is_duplicate(self, fingerprint: str, severity: str) -> bool:
        key = f"siem:alerted:{fingerprint}:{severity}"
        return bool(cache.get(key))

    def _mark_notified(self, fingerprint: str, severity: str) -> None:
        key = f"siem:alerted:{fingerprint}:{severity}"
        cache.set(key, 1, timeout=ALERT_COOLDOWN_SECONDS)


alert_manager = AlertManager()
