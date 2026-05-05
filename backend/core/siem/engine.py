"""
SIEM Engine
"""

import json
import time
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Optional

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from .signatures import classify, is_attack, SEVERITY_MAP, fingerprint_session

logger = logging.getLogger("honeypot.siem")

ROUTE_ALLOW = "ALLOW"
ROUTE_DECEIVE = "DECEIVE"
ROUTE_BLOCK = "BLOCK"

_PFX_SCORE = "siem:score:"
_PFX_ROUTE = "siem:route:"
_PFX_ATTEMPTS = "siem:attempts:"
_PFX_BURST = "siem:burst:"

BURST_LIMIT = getattr(settings, "SIEM_BURST_LIMIT", 20)
BRUTE_LIMIT = getattr(settings, "SIEM_BRUTE_LIMIT", 8)


class SiemEngine:
    """
    Instantiate once at module load. All methods are thread-safe because
    Redis handles concurrent writes atomically.
    """

    @property
    def _deceive_threshold(self):
        return getattr(settings, "SIEM_DECEIVE_THRESHOLD", 45)

    @property
    def _block_threshold(self):
        return getattr(settings, "SIEM_BLOCK_THRESHOLD", 120)

    SCORE_WEIGHTS = {
        "web_shell": 80,
        "command_injection": 70,
        "ssrf": 65,
        "xxe": 65,
        "deserialization": 65,
        "path_traversal": 55,
        "sql_injection": 50,
        "ssti": 55,
        "lfi": 50,
        "rfi": 55,
        "ldap_injection": 50,
        "nosql_injection": 50,
        "xss": 35,
        "header_injection": 35,
        "open_redirect": 30,
        "auth_bypass": 40,
        "prototype_pollution": 30,
        "brute_force": 20,
        "reconnaissance": 15,
        "other": 5,
    }

    def evaluate(self, request_data: dict) -> dict:
        """
        Main entry point. Returns a routing decision with full context.
        """
        ip = request_data.get("ip", "0.0.0.0")
        ua = request_data.get("user_agent", "")
        method = request_data.get("method", "GET")
        path = request_data.get("path", "/")
        body = request_data.get("body", "")
        qs = request_data.get("query_string", "")
        headers = json.dumps(request_data.get("headers", {}))
        username = request_data.get("username", "")
        password = request_data.get("password", "")

        fp = fingerprint_session(
            ip,
            ua,
            request_data.get("accept_language", ""),
            request_data.get("accept_encoding", ""),
        )

        corpus = " ".join([path, qs, body, headers, username, password])

        bypass_users = settings.HONEYPOT_CONFIG.get("LEGITIMATE_BYPASS_USERS", [])
        if username and username.lower() in [u.lower() for u in bypass_users]:
            cache.delete(_PFX_ROUTE + fp)
            cache.set(_PFX_SCORE + fp, 0, timeout=3600)

            return {
                "decision": ROUTE_ALLOW,
                "fingerprint": fp,
                "session_score": 0,
                "attack_type": "none",
                "severity": "info",
                "confidence": 1.0,
                "delta": 0,
                "patterns": [],
                "is_brute": False,
                "is_burst": False,
                "iocs": [],
                "timestamp": timezone.now().isoformat(),
            }

        sig_result = classify(corpus)
        attack_type = sig_result["attack_type"]
        confidence = sig_result["confidence"]
        severity = sig_result["severity"]
        patterns = sig_result["patterns_matched"]

        delta = int(self.SCORE_WEIGHTS.get(attack_type, 5) * confidence)

        is_brute = False
        if method == "POST" and ("/login" in path or "/auth" in path):
            attempt_key = _PFX_ATTEMPTS + fp
            attempts = cache.get(attempt_key, 0) + 1
            cache.set(attempt_key, attempts, timeout=600)
            if attempts >= BRUTE_LIMIT:
                is_brute = True
                attack_type = "brute_force"
                severity = "high"
                delta = max(delta, 25)

        is_burst = self._check_burst(ip)

        session_score = self._update_score(fp, delta)

        decision = self._decide(fp, session_score, is_burst, confidence, attack_type)

        return {
            "decision": decision,
            "fingerprint": fp,
            "session_score": session_score,
            "attack_type": attack_type,
            "severity": severity,
            "confidence": confidence,
            "delta": delta,
            "patterns": patterns,
            "rules": patterns,
            "is_brute": is_brute,
            "is_burst": is_burst,
            "iocs": self._extract_minimal_iocs(corpus),
            "timestamp": timezone.now().isoformat(),
        }

    def evaluate_login(
        self,
        ip: str,
        ua: str,
        username: str,
        password: str,
        path: str = "/api/auth/login/",
    ) -> dict:
        """
        Convenience wrapper specifically for login endpoint evaluation.
        Adds credential-level checks on top of the general evaluation.
        """
        data = {
            "ip": ip,
            "user_agent": ua,
            "method": "POST",
            "path": path,
            "username": username,
            "password": password,
            "body": json.dumps({"username": username, "password": password}),
            "headers": {},
        }
        result = self.evaluate(data)

        from core.threat_analyzer import ThreatAnalyzer

        cred_analysis = ThreatAnalyzer().analyze_credentials(username, password)
        result["credential_analysis"] = cred_analysis

        bypass_users = settings.HONEYPOT_CONFIG.get("LEGITIMATE_BYPASS_USERS", [])
        if username and username.lower() in [u.lower() for u in bypass_users]:
            return result

        if cred_analysis.get("is_default"):
            self._update_score(result["fingerprint"], 20)
            result["session_score"] += 20
            if result["decision"] == ROUTE_ALLOW:
                result["decision"] = ROUTE_DECEIVE
                result["attack_type"] = "auth_bypass"

        return result

    def record_failed_login(self, fingerprint: str) -> int:
        """Increment failed-login counter. Returns new count."""
        key = _PFX_ATTEMPTS + fingerprint
        count = cache.get(key, 0) + 1
        cache.set(key, count, timeout=600)
        return count

    def get_session_score(self, fingerprint: str) -> int:
        try:
            return int(cache.get(_PFX_SCORE + fingerprint, 0))
        except Exception as e:
            logger.warning(f"Cache get failed for {_PFX_SCORE + fingerprint}: {e}")
            return 0

    def force_deceive(self, fingerprint: str) -> None:
        """Permanently pin a fingerprint to the DECEIVE route."""
        cache.set(_PFX_ROUTE + fingerprint, ROUTE_DECEIVE, timeout=86400)

    def force_block(self, fingerprint: str) -> None:
        """Permanently pin a fingerprint to the BLOCK route."""
        cache.set(_PFX_ROUTE + fingerprint, ROUTE_BLOCK, timeout=86400)

    def _update_score(self, fingerprint: str, delta: int) -> int:
        key = _PFX_SCORE + fingerprint
        current = int(cache.get(key, 0))
        new_score = current + delta
        cache.set(key, new_score, timeout=3600)
        return new_score

    def _check_burst(self, ip: str) -> bool:
        key = _PFX_BURST + ip
        hits = cache.get(key, 0) + 1
        cache.set(key, hits, timeout=60)
        return hits > BURST_LIMIT

    def _decide(
        self,
        fingerprint: str,
        score: int,
        is_burst: bool,
        confidence: float,
        attack_type: str,
    ) -> str:
        pinned = cache.get(_PFX_ROUTE + fingerprint)
        if pinned:
            return pinned

        if score >= self._block_threshold:
            cache.set(_PFX_ROUTE + fingerprint, ROUTE_BLOCK, timeout=86400)
            return ROUTE_BLOCK

        if score >= self._deceive_threshold:
            cache.set(_PFX_ROUTE + fingerprint, ROUTE_DECEIVE, timeout=3600)
            return ROUTE_DECEIVE

        critical_types = {
            "web_shell",
            "command_injection",
            "ssrf",
            "xxe",
            "deserialization",
            "sql_injection",
            "ssti",
            "lfi",
            "rfi",
        }
        if confidence >= 0.85 and attack_type in critical_types:
            cache.set(_PFX_ROUTE + fingerprint, ROUTE_DECEIVE, timeout=3600)
            return ROUTE_DECEIVE

        if is_burst:
            return ROUTE_DECEIVE

        return ROUTE_ALLOW

    def _extract_minimal_iocs(self, corpus: str) -> list:
        import re

        iocs = []
        for ip in re.findall(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            corpus,
        ):
            if not ip.startswith("127."):
                iocs.append({"type": "ip", "value": ip})
        return iocs[:10]


siem = SiemEngine()
