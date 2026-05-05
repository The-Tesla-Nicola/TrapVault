"""
Threat Intelligence Enrichment Module
"""

import os
import logging
import requests
import geoip2.database
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings

logger = logging.getLogger("honeypot.threat_intel")

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
GEOIP_DB_PATH = settings.HONEYPOT_CONFIG.get(
    "GEOIP_PATH", "/app/geoip/GeoLite2-City.mmdb"
)
CACHE_TTL_SECONDS = 3600


class ThreatIntelligenceEnricher:
    def __init__(self):
        self.abuseipdb_enabled = bool(ABUSEIPDB_API_KEY)
        self.geoip_reader = None
        if os.path.exists(GEOIP_DB_PATH):
            try:
                self.geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
                logger.info(f"GeoIP loaded from {GEOIP_DB_PATH}")
            except Exception as e:
                logger.error(f"GeoIP load failed: {e}")

    def enrich_ip(self, ip_address, session_id=None):
        cache_key = f"threat_intel:{ip_address}"
        try:
            cached = cache.get(cache_key)
            if cached:
                return cached
        except Exception as e:
            logger.warning(f"Cache get failed for {cache_key}: {e}")

        result = {
            "ip": ip_address,
            "timestamp": timezone.now().isoformat(),
            "geolocation": self._get_geolocation(ip_address),
            "abuse_data": self._get_abuse_data(ip_address),
            "threat_level": "unknown",
            "risk_score": 0,
        }
        result["threat_level"] = self._calculate_threat_level(result)
        result["risk_score"] = self._calculate_risk_score(result)

        try:
            cache.set(cache_key, result, CACHE_TTL_SECONDS)
        except Exception as e:
            logger.warning(f"Cache set failed for {cache_key}: {e}")

        return result

    def _get_geolocation(self, ip_address):
        if not self.geoip_reader:
            return {
                "country": "Unknown",
                "country_code": "XX",
                "city": "Unknown",
                "latitude": 0.0,
                "longitude": 0.0,
                "isp": "Unknown",
            }
        try:
            response = self.geoip_reader.city(ip_address)
            return {
                "country": response.country.name or "Unknown",
                "country_code": response.country.iso_code or "XX",
                "city": response.city.name or "Unknown",
                "latitude": float(response.location.latitude or 0),
                "longitude": float(response.location.longitude or 0),
                "isp": response.traits.isp or "Unknown",
            }
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip_address}: {e}")
            return {
                "country": "Unknown",
                "country_code": "XX",
                "city": "Unknown",
                "latitude": 0.0,
                "longitude": 0.0,
                "isp": "Unknown",
            }

    def _get_abuse_data(self, ip_address):
        if not self.abuseipdb_enabled:
            return {"abuse_confidence_score": 0, "total_reports": 0}
        try:
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            params = {"ipAddress": ip_address, "maxAgeInDays": 90}
            response = requests.get(
                f"{ABUSEIPDB_BASE_URL}/check", headers=headers, params=params, timeout=5
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                }
            return {"abuse_confidence_score": 0, "total_reports": 0}
        except Exception as e:
            logger.error(f"AbuseIPDB lookup failed: {e}")
            return {"abuse_confidence_score": 0, "total_reports": 0}

    def _calculate_threat_level(self, enrichment_data):
        abuse_score = enrichment_data.get("abuse_data", {}).get(
            "abuse_confidence_score", 0
        )
        if abuse_score >= 80:
            return "critical"
        elif abuse_score >= 50:
            return "high"
        elif abuse_score >= 20:
            return "medium"
        elif abuse_score > 0:
            return "low"
        return "unknown"

    def _calculate_risk_score(self, enrichment_data):
        abuse_data = enrichment_data.get("abuse_data", {})
        base_score = abuse_data.get("abuse_confidence_score", 0) * 0.7
        total_reports = abuse_data.get("total_reports", 0)
        if total_reports > 100:
            base_score += 20
        elif total_reports > 50:
            base_score += 15
        elif total_reports > 10:
            base_score += 10
        return min(100, round(base_score, 2))

    def enrich_session(self, session):
        enrichment = self.enrich_ip(session.ip_address, session.id)
        geo = enrichment.get("geolocation", {})
        abuse = enrichment.get("abuse_data", {})
        session.country_name = geo.get("country", "Unknown")
        session.country_code = geo.get("country_code", "XX")
        session.city = geo.get("city", "Unknown")
        session.isp = geo.get("isp", "Unknown")
        session.threat_level = enrichment.get("threat_level", "unknown")
        session.abuse_confidence_score = abuse.get("abuse_confidence_score", 0)
        session.save(
            update_fields=[
                "country_name",
                "country_code",
                "city",
                "isp",
                "threat_level",
                "abuse_confidence_score",
            ]
        )
        return enrichment


threat_intel = ThreatIntelligenceEnricher()
