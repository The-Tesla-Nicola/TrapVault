"""
SIEM Package
===========
Core SIEM components for threat detection and response.
"""

from .engine import SiemEngine, siem, ROUTE_ALLOW, ROUTE_DECEIVE, ROUTE_BLOCK
from .signatures import classify, is_attack, fingerprint_session
from .alerts import AlertManager, alert_manager
from .threat_intel import (
    ThreatIntelligenceEnricher,
    ThreatIntelligenceEnricher as ThreatIntel,
    threat_intel,
)
from .ml_anomaly import MLAnomalyDetector, get_ml_score

__all__ = [
    "SiemEngine",
    "siem",
    "ROUTE_ALLOW",
    "ROUTE_DECEIVE",
    "ROUTE_BLOCK",
    "classify",
    "is_attack",
    "fingerprint_session",
    "AlertManager",
    "alert_manager",
    "ThreatIntel",
    "threat_intel",
    "MLAnomalyDetector",
    "get_ml_score",
]
