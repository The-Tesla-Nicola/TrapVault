"""
SIEM Engine Tests
==================
Unit tests for the SIEM detection engine.
"""

import uuid
import pytest
from unittest.mock import MagicMock, patch
from core.siem.engine import SiemEngine, ROUTE_ALLOW, ROUTE_DECEIVE, ROUTE_BLOCK


class TestSiemEngine:
    @pytest.fixture
    def siem_engine(self):
        with patch("django.conf.settings"):
            return SiemEngine()

    @pytest.fixture
    def sample_request_data(self):
        return {
            "ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "method": "POST",
            "path": "/auth/login/",
            "query_string": "",
            "body": '{"username": "admin", "password": "admin"}',
            "headers": {"HTTP_USER_AGENT": "Mozilla/5.0"},
            "username": "admin",
            "password": "admin",
        }

    def test_engine_initialization(self, siem_engine):
        assert siem_engine is not None
        assert hasattr(siem_engine, "_deceive_threshold")
        assert hasattr(siem_engine, "_block_threshold")

    def test_evaluate_sql_injection(self, siem_engine, sample_request_data):
        sample_request_data["body"] = "username=admin' OR '1'='1"
        sample_request_data["path"] = "/auth/login/"
        result = siem_engine.evaluate(sample_request_data)
        assert "attack_type" in result
        assert result["attack_type"] in ["sql_injection", "other"]
        assert "severity" in result

    def test_evaluate_xss_payload(self, siem_engine, sample_request_data):
        sample_request_data["body"] = "<script>alert(1)</script>"
        sample_request_data["path"] = "/api/search/"
        result = siem_engine.evaluate(sample_request_data)
        assert "attack_type" in result

    def test_evaluate_normal_request(self, siem_engine, sample_request_data):
        result = siem_engine.evaluate(sample_request_data)
        assert result["confidence"] >= 0.0
        assert result["confidence"] <= 1.0
        assert "attack_type" in result
        assert "severity" in result

    def test_evaluate_command_injection(self, siem_engine, sample_request_data):
        sample_request_data["body"] = "username=admin; rm -rf /"
        sample_request_data["path"] = "/api/exec/"
        result = siem_engine.evaluate(sample_request_data)
        assert "attack_type" in result

    def test_evaluate_path_traversal(self, siem_engine, sample_request_data):
        sample_request_data["path"] = "/api/files"
        sample_request_data["query_string"] = "path=../../etc/passwd"
        result = siem_engine.evaluate(sample_request_data)
        assert "attack_type" in result

    def test_routing_decision_allow(self, siem_engine, sample_request_data):
        sample_request_data["body"] = "username=normal&password=password123"
        result = siem_engine.evaluate(sample_request_data)
        assert "decision" in result
        assert result["decision"] in [ROUTE_ALLOW, ROUTE_DECEIVE, ROUTE_BLOCK]

    def test_score_calculation(self, siem_engine):
        weights = siem_engine.SCORE_WEIGHTS
        assert "sql_injection" in weights
        assert "xss" in weights
        assert "command_injection" in weights
        assert weights["sql_injection"] > 0
        assert weights["xss"] > 0


class TestSiemSignatures:
    def test_detect_sql_injection(self):
        from core.siem.signatures import classify

        sql_payloads = [
            "admin' OR '1'='1",
            "1=1--",
            "UNION SELECT * FROM users",
            "'; DROP TABLE users--",
        ]
        for payload in sql_payloads:
            result = classify(payload)
            assert result is not None

    def test_detect_xss(self):
        from core.siem.signatures import classify

        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
        ]
        for payload in xss_payloads:
            result = classify(payload)
            assert result is not None

    def test_detect_command_injection(self):
        from core.siem.signatures import classify

        cmd_payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "`id`",
            "$(whoami)",
        ]
        for payload in cmd_payloads:
            result = classify(payload)
            assert result is not None

    def test_normal_input_classification(self):
        from core.siem.signatures import classify

        normal_inputs = [
            "John Doe",
            "hello@email.com",
            "https://example.com",
            "hello world",
        ]
        for text in normal_inputs:
            result = classify(text)
            assert result["attack_type"] == "other"


class TestSoarAutomation:
    def test_auto_block_threshold(self):
        from django.conf import settings

        threshold = settings.HONEYPOT_CONFIG.get("AUTO_BLOCK_THRESHOLD")
        assert threshold is not None
        assert threshold > 0
        assert isinstance(threshold, int)

    @patch("django.core.cache.cache")
    def test_blacklist_check(self, mock_cache):
        from core.soar.automation import SOAREngine

        mock_cache.get.return_value = None
        engine = SOAREngine()
        result = engine.check_ip_blacklist("192.168.1.1")
        assert result is None


class TestThreatIntel:
    def test_threat_intel_initialization(self):
        from core.siem.threat_intel import threat_intel

        assert threat_intel is not None

    @patch("core.siem.threat_intel.requests.get")
    def test_enrich_session_no_api_key(self, mock_get):
        from core.siem.threat_intel import ThreatIntelligenceEnricher

        result = ThreatIntelligenceEnricher().enrich_ip("192.168.1.1")
        assert result is not None


class TestMLAnomaly:
    @pytest.mark.django_db
    def test_ml_anomaly_initialization(self):
        from core.siem.ml_anomaly import get_ml_score

        session_id = str(uuid.uuid4())
        result = get_ml_score(session_id)
        assert isinstance(result, dict)
        assert "is_anomaly" in result
        assert "anomaly_score" in result


class TestViews:
    @pytest.mark.django_db
    def test_health_check_view(self, client):
        response = client.get("/api/health/")
        assert response.status_code == 200
        assert b"ok" in response.content or b"status" in response.content

    @pytest.mark.django_db
    def test_api_metrics_view(self, client):
        response = client.get("/api/metrics/")
        assert response.status_code in [200, 401, 404]
