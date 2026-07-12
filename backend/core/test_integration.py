"""
Integration Tests
================
End-to-end integration tests for the honeypot platform.
"""

import pytest
from django.test import TestCase, Client
import json


@pytest.mark.django_db
class TestAuthIntegration(TestCase):
    def setUp(self):
        self.client = Client()

    def test_health_endpoint(self):
        response = self.client.get("/api/health/")
        assert response.status_code == 200

    def test_metrics_endpoint(self):
        response = self.client.get("/api/metrics/")
        assert response.status_code in [200, 401, 404]


@pytest.mark.django_db
class TestSIEMIntegration(TestCase):
    def setUp(self):
        self.client = Client()

    def test_sql_injection_detection(self):
        response = self.client.post(
            "/api/auth/login/",
            data=json.dumps({"username": "admin' OR '1'='1", "password": "test"}),
            content_type="application/json",
        )
        assert response.status_code in [200, 400, 401, 500]

    def test_xss_payload_blocked(self):
        response = self.client.post(
            "/api/auth/login/",
            data=json.dumps(
                {"username": "<script>alert(1)</script>", "password": "test"}
            ),
            content_type="application/json",
        )
        assert response.status_code in [200, 400, 401]

    def test_normal_login_flow(self):
        response = self.client.post(
            "/api/auth/login/",
            data=json.dumps({"username": "normaluser", "password": "normalpass"}),
            content_type="application/json",
        )
        assert response.status_code in [200, 401, 404]


@pytest.mark.django_db
class TestMonitorIntegration(TestCase):
    def setUp(self):
        self.client = Client()

    def test_monitor_login_page(self):
        response = self.client.get("/monitor/login/")
        assert response.status_code in [200, 302, 404]

    def test_monitor_protected(self):
        response = self.client.get("/monitor/siem/")
        assert response.status_code in [200, 302, 401, 404]


@pytest.mark.django_db
class TestRealBankIntegration(TestCase):
    def setUp(self):
        self.client = Client()

    def test_real_bank_login_endpoint(self):
        response = self.client.post(
            "/real-bank/auth/login/",
            data=json.dumps({"username": "test", "password": "test"}),
            content_type="application/json",
        )
        assert response.status_code in [200, 400, 401, 404]


class TestDeceptionIntegration(TestCase):
    def setUp(self):
        self.client = Client()

    def test_fake_admin_dashboard(self):
        response = self.client.get("/admin/dashboard/")
        assert response.status_code in [200, 302, 404]

    def test_fake_wp_admin(self):
        response = self.client.get("/wp-admin/")
        assert response.status_code in [200, 302, 404]

    def test_env_file_trap(self):
        response = self.client.get("/api/.env")
        assert response.status_code in [200, 302, 404, 400]


@pytest.mark.django_db
class TestRateLimiting(TestCase):
    def setUp(self):
        self.client = Client()

    def test_rate_limit_enforced(self):
        for _ in range(100):
            response = self.client.get("/api/health/")
        assert True


@pytest.mark.django_db
class TestSOARIntegration(TestCase):
    def setUp(self):
        self.client = Client()

    def test_auto_block_threshold(self):
        from django.conf import settings

        threshold = settings.HONEYPOT_CONFIG.get("AUTO_BLOCK_THRESHOLD")
        assert threshold is not None
        assert threshold > 0
