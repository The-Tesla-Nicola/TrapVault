from django.test import RequestFactory, TestCase, override_settings
from django.http import HttpResponse
from core.middleware import AttackDetectionMiddleware
from core.models import AttackerSession, AttackEvent
from unittest.mock import MagicMock, patch


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
)
class MiddlewareTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.get_response = MagicMock(return_value=HttpResponse("OK"))
        self.middleware = AttackDetectionMiddleware(self.get_response)

    def test_middleware_creates_attack_event(self):
        # Create a request that should NOT be excluded
        request = self.factory.get("/some-fake-endpoint")

        # We need to mock siem.evaluate to return a predictable result
        with patch("core.siem.engine.siem.evaluate") as mock_evaluate:
            mock_evaluate.return_value = {
                "attack_type": "sql_injection",
                "severity": "high",
                "confidence": 0.9,
                "patterns": ["sqli_mock"],
                "rules": ["rule_mock"],
                "iocs": [],
                "decision": "ALLOW",
            }

            response = self.middleware(request)

            # Check if AttackerSession was created
            self.assertEqual(AttackerSession.objects.count(), 1)
            session = AttackerSession.objects.first()

            # Check if AttackEvent was created
            self.assertEqual(AttackEvent.objects.count(), 1)
            event = AttackEvent.objects.first()

            self.assertEqual(event.session, session)
            self.assertEqual(event.attack_type, "sql_injection")
            self.assertEqual(event.severity, "high")
            self.assertEqual(event.path, "/some-fake-endpoint")

    def test_middleware_excludes_monitor_paths(self):
        request = self.factory.get("/monitor/siem/")
        response = self.middleware(request)

        # Should NOT create session or event for excluded paths
        self.assertEqual(AttackerSession.objects.count(), 0)
        self.assertEqual(AttackEvent.objects.count(), 0)

    def test_middleware_blocks_blocked_session(self):
        # Pre-create a blocked session
        ip = "1.2.3.4"
        ua = "test-ua"
        import hashlib

        fp_raw = f"{ip}|{ua}"
        fingerprint = hashlib.sha256(fp_raw.encode()).hexdigest()[:32]

        session = AttackerSession.objects.create(
            fingerprint=fingerprint, ip_address=ip, user_agent=ua, is_blocked=True
        )

        request = self.factory.get("/any-path", HTTP_USER_AGENT=ua, REMOTE_ADDR=ip)
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)
        # get_response should NOT have been called
        self.get_response.assert_not_called()
