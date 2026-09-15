"""
BOB Defense Threat Intelligence Platform
Automated Engine & Security Verification Tests
"""

import unittest
from backend.models import Alert
from backend.security import sanitize_input_string, sanitize_alert_payload, check_rate_limit
from backend.engine.mitre_mapper import MitreMapper
from backend.engine.correlator import ThreatCorrelator
from backend.engine.bluf_generator import BLUFGenerator

class TestBobDefensePlatform(unittest.TestCase):
    def setUp(self):
        self.mitre_mapper = MitreMapper()
        self.correlator = ThreatCorrelator(self.mitre_mapper)
        self.bluf_gen = BLUFGenerator()

    def test_mitre_mapping(self):
        tactics, techniques = self.mitre_mapper.map_alert_to_mitre(
            "Cobalt Strike Beaconing via DNS Tunneling",
            "Observed periodic beaconing to rogue C2 server",
            "payload: powershell.exe -EncodedCommand",
            ["C2", "Execution"]
        )
        self.assertIn("T1071", techniques)
        self.assertIn("Command and Control", tactics)

    def test_false_positive_filtering(self):
        # Benign vulnerability scanner alert
        fp_alert_dict = {
            "source_type": "CYBER",
            "source_feed": "Nessus-Scanner",
            "title": "Vulnerability Scanner Scheduled Network Port Sweep",
            "description": "Internal automated health check and compliance scan",
            "target_asset": "COMMAND-POST",
            "tags": ["Automated", "Routine"]
        }
        alert = self.correlator.ingest_and_process_alert(fp_alert_dict)
        self.assertTrue(alert.is_false_positive)
        self.assertEqual(alert.severity, "BENIGN")

    def test_multi_source_correlation(self):
        # Ingest coordinated genuine attacks targeting SATCOM-UPLINK-04
        cyber_alert = {
            "source_type": "CYBER",
            "source_feed": "Zeek-IDS",
            "severity": "CRITICAL",
            "title": "Cobalt Strike C2 Beaconing",
            "description": "Outbound DNS tunneling",
            "target_asset": "SATCOM-UPLINK-04",
            "tags": ["APT-COSMIC", "C2"]
        }
        sat_alert = {
            "source_type": "SATELLITE",
            "source_feed": "Space-SSN-Sensor",
            "severity": "CRITICAL",
            "title": "Severe RF Uplink Jamming Detected on Ku-Band",
            "description": "Satellite transponder #4 experienced sudden 22dB drop",
            "target_asset": "SATCOM-UPLINK-04",
            "tags": ["APT-COSMIC", "RF Jamming"]
        }

        a1 = self.correlator.ingest_and_process_alert(cyber_alert)
        a2 = self.correlator.ingest_and_process_alert(sat_alert)

        self.assertFalse(a1.is_false_positive)
        self.assertFalse(a2.is_false_positive)

        # Ensure clusters were formed and correlated
        clusters = list(self.correlator.threat_clusters.values())
        self.assertGreaterEqual(len(clusters), 1)
        
        target_cluster = next((c for c in clusters if "SATCOM-UPLINK-04" in c.affected_assets), None)
        self.assertIsNotNone(target_cluster)
        self.assertIn("CYBER", target_cluster.attack_vectors)
        self.assertIn("SATELLITE", target_cluster.attack_vectors)
        self.assertEqual(target_cluster.threat_actor, "APT-COSMIC")

    def test_bluf_briefing_generation(self):
        # Create threat cluster
        cyber_alert = {
            "source_type": "CYBER",
            "source_feed": "Zeek-IDS",
            "severity": "CRITICAL",
            "title": "Cobalt Strike C2 Beaconing",
            "target_asset": "SATCOM-UPLINK-04",
            "tags": ["APT-COSMIC"]
        }
        self.correlator.ingest_and_process_alert(cyber_alert)
        cluster = list(self.correlator.threat_clusters.values())[0]

        report = self.bluf_gen.generate_bluf_brief(cluster)
        self.assertIsNotNone(report.bluf_headline)
        self.assertIsNotNone(report.bottom_line_up_front)
        self.assertGreater(len(report.key_judgments), 0)
        self.assertGreater(len(report.recommended_commander_actions), 0)

    def test_stix_export(self):
        cyber_alert = {
            "source_type": "CYBER",
            "source_feed": "Zeek-IDS",
            "severity": "CRITICAL",
            "title": "Cobalt Strike C2 Beaconing",
            "target_asset": "SATCOM-UPLINK-04",
            "tags": ["APT-COSMIC"]
        }
        self.correlator.ingest_and_process_alert(cyber_alert)
        cluster = list(self.correlator.threat_clusters.values())[0]
        stix = self.bluf_gen.export_stix_bundle(cluster)
        self.assertEqual(stix["type"], "bundle")
        self.assertGreaterEqual(len(stix["objects"]), 2)

    def test_copilot_fallback(self):
        answer_data = self.bluf_gen.ask_copilot("What is the tactical impact on SATCOM?")
        self.assertIn("answer", answer_data)
        self.assertIn("timestamp", answer_data)

    def test_security_sanitization(self):
        malicious_input = "<script>alert('pwned')</script> SELECT * FROM users; DROP TABLE alerts; --"
        cleaned = sanitize_input_string(malicious_input)
        self.assertNotIn("<script>", cleaned)
        self.assertIn("&lt;script&gt;", cleaned)

    def test_supabase_auth_login_and_registration(self):
        from backend.supabase_client import supabase_auth
        # Test Default Seed Login
        ok, msg, data = supabase_auth.login_analyst("commander@bob-defense.mil", "Commander2026!")
        self.assertTrue(ok)
        self.assertIsNotNone(data["token"])
        self.assertIn("LEVEL-5", data["analyst"]["clearance_level"])

        # Test Registration
        reg_data = {
            "name": "Captain Kirk",
            "callsign": "ENTERPRISE-01",
            "email": "kirk@bob-defense.mil",
            "clearance_level": "LEVEL-5 (TOP SECRET // SI-TK)",
            "division": "Space Command",
            "password": "SecurePassword123!"
        }
        reg_ok, reg_msg, reg_res = supabase_auth.register_analyst(reg_data)
        self.assertTrue(reg_ok)
        self.assertIsNotNone(reg_res["token"])

        # Test Login with new user
        login_ok, _, login_res = supabase_auth.login_analyst("kirk@bob-defense.mil", "SecurePassword123!")
        self.assertTrue(login_ok)
        self.assertEqual(login_res["analyst"]["callsign"], "ENTERPRISE-01")

if __name__ == "__main__":
    unittest.main()

