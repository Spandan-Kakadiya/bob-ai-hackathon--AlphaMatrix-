"""
Test Vercel Serverless Entrypoint and Routes
"""
import unittest
from api.index import app
from backend.main import health_check, serve_index
import asyncio

class TestVercelEntrypoint(unittest.TestCase):
    def test_app_instance(self):
        self.assertIsNotNone(app)
        self.assertEqual(app.title, "BOB Defense Threat Intelligence Platform")

    def test_health_endpoint_direct(self):
        res = asyncio.run(health_check())
        self.assertEqual(res["status"], "HEALTHY")
        self.assertIn("active_clusters", res)
        self.assertIn("total_alerts", res)

    def test_routes_registered(self):
        route_paths = [r.path for r in app.routes]
        self.assertIn("/api/health", route_paths)
        self.assertIn("/api/stats", route_paths)
        self.assertIn("/api/alerts", route_paths)
        self.assertIn("/api/clusters", route_paths)
        self.assertIn("/api/bluf/generate", route_paths)
        self.assertIn("/api/mitre/matrix", route_paths)
        self.assertIn("/", route_paths)

if __name__ == "__main__":
    unittest.main()
