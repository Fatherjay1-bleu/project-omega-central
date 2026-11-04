"""Security regression contracts for the public synthetic demonstration.

Run: python -m unittest discover -s tests -p 'test_public_demo_security_contract.py'
No live deployment or customer data is required.
"""
import unittest

from public_demo import application


class PublicDemoSecurityContractTests(unittest.TestCase):
    def setUp(self):
        application.config["TESTING"] = True
        self.client = application.test_client()

    def test_demo_index_is_explicitly_synthetic(self):
        response = self.client.get("/demo")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIs(payload["synthetic"], True)
        self.assertEqual(len(payload["scenarios"]), 3)

    def test_public_analyze_post_is_denied(self):
        response = self.client.post("/api/v3/analyze", json={"events": []})
        self.assertEqual(response.status_code, 405)

    def test_mutating_methods_are_denied_even_on_read_routes(self):
        for path in ("/", "/demo", "/health", "/api/events", "/api/v2/report"):
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                with self.subTest(path=path, method=method):
                    response = self.client.open(path, method=method)
                    self.assertEqual(response.status_code, 405)

    def test_security_headers_on_public_response(self):
        response = self.client.get("/demo")
        self.assertEqual(response.headers.get("Content-Security-Policy"), "default-src 'self'")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer")

    def test_unknown_scenario_does_not_fall_back_to_customer_data(self):
        response = self.client.get("/demo/scenario/999")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn("events", response.get_json())


if __name__ == "__main__":
    unittest.main()
