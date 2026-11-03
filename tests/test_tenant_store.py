"""Isolated tenant storage tests; no network or customer data."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from sentinel.enterprise.tenant_policy import VerifiedPrincipal, _mint_verified_principal, AuthorizationDenied
from sentinel.enterprise.tenant_store import TenantEventStore

ISSUER = "https://identity.example.test"

class TenantStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = TenantEventStore(Path(self.temp.name) / "events.sqlite", trusted_issuer=ISSUER)
        self.store.initialize()
        self.analyst = _mint_verified_principal("user-a", "tenant-a", "analyst", ISSUER)
        self.viewer = _mint_verified_principal("viewer-a", "tenant-a", "viewer", ISSUER)
        self.other = _mint_verified_principal("user-b", "tenant-b", "admin", ISSUER)

    def test_own_tenant_roundtrip(self):
        self.store.put(self.analyst, "tenant-a", "evt-1", {"severity": 7})
        self.assertEqual(self.store.get(self.viewer, "tenant-a", "evt-1"), {"severity": 7})

    def test_cross_tenant_read_denied_even_with_known_event_id(self):
        self.store.put(self.analyst, "tenant-a", "evt-1", {"secret": "test-only"})
        with self.assertRaises(AuthorizationDenied):
            self.store.get(self.other, "tenant-a", "evt-1")

    def test_cross_tenant_write_denied_even_for_admin(self):
        with self.assertRaises(AuthorizationDenied):
            self.store.put(self.other, "tenant-a", "evt-1", {})

    def test_viewer_cannot_ingest(self):
        with self.assertRaises(AuthorizationDenied):
            self.store.put(self.viewer, "tenant-a", "evt-1", {})

    def test_same_event_id_isolated_across_tenants(self):
        self.store.put(self.analyst, "tenant-a", "evt-1", {"tenant": "a"})
        self.store.put(self.other, "tenant-b", "evt-1", {"tenant": "b"})
        self.assertEqual(self.store.get(self.analyst, "tenant-a", "evt-1"), {"tenant": "a"})
        self.assertEqual(self.store.get(self.other, "tenant-b", "evt-1"), {"tenant": "b"})

    def test_unverified_identity_and_wrong_issuer_denied(self):
        for p in (None, {"tenant_id": "tenant-a"},
                  _mint_verified_principal("x", "tenant-a", "admin", "https://evil.test")):
            with self.subTest(principal=p), self.assertRaises(AuthorizationDenied):
                self.store.get(p, "tenant-a", "evt-1")

    def test_duplicate_event_id_denied(self):
        self.store.put(self.analyst, "tenant-a", "evt-1", {})
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.put(self.analyst, "tenant-a", "evt-1", {})

    def test_payload_validation_and_size(self):
        for payload in ([], {"bad": float("nan")}, {"oversize": "x" * 70000}):
            with self.subTest(payload_type=type(payload)), self.assertRaises(ValueError):
                self.store.put(self.analyst, "tenant-a", "evt-1", payload)

    def test_sql_injection_like_event_id_is_data(self):
        event_id = "x' OR 1=1 --"
        self.store.put(self.analyst, "tenant-a", event_id, {"ok": True})
        self.assertEqual(self.store.get(self.analyst, "tenant-a", event_id), {"ok": True})
        self.assertIsNone(self.store.get(self.analyst, "tenant-a", "x"))

    def test_missing_event_returns_none_without_cross_tenant_fallback(self):
        self.assertIsNone(self.store.get(self.viewer, "tenant-a", "missing"))

if __name__ == "__main__":
    unittest.main()
