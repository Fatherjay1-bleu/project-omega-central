"""End-to-end staging boundary tests using fake identity adapters.

These tests do not validate OIDC cryptography or production isolation.
"""
import tempfile
import unittest
from pathlib import Path

from sentinel.enterprise.auth_gateway import EnterpriseAuthGateway
from sentinel.enterprise.tenant_policy import AuthorizationDenied
from sentinel.enterprise.tenant_store import TenantEventStore

ISSUER = "https://identity.example.test"

class EnterpriseBoundaryIntegrationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = TenantEventStore(Path(tmp.name) / "events.sqlite", trusted_issuer=ISSUER)
        self.store.initialize()
        self.gateway = EnterpriseAuthGateway(
            token_verifier=lambda token: {
                "sub": {"token-alice": "alice", "token-bob": "bob"}.get(token),
                "iss": ISSUER,
            },
            membership_resolver=lambda subject, tenant: {
                ("alice", "tenant-a"): "analyst",
                ("bob", "tenant-b"): "admin",
            }.get((subject, tenant)),
            trusted_issuer=ISSUER,
        )

    def test_authenticated_tenant_roundtrip(self):
        alice = self.gateway.authenticate("token-alice", "tenant-a")
        self.store.put(alice, "tenant-a", "event-1", {"severity": 8})
        self.assertEqual(self.store.get(alice, "tenant-a", "event-1"), {"severity": 8})

    def test_token_from_other_tenant_cannot_read_known_id(self):
        alice = self.gateway.authenticate("token-alice", "tenant-a")
        bob = self.gateway.authenticate("token-bob", "tenant-b")
        self.store.put(alice, "tenant-a", "event-1", {"sensitive": "synthetic"})
        with self.assertRaises(AuthorizationDenied):
            self.store.get(bob, "tenant-a", "event-1")
        self.assertIsNone(self.store.get(bob, "tenant-b", "event-1"))

    def test_token_from_other_tenant_cannot_write(self):
        bob = self.gateway.authenticate("token-bob", "tenant-b")
        with self.assertRaises(AuthorizationDenied):
            self.store.put(bob, "tenant-a", "event-1", {"forged": True})

    def test_cross_tenant_membership_request_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.gateway.authenticate("token-alice", "tenant-b")

    def test_unknown_token_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.gateway.authenticate("invalid-token", "tenant-a")

    def test_tenant_id_in_payload_does_not_override_authorization(self):
        alice = self.gateway.authenticate("token-alice", "tenant-a")
        self.store.put(alice, "tenant-a", "event-1", {"tenant_id": "tenant-b"})
        with self.assertRaises(AuthorizationDenied):
            self.store.get(alice, "tenant-b", "event-1")

if __name__ == "__main__":
    unittest.main()
