"""Isolated enterprise authorization tests; no live data or network."""
import unittest
from sentinel.enterprise.tenant_policy import Action, AuthorizationDenied, VerifiedPrincipal, _mint_verified_principal, require_tenant_grant

ISSUER = "https://identity.example.test"

class TenantPolicyTests(unittest.TestCase):
    def principal(self, tenant="tenant-a", role="viewer", issuer=ISSUER):
        return _mint_verified_principal("subject-1", tenant, role, issuer)

    def check(self, principal, tenant="tenant-a", action=Action.READ, issuer=ISSUER):
        return require_tenant_grant(principal, tenant, action, trusted_issuer=issuer)

    def test_viewer_can_read_own_tenant(self):
        self.assertTrue(self.check(self.principal()))

    def test_cross_tenant_denied_for_all_roles_and_actions(self):
        for role in ("viewer", "analyst", "admin"):
            for action in Action:
                with self.subTest(role=role, action=action), self.assertRaises(AuthorizationDenied):
                    self.check(self.principal(role=role), "tenant-b", action)

    def test_roles_are_least_privilege(self):
        for role, allowed in (("viewer", {Action.READ}), ("analyst", {Action.READ, Action.INGEST}),
                              ("admin", set(Action)), ("unknown", set())):
            for action in Action:
                with self.subTest(role=role, action=action):
                    if action in allowed:
                        self.assertTrue(self.check(self.principal(role=role), action=action))
                    else:
                        with self.assertRaises(AuthorizationDenied):
                            self.check(self.principal(role=role), action=action)

    def test_unverified_principal_denied(self):
        for value in (None, {}, {"tenant_id": "tenant-a"}, object()):
            with self.subTest(value=type(value)), self.assertRaises(AuthorizationDenied):
                self.check(value)

    def test_untrusted_issuer_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.check(self.principal(issuer="https://attacker.test"))

    def test_unicode_tenant_and_issuer_fail_closed(self):
        principal = self.principal(tenant="équipe", issuer="https://idéntité.example.test")
        self.assertTrue(self.check(principal, "équipe", issuer="https://idéntité.example.test"))
        with self.assertRaises(AuthorizationDenied):
            self.check(principal, "autre", issuer="https://idéntité.example.test")
        with self.assertRaises(AuthorizationDenied):
            self.check(principal, "équipe", issuer="https://other.example.test")

    def test_untyped_action_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.check(self.principal(), action="read")

    def test_missing_tenant_or_trust_denied(self):
        for tenant, issuer in (("", ISSUER), (None, ISSUER), ("tenant-a", "")):
            with self.subTest(tenant=tenant, issuer=issuer), self.assertRaises(AuthorizationDenied):
                self.check(self.principal(), tenant, issuer=issuer)

    def test_malformed_identity_rejected(self):
        for tenant in ("", " tenant-a", "tenant-a ", "x" * 257):
            with self.subTest(tenant=tenant), self.assertRaises(ValueError):
                self.principal(tenant=tenant)

if __name__ == "__main__":
    unittest.main()
