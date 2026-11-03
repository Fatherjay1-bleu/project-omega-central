"""Gateway contract tests with fake trusted adapters, NOT OIDC conformance tests."""
import unittest
from sentinel.enterprise.auth_gateway import EnterpriseAuthGateway
from sentinel.enterprise.tenant_policy import AuthorizationDenied, VerifiedPrincipal

ISSUER = "https://identity.example.test"

class GatewayTests(unittest.TestCase):
    def gateway(self, verifier=None, resolver=None):
        return EnterpriseAuthGateway(
            token_verifier=verifier if verifier is not None else lambda token: {"sub": "alice", "iss": ISSUER},
            membership_resolver=resolver if resolver is not None else lambda sub, tenant: "analyst" if tenant == "a" else None,
            trusted_issuer=ISSUER)

    def test_trusted_adapters_return_scoped_principal(self):
        p = self.gateway().authenticate("opaque-token", "a")
        self.assertEqual(p, VerifiedPrincipal("alice", "a", "analyst", ISSUER))

    def test_cross_tenant_membership_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.gateway().authenticate("opaque-token", "b")

    def test_unverified_token_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.gateway(verifier=lambda token: (_ for _ in ()).throw(ValueError("bad signature"))).authenticate("x", "a")

    def test_wrong_issuer_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.gateway(verifier=lambda token: {"sub": "alice", "iss": "https://evil.test"}).authenticate("x", "a")

    def test_injected_role_claim_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.gateway(verifier=lambda token: {"sub": "alice", "iss": ISSUER, "role": "admin"}).authenticate("x", "a")

    def test_invalid_subject_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.gateway(verifier=lambda token: {"sub": "", "iss": ISSUER}).authenticate("x", "a")

    def test_unknown_role_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.gateway(resolver=lambda sub, tenant: "superadmin").authenticate("x", "a")

    def test_invalid_token_and_tenant_denied(self):
        for token, tenant in ((None, "a"), ("bad token", "a"), ("x", ""), ("x" * 8193, "a")):
            with self.subTest(token=type(token), tenant=tenant), self.assertRaises(AuthorizationDenied):
                self.gateway().authenticate(token, tenant)

    def test_resolver_failure_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.gateway(resolver=lambda sub, tenant: 1 / 0).authenticate("x", "a")

    def test_missing_trusted_adapters_denied(self):
        with self.assertRaises(ValueError):
            EnterpriseAuthGateway(token_verifier=None, membership_resolver=None, trusted_issuer=ISSUER)

if __name__ == "__main__":
    unittest.main()
