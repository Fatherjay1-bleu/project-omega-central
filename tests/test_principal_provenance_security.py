"""Regression tests for staging principal provenance; not an in-process sandbox."""
import unittest
from sentinel.enterprise.tenant_policy import (
    Action, AuthorizationDenied, VerifiedPrincipal, require_tenant_grant,
)

ISSUER = "https://identity.example.test"

class PrincipalProvenanceSecurityTests(unittest.TestCase):
    def test_directly_constructed_principal_must_not_authorize_manage(self):
        forged = VerifiedPrincipal("attacker", "victim-tenant", "admin", ISSUER)
        with self.assertRaises(AuthorizationDenied):
            require_tenant_grant(forged, "victim-tenant", Action.MANAGE, trusted_issuer=ISSUER)

    def test_directly_constructed_principal_must_not_read_or_ingest(self):
        forged = VerifiedPrincipal("attacker", "victim-tenant", "admin", ISSUER)
        for action in (Action.READ, Action.INGEST):
            with self.subTest(action=action), self.assertRaises(AuthorizationDenied):
                require_tenant_grant(forged, "victim-tenant", action, trusted_issuer=ISSUER)

    def test_injected_arbitrary_proof_is_denied(self):
        forged = VerifiedPrincipal("attacker", "victim-tenant", "admin", ISSUER, object())
        with self.assertRaises(AuthorizationDenied):
            require_tenant_grant(forged, "victim-tenant", Action.MANAGE, trusted_issuer=ISSUER)

if __name__ == "__main__":
    unittest.main()
