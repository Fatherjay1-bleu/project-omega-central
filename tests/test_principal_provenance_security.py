"""Known P0 gap: direct construction of VerifiedPrincipal bypasses identity provenance.

Expected failure documents a reproducible security gap, NOT a passing security gate.
Remove expectedFailure only after gateway-minted identity provenance is enforced.
"""
import unittest
from sentinel.enterprise.tenant_policy import Action, AuthorizationDenied, VerifiedPrincipal, require_tenant_grant

ISSUER = "https://identity.example.test"

class PrincipalProvenanceSecurityTests(unittest.TestCase):
    @unittest.expectedFailure
    def test_directly_constructed_principal_must_not_authorize_manage(self):
        forged = VerifiedPrincipal("attacker", "victim-tenant", "admin", ISSUER)
        with self.assertRaises(AuthorizationDenied):
            require_tenant_grant(forged, "victim-tenant", Action.MANAGE, trusted_issuer=ISSUER)

if __name__ == "__main__":
    unittest.main()
