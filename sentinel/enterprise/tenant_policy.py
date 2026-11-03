"""Staging authorization policy. Provenance guard is defense-in-depth, not a Python security sandbox."""
from dataclasses import dataclass, field
from enum import Enum
import hmac

class AuthorizationDenied(PermissionError):
    """Missing, invalid, or cross-tenant authorization."""

class Action(str, Enum):
    READ = "read"
    INGEST = "ingest"
    MANAGE = "manage"

ROLE_GRANTS = {
    "viewer": frozenset({Action.READ}),
    "analyst": frozenset({Action.READ, Action.INGEST}),
    "admin": frozenset({Action.READ, Action.INGEST, Action.MANAGE}),
}

# In-process capability only. Do not treat this as protection against malicious Python code.
_PROVENANCE = object()

@dataclass(frozen=True)
class VerifiedPrincipal:
    subject: str
    tenant_id: str
    role: str
    issuer: str
    _proof: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if any(type(value) is not str or not value or len(value) > 256 or value.strip() != value
               for value in (self.subject, self.tenant_id, self.role, self.issuer)):
            raise ValueError("invalid verified principal")

def _mint_verified_principal(subject, tenant_id, role, issuer):
    """Only call after independently verifying token and server-side membership."""
    return VerifiedPrincipal(subject, tenant_id, role, issuer, _PROVENANCE)

def require_tenant_grant(principal, resource_tenant_id, action, *, trusted_issuer):
    if type(principal) is not VerifiedPrincipal or principal._proof is not _PROVENANCE:
        raise AuthorizationDenied("trusted identity provenance required")
    if type(trusted_issuer) is not str or not trusted_issuer:
        raise AuthorizationDenied("trusted issuer required")
    if not hmac.compare_digest(principal.issuer, trusted_issuer):
        raise AuthorizationDenied("untrusted issuer")
    if type(resource_tenant_id) is not str or not resource_tenant_id:
        raise AuthorizationDenied("resource tenant required")
    if not hmac.compare_digest(principal.tenant_id, resource_tenant_id):
        raise AuthorizationDenied("cross-tenant access denied")
    if type(action) is not Action or action not in ROLE_GRANTS.get(principal.role, ()):
        raise AuthorizationDenied("grant denied")
    return True
