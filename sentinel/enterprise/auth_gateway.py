"""Staging-only authenticated gateway. A real OIDC verifier is NOT supplied here.

The trusted verifier must validate signature, algorithm allowlist, issuer,
audience, expiry, token type, and key rotation before returning claims.
Roles/membership must be resolved from trusted server-side authorization data.
This module is not wired into the public demo.
"""
from .tenant_policy import AuthorizationDenied, VerifiedPrincipal

class EnterpriseAuthGateway:
    def __init__(self, *, token_verifier, membership_resolver, trusted_issuer):
        if not callable(token_verifier) or not callable(membership_resolver):
            raise ValueError("trusted verifier and membership resolver required")
        if type(trusted_issuer) is not str or not trusted_issuer:
            raise ValueError("trusted issuer required")
        self._verify = token_verifier
        self._membership = membership_resolver
        self._issuer = trusted_issuer

    def authenticate(self, bearer_token, tenant_id):
        if (type(bearer_token) is not str or not 1 <= len(bearer_token) <= 8192
                or any(ch.isspace() for ch in bearer_token)
                or type(tenant_id) is not str or not 1 <= len(tenant_id) <= 256):
            raise AuthorizationDenied("invalid authentication request")
        try:
            claims = self._verify(bearer_token)
            if type(claims) is not dict or set(claims) != {"sub", "iss"}:
                raise AuthorizationDenied("untrusted identity claims")
            if claims["iss"] != self._issuer:
                raise AuthorizationDenied("issuer mismatch")
            subject = claims["sub"]
            if type(subject) is not str or not subject or len(subject) > 256:
                raise AuthorizationDenied("invalid subject")
            role = self._membership(subject, tenant_id)
            if role not in ("viewer", "analyst", "admin") or type(role) is not str:
                raise AuthorizationDenied("membership not granted")
            return VerifiedPrincipal(subject, tenant_id, role, self._issuer)
        except Exception as exc:
            raise AuthorizationDenied("authentication denied") from exc
