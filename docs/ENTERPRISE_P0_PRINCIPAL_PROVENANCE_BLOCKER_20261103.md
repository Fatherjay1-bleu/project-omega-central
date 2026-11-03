# P0: Principal provenance is not enforced

## Reproduction
At branch commit cfd950e, `VerifiedPrincipal` is a public dataclass.
Any in-process caller can construct `VerifiedPrincipal("attacker", "victim-tenant", "admin", trusted_issuer)` and pass it to `require_tenant_grant`; the authorization function returns True. A local isolated Python reproduction confirmed this behavior. This is not proof of remote exploitability; no enterprise HTTP endpoint has been enabled.

`tests/test_principal_provenance_security.py` captures the intended deny behavior as an **expected failure**. It MUST NOT be counted as a passed security acceptance criterion.

## Required remediation
- Make verified identity an output of a trusted authentication boundary, not a user-constructible claim container.
- Ensure no HTTP or RPC handler accepts a principal, tenant, role, or issuer directly from request JSON, headers, or unverified JWT payloads.
- Enforce server-side tenant membership and role checks at every storage/API operation.
- Add tests proving forged principals and injected role claims are denied, including end-to-end HTTP tests.
- Implement real OIDC signature, algorithm, issuer, audience, expiry, token type, JWKS key rotation and outage handling.
- Replace this expected failure with a passing denial test; obtain independent review before production.

Production gate: **NO-GO** until fixed and independently verified.
