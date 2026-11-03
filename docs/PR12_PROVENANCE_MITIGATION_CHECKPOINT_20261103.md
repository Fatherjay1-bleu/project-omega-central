# Principal provenance mitigation checkpoint — 2026-11-03

The enterprise staging authorization policy now rejects a directly constructed `VerifiedPrincipal` unless it carries a module-local provenance marker. The gateway mints marked principals only after its injected verifier and server-side membership resolver accept the request. The previously expected-failing direct-construction test now asserts denial without `expectedFailure`.

**Limitations:** Python module-private names and object markers are NOT a robust trust boundary against malicious in-process code; the mint helper is importable. This change prevents accidental acceptance of untrusted plain principal objects but is not a production-grade proof of authenticated identity. Do not pass untrusted requests to internal helpers. A real OIDC verifier, authenticated HTTP boundary, trusted membership storage, and independent security review remain P0 blockers.

**Verification:** Code and tests committed; execution of the updated suite is pending. No claim of passing regression tests. Public demo and main remain unchanged.
