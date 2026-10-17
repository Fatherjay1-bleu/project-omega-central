"""HTTP-layer validation for POST /api/v3/analyze request bodies.

Validates the structure of an incoming JSON request before delegating to
sentinel/batch.py for per-event validation and native-engine scoring.

Browser-origin policy
---------------------
The endpoint is loopback-only (127.0.0.1).  Two complementary checks apply
to browser-initiated requests:

1. Content-Type enforcement — Flask's request.get_json(force=False) only
   parses bodies with Content-Type: application/json.  A cross-origin HTML
   form cannot set this type, blocking classic CSRF form submissions.

2. Origin / Sec-Fetch-Site check — browser requests originating from a
   different origin carry a non-null Origin header or a Sec-Fetch-Site value
   other than "same-origin" / "none".  Requests from external origins are
   rejected with 403.  Requests with no browser origin metadata (e.g. curl,
   native tools) are allowed; this endpoint is loopback-only and carries no
   persistent session credentials.

X-Requested-With is NOT used as an authentication or security mechanism.
"""
from sentinel.batch import MAX_BATCH_SIZE, analyze_batch
from sentinel.orchestrator import EngineError  # noqa: F401 re-exported for callers

# Maximum request body size in bytes — enforced at the Flask layer via
# app.config["MAX_CONTENT_LENGTH"].  Declared here so app.py can import it.
MAX_CONTENT_LENGTH = 256 * 1024   # 256 KB

# Fixed-vocabulary error messages — never echo raw user input.
_ERR_NOT_JSON      = "Request body must be JSON with Content-Type: application/json."
_ERR_NOT_OBJECT    = "Request body must be a JSON object."
_ERR_MISSING_ARRAY = "Request body must contain an 'events' array."
_ERR_NOT_ARRAY     = "'events' must be a JSON array."
_ERR_TOO_LARGE     = f"'events' array exceeds the maximum of {MAX_BATCH_SIZE} events."
_ERR_ORIGIN        = "Cross-origin requests are not permitted."


class IngestionError(ValueError):
    """Raised when the HTTP request structure is invalid."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.http_status = status


def check_origin(origin_header, sec_fetch_site_header):
    """Reject browser requests that originate from a different origin.

    Raises IngestionError(403) when:
    - Origin header is present and is not a loopback address.
    - Sec-Fetch-Site header is present and is not 'same-origin' or 'none'.

    Neither header being present (non-browser clients) is accepted.
    """
    _LOOPBACK = {"http://127.0.0.1:5000", "http://localhost:5000"}
    _SAFE_FETCH_SITES = {"same-origin", "none"}

    if origin_header is not None and origin_header not in _LOOPBACK:
        raise IngestionError(_ERR_ORIGIN, status=403)
    if (sec_fetch_site_header is not None
            and sec_fetch_site_header not in _SAFE_FETCH_SITES):
        raise IngestionError(_ERR_ORIGIN, status=403)


def validate_body(json_body):
    """Validate the parsed JSON body structure.

    Returns the events list on success.
    Raises IngestionError(400) on any structural problem.
    Never echoes raw user values in error messages.
    """
    if json_body is None:
        raise IngestionError(_ERR_NOT_JSON)
    if not isinstance(json_body, dict):
        raise IngestionError(_ERR_NOT_OBJECT)
    if "events" not in json_body:
        raise IngestionError(_ERR_MISSING_ARRAY)
    if not isinstance(json_body["events"], list):
        raise IngestionError(_ERR_NOT_ARRAY)
    if len(json_body["events"]) > MAX_BATCH_SIZE:
        raise IngestionError(_ERR_TOO_LARGE)
    return json_body["events"]


def ingest_and_analyze(json_body, origin_header=None, sec_fetch_site_header=None):
    """Full ingestion pipeline: origin check → body validate → batch analyze.

    Returns a BatchResult on success.
    Raises IngestionError on bad structure or disallowed origin (→ 400/403).
    Raises EngineError on native binary failure (→ 503).
    """
    check_origin(origin_header, sec_fetch_site_header)
    events = validate_body(json_body)
    return analyze_batch(events)
