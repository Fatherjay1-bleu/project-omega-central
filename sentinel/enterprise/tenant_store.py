"""Isolated staging tenant event storage; not a production datastore."""
import json
import sqlite3
from pathlib import Path
from .tenant_policy import Action, require_tenant_grant

MAX_PAYLOAD_BYTES = 65536

class TenantEventStore:
    def __init__(self, path, *, trusted_issuer):
        if type(trusted_issuer) is not str or not trusted_issuer:
            raise ValueError("trusted issuer required")
        self.path = str(Path(path))
        self.trusted_issuer = trusted_issuer

    def initialize(self):
        with sqlite3.connect(self.path) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS tenant_events (
                tenant_id TEXT NOT NULL, event_id TEXT NOT NULL,
                payload TEXT NOT NULL, PRIMARY KEY (tenant_id, event_id))""")

    def put(self, principal, tenant_id, event_id, payload):
        require_tenant_grant(principal, tenant_id, Action.INGEST, trusted_issuer=self.trusted_issuer)
        if type(event_id) is not str or not 1 <= len(event_id) <= 128 or event_id.strip() != event_id:
            raise ValueError("invalid event id")
        if type(payload) is not dict:
            raise ValueError("invalid payload")
        encoded = json.dumps(payload, allow_nan=False, separators=(",", ":"), sort_keys=True)
        if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload too large")
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO tenant_events (tenant_id,event_id,payload) VALUES (?,?,?)",
                       (tenant_id,event_id,encoded))

    def get(self, principal, tenant_id, event_id):
        require_tenant_grant(principal, tenant_id, Action.READ, trusted_issuer=self.trusted_issuer)
        if type(event_id) is not str or not 1 <= len(event_id) <= 128:
            raise ValueError("invalid event id")
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT payload FROM tenant_events WHERE tenant_id=? AND event_id=?",
                             (tenant_id,event_id)).fetchone()
        return json.loads(row[0]) if row else None
