-- agno-dcp Postgres schema.
-- Idempotent: every CREATE uses IF NOT EXISTS, so re-applying this
-- file against an existing database is safe.
--
-- All tables are prefixed dcp_* so they coexist cleanly with the
-- native Agno tables (sessions, runs, etc.) in the same database.
--
-- Apply with: psql $DATABASE_URL -f schema.sql

BEGIN;

CREATE TABLE IF NOT EXISTS dcp_citizenship_bundles (
    agent_id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dcp_intents (
    intent_id BIGSERIAL PRIMARY KEY,
    agent_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dcp_intents_agent
    ON dcp_intents (agent_id);
CREATE INDEX IF NOT EXISTS idx_dcp_intents_created
    ON dcp_intents (created_at);

CREATE TABLE IF NOT EXISTS dcp_policy_decisions (
    decision_id BIGSERIAL PRIMARY KEY,
    agent_id TEXT NOT NULL,
    approved BOOLEAN NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dcp_decisions_agent
    ON dcp_policy_decisions (agent_id);

CREATE TABLE IF NOT EXISTS dcp_audit_chain (
    entry_index BIGSERIAL PRIMARY KEY,
    agent_id TEXT,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dcp_audit_agent
    ON dcp_audit_chain (agent_id);
CREATE INDEX IF NOT EXISTS idx_dcp_audit_event
    ON dcp_audit_chain (event_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dcp_audit_entry_hash
    ON dcp_audit_chain (entry_hash);

CREATE TABLE IF NOT EXISTS dcp_audit_roots (
    root_id BIGSERIAL PRIMARY KEY,
    agent_id TEXT,
    root_hash TEXT NOT NULL,
    entry_count BIGINT NOT NULL,
    signature_b64 TEXT NOT NULL,
    signer_public_key_b64 TEXT NOT NULL,
    sealed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dcp_roots_agent
    ON dcp_audit_roots (agent_id);
CREATE INDEX IF NOT EXISTS idx_dcp_roots_sealed
    ON dcp_audit_roots (sealed_at);

COMMIT;
