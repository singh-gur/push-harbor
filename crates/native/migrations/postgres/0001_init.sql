-- Same schema as migrations/sqlite, plus shared rate-limit counters (instances must agree).

-- Confirmed registrations: one row per Web Push endpoint.
CREATE TABLE registrations (
    endpoint   TEXT PRIMARY KEY,
    platform   TEXT NOT NULL,
    target     TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    sender_key BYTEA NOT NULL,
    created_at BIGINT NOT NULL
);

-- Registrations waiting for their challenge answer (expire after 5 minutes).
CREATE TABLE pending_registrations (
    rid             TEXT PRIMARY KEY,
    platform        TEXT NOT NULL,
    target          TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    sender_key      BYTEA NOT NULL,
    nonce           TEXT NOT NULL,
    expires_at      BIGINT NOT NULL,
    challenges_sent BIGINT NOT NULL,
    replaces        TEXT
);

-- Idempotency-Key claims (1 h window). Payloads are never stored.
CREATE TABLE idempotency (
    endpoint   TEXT NOT NULL,
    key        TEXT NOT NULL,
    delivered  BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (endpoint, key)
);

-- Fixed-window rate-limit counters, one row per bucket (global, per IP/sender/endpoint, ...).
CREATE TABLE rate_limits (
    bucket     TEXT PRIMARY KEY,
    window_end BIGINT NOT NULL,
    count      BIGINT NOT NULL
);

CREATE INDEX pending_expiry ON pending_registrations (expires_at);
CREATE INDEX idempotency_expiry ON idempotency (expires_at);
CREATE INDEX rate_limits_expiry ON rate_limits (window_end);
