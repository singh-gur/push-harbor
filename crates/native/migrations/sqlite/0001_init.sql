-- Confirmed registrations: one row per Web Push endpoint.
CREATE TABLE registrations (
    endpoint   TEXT PRIMARY KEY,
    platform   TEXT NOT NULL,
    target     TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    sender_key BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

-- Registrations waiting for their challenge answer (expire after 5 minutes).
CREATE TABLE pending_registrations (
    rid             TEXT PRIMARY KEY,
    platform        TEXT NOT NULL,
    target          TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    sender_key      BLOB NOT NULL,
    nonce           TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    challenges_sent INTEGER NOT NULL,
    replaces        TEXT
);

-- Idempotency-Key claims (1 h window). Payloads are never stored.
CREATE TABLE idempotency (
    endpoint   TEXT NOT NULL,
    key        TEXT NOT NULL,
    delivered  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (endpoint, key)
);

CREATE INDEX pending_expiry ON pending_registrations (expires_at);
CREATE INDEX idempotency_expiry ON idempotency (expires_at);
