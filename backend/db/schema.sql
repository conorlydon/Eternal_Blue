-- Eternal-Blue database schema
-- Source of truth: docs/SCHEMA.md
--
-- Apply against a fresh database:
--   docker exec -i eb-postgres psql -U eternalblue -d eternalblue_db < backend/db/schema.sql
-- or
--   psql -h localhost -U eternalblue -d eternalblue_db -f backend/db/schema.sql
--
-- Idempotent: re-running on an existing DB will not error.

-- gen_random_uuid() ships in pgcrypto pre-PG13 and in core PG13+.
-- The extension is harmless on PG13+ — it just no-ops.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(32) UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    key_version     INTEGER DEFAULT 1,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- conversations  (one row per unique pair of users)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS conversations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_a_id       UUID NOT NULL REFERENCES users(id),
    user_b_id       UUID NOT NULL REFERENCES users(id),
    last_message_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_a_id, user_b_id),
    CHECK (user_a_id < user_b_id)
);

-- ---------------------------------------------------------------------------
-- messages  (ciphertext only — server never sees plaintext)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS messages (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id       UUID NOT NULL REFERENCES conversations(id),
    sender_id             UUID NOT NULL REFERENCES users(id),
    recipient_id          UUID NOT NULL REFERENCES users(id),
    ciphertext            TEXT NOT NULL,
    encapsulated_key      TEXT NOT NULL,
    nonce                 TEXT NOT NULL,
    sent_at               TIMESTAMPTZ DEFAULT NOW(),
    read_at               TIMESTAMPTZ DEFAULT NULL,
    is_forwarded          BOOLEAN DEFAULT FALSE,
    original_message_id   UUID REFERENCES messages(id),
    deleted_by_sender     BOOLEAN DEFAULT FALSE,
    deleted_by_recipient  BOOLEAN DEFAULT FALSE
);

-- ---------------------------------------------------------------------------
-- revocations  (audit trail for revoked forwarded copies)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS revocations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id  UUID NOT NULL REFERENCES messages(id),
    revoked_by  UUID NOT NULL REFERENCES users(id),
    revoked_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- digest_queue  (pending keccak256 digests awaiting batch flush to Sepolia)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS digest_queue (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id  UUID NOT NULL REFERENCES messages(id),
    digest      TEXT NOT NULL,
    queued_at   TIMESTAMPTZ DEFAULT NOW(),
    batch_id    UUID DEFAULT NULL
);

-- ---------------------------------------------------------------------------
-- blockchain_records  (on-chain tx receipts per flushed batch)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blockchain_records (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id     UUID NOT NULL,
    batch_hash   TEXT NOT NULL,
    tx_hash      TEXT NOT NULL,
    block_number INTEGER,
    recorded_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- Indexes  (most common query patterns)
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_messages_recipient    ON messages(recipient_id);
CREATE INDEX IF NOT EXISTS idx_messages_sender       ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_conversations_user_a  ON conversations(user_a_id);
CREATE INDEX IF NOT EXISTS idx_conversations_user_b  ON conversations(user_b_id);
CREATE INDEX IF NOT EXISTS idx_digest_queue_batch    ON digest_queue(batch_id);
