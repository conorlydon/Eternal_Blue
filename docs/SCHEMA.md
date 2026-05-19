# Eternal-Blue Database Schema

**Database:** PostgreSQL  
**Host:** localhost (internal only — not exposed outside the VM)  
**Database name:** eternalblue_db  
**User:** eternalblue

---

## Tables

### users
Stores registered users, their hashed passwords, and their public keys.

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(32) UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    key_version     INTEGER DEFAULT 1,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key, auto-generated |
| `username` | VARCHAR(32) | Unique, alphanumeric + underscores only |
| `password_hash` | TEXT | Argon2id hash — plaintext password never stored |
| `public_key` | TEXT | Base64url-encoded X25519 public key |
| `key_version` | INTEGER | Increments on key rotation — used for TOFU detection |
| `created_at` | TIMESTAMPTZ | Registration timestamp |

---

### conversations
One row per unique pair of users. Created automatically when the first message is sent between two users.

```sql
CREATE TABLE conversations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_a_id       UUID NOT NULL REFERENCES users(id),
    user_b_id       UUID NOT NULL REFERENCES users(id),
    last_message_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_a_id, user_b_id)
);
```

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key, auto-generated |
| `user_a_id` | UUID | Foreign key → users |
| `user_b_id` | UUID | Foreign key → users |
| `last_message_at` | TIMESTAMPTZ | Updated on every new message — used to sort inbox |
| `created_at` | TIMESTAMPTZ | When the conversation was first created |

> The UNIQUE constraint on `(user_a_id, user_b_id)` ensures only one conversation exists per pair of users.

---

### messages
Stores encrypted message blobs. The server never stores or sees plaintext — only ciphertext produced by the C++ client.

```sql
CREATE TABLE messages (
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
```

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key, auto-generated |
| `conversation_id` | UUID | Foreign key → conversations |
| `sender_id` | UUID | Foreign key → users |
| `recipient_id` | UUID | Foreign key → users |
| `ciphertext` | TEXT | Base64url-encoded HPKE-encrypted payload |
| `encapsulated_key` | TEXT | Base64url-encoded HPKE `enc` value |
| `nonce` | TEXT | Base64url-encoded AES-GCM nonce (12 bytes) |
| `sent_at` | TIMESTAMPTZ | Message send timestamp |
| `read_at` | TIMESTAMPTZ | NULL until recipient opens the conversation |
| `is_forwarded` | BOOLEAN | TRUE if this is a forwarded copy |
| `original_message_id` | UUID | Points to the original message if forwarded, otherwise NULL |
| `deleted_by_sender` | BOOLEAN | TRUE if sender deleted from their outbox |
| `deleted_by_recipient` | BOOLEAN | TRUE if recipient deleted from their inbox |

> Deletion is soft — rows are never removed from the database. A message is hidden from a user's view when their respective deleted flag is TRUE. This preserves the audit trail and blockchain integrity.

---

### revocations
Records when an original sender revokes a forwarded copy. Kept as a separate table to provide an audit trail.

```sql
CREATE TABLE revocations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id  UUID NOT NULL REFERENCES messages(id),
    revoked_by  UUID NOT NULL REFERENCES users(id),
    revoked_at  TIMESTAMPTZ DEFAULT NOW()
);
```

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key, auto-generated |
| `message_id` | UUID | The forwarded message being revoked |
| `revoked_by` | UUID | Must be the original sender |
| `revoked_at` | TIMESTAMPTZ | Revocation timestamp |

> Only the original sender of a message can revoke a forwarded copy. The API enforces this — a 403 is returned if the requesting user is not the original sender.

---

### digest_queue
Holds keccak256 hashes of message ciphertexts waiting to be written to the Sepolia blockchain. Rows remain here with `batch_id = NULL` until the next digest flush runs.

```sql
CREATE TABLE digest_queue (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id  UUID NOT NULL REFERENCES messages(id),
    digest      TEXT NOT NULL,
    queued_at   TIMESTAMPTZ DEFAULT NOW(),
    batch_id    UUID DEFAULT NULL
);
```

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key, auto-generated |
| `message_id` | UUID | The message this digest belongs to |
| `digest` | TEXT | keccak256 hash of the message ciphertext (hex string) |
| `queued_at` | TIMESTAMPTZ | When the digest was queued |
| `batch_id` | UUID | NULL until batched — set when written to blockchain |

> The digest flush runs on a fixed time interval (configurable via `DIGEST_FLUSH_INTERVAL_MS` in `.env`, default 10 minutes). All rows with `batch_id = NULL` are collected, combined into a single batch hash, written to the Solidity contract on Sepolia, and then stamped with the resulting `batch_id`.

---

### blockchain_records
Stores the result of each successful digest flush — the on-chain transaction hash and the batch it corresponds to.

```sql
CREATE TABLE blockchain_records (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id     UUID NOT NULL,
    batch_hash   TEXT NOT NULL,
    tx_hash      TEXT NOT NULL,
    block_number INTEGER,
    recorded_at  TIMESTAMPTZ DEFAULT NOW()
);
```

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key, auto-generated |
| `batch_id` | UUID | Links to `digest_queue.batch_id` |
| `batch_hash` | TEXT | keccak256 of all digests in the batch combined |
| `tx_hash` | TEXT | Ethereum transaction hash returned by Sepolia |
| `block_number` | INTEGER | Block the transaction was mined in |
| `recorded_at` | TIMESTAMPTZ | When the record was inserted |

> To verify a message: look up its `digest_queue` row to find the `batch_id`, then look up `blockchain_records` for that `batch_id` to get the `tx_hash`. The verification page fetches the `batch_hash` from Sepolia using the `tx_hash` and recomputes it locally to confirm a match.

---

## Indexes

```sql
CREATE INDEX idx_messages_conversation ON messages(conversation_id);
CREATE INDEX idx_messages_recipient    ON messages(recipient_id);
CREATE INDEX idx_messages_sender       ON messages(sender_id);
CREATE INDEX idx_conversations_user_a  ON conversations(user_a_id);
CREATE INDEX idx_conversations_user_b  ON conversations(user_b_id);
CREATE INDEX idx_digest_queue_batch    ON digest_queue(batch_id);
```

These indexes cover the most common query patterns — loading a conversation's messages, loading a user's inbox, and finding unbatched digest queue rows.

---

## Entity Relationships

```
users ──< conversations >── users
users ──< messages
conversations ──< messages
messages ──< messages (self-ref: original_message_id)
messages ──< revocations
messages ──< digest_queue
digest_queue >── blockchain_records (via batch_id)
```

---

## Security Notes

- **Passwords** are stored as Argon2id hashes. The plaintext password is never written to disk.
- **Message content** is never stored in plaintext. The server stores ciphertext only — decryption happens exclusively on the C++ client.
- **Private keys** never leave the client machine. The database has no column for private keys.
- **PostgreSQL** is configured to listen on localhost only (`listen_addresses = 'localhost'`). The database port is not exposed outside the VM.
- **Soft deletes** are used throughout — no data is physically removed, preserving the blockchain audit trail.