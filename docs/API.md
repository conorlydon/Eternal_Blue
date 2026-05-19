# Eternal-Blue API Reference

**Base URL:** `https://eternalblue.theburkenator.com/api`  
**During development:** `http://200.69.13.70:3000/api`  
**Content-Type:** `application/json` on all requests and responses  
**Auth:** All endpoints marked 🔒 require `Authorization: Bearer <token>` header

---

## Conventions

### Binary data encoding
All binary data (ciphertext, keys, nonces) is encoded as **base64url** (no padding) in JSON strings.

### Standard error response
Every error returns this shape:
```json
{
  "error": "ERROR_CODE",
  "message": "Human readable description"
}
```

| Code | HTTP Status | Meaning |
|---|---|---|
| `INVALID_INPUT` | 400 | Missing or malformed field |
| `UNAUTHORIZED` | 401 | Missing or invalid token |
| `FORBIDDEN` | 403 | Token valid but action not permitted |
| `NOT_FOUND` | 404 | Resource does not exist |
| `CONFLICT` | 409 | e.g. username already taken |
| `SERVER_ERROR` | 500 | Unexpected server error |

### Timestamps
All timestamps are **ISO 8601 UTC** strings, e.g. `"2026-05-19T14:32:00Z"`.

### IDs
All resource IDs are **UUIDs v4** strings.

---

## Auth

### POST /auth/register
Register a new user and publish their public key.

**Request:**
```json
{
  "username": "alice",
  "password": "correct-horse-battery-staple",
  "public_key": "base64url-encoded-x25519-public-key"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `username` | string | ✓ | 3–32 chars, alphanumeric + underscores only |
| `password` | string | ✓ | Min 12 chars |
| `public_key` | string | ✓ | base64url-encoded X25519 public key (32 bytes → 43 chars) |

**Success — 201 Created:**
```json
{
  "user_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "username": "alice"
}
```

**Errors:**
- `409 CONFLICT` — username already taken
- `400 INVALID_INPUT` — missing field or format violation

---

### POST /auth/login
Authenticate and receive a JWT.

**Request:**
```json
{
  "username": "alice",
  "password": "correct-horse-battery-staple"
}
```

**Success — 200 OK:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2026-05-20T14:32:00Z",
  "user_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

**Errors:**
- `401 UNAUTHORIZED` — wrong password
- `404 NOT_FOUND` — username does not exist

> **Note:** Token lifetime is 24 hours. The C++ client stores this in memory only — not persisted to disk.

---

## Keys

### GET /keys/:username 🔒
Look up another user's public key. Used by the sender before encrypting a message.

**Response — 200 OK:**
```json
{
  "username": "bob",
  "user_id": "a3bb189e-8bf9-3888-9912-ace4e6543002",
  "public_key": "base64url-encoded-x25519-public-key",
  "published_at": "2026-05-19T10:00:00Z",
  "key_version": 1
}
```

**Errors:**
- `404 NOT_FOUND` — no user with that username

> **TOFU note:** The C++ client pins the first public key it receives for a given username. If `key_version` increases on a subsequent fetch, the client must warn the user loudly before proceeding. This is the Trust On First Use model.

---

### PUT /keys/update 🔒
Replace the authenticated user's public key (e.g. after key rotation).

**Request:**
```json
{
  "public_key": "base64url-encoded-new-x25519-public-key"
}
```

**Success — 200 OK:**
```json
{
  "key_version": 2,
  "updated_at": "2026-05-19T15:00:00Z"
}
```

---

## Messages

### POST /messages 🔒
Send an encrypted message to another user.

The server stores ciphertext only — it never sees plaintext.

**Request:**
```json
{
  "recipient_username": "bob",
  "ciphertext": "base64url-encoded-aead-ciphertext",
  "session_key": "base64url-encoded-hpke-enc",
  "nonce": "base64url-encoded-nonce"
}
```

| Field                | Type | Required | Notes |
|----------------------|---|---|---|
| `recipient_username` | string | ✓ | Must be a registered user |
| `ciphertext`         | string | ✓ | HPKE-encrypted payload (base64url) |
| `session_key`        | string | ✓ | HPKE `enc` value (base64url) |
| `nonce`              | string | ✓ | 12-byte AES-GCM nonce (base64url) |

**Success — 201 Created:**
```json
{
  "message_id": "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
  "sent_at": "2026-05-19T14:32:00Z"
}
```

**Errors:**
- `404 NOT_FOUND` — recipient does not exist
- `400 INVALID_INPUT` — missing or malformed field

---

### GET /messages 🔒
Fetch all messages in the authenticated user's inbox (received) and outbox (sent).

**Query params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `box` | `inbox` \| `outbox` \| `all` | `all` | Filter by direction |
| `since` | ISO 8601 string | — | Only return messages after this time |
| `limit` | integer | 50 | Max 100 |

**Example:** `GET /messages?box=inbox&limit=20`

**Success — 200 OK:**
```json
{
  "messages": [
    {
      "message_id": "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
      "sender_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "sender_username": "alice",
      "recipient_id": "a3bb189e-8bf9-3888-9912-ace4e6543002",
      "recipient_username": "bob",
      "ciphertext": "base64url-encoded-aead-ciphertext",
      "session_key": "base64url-encoded-hpke-enc",
      "nonce": "base64url-encoded-nonce",
      "sent_at": "2026-05-19T14:32:00Z",
      "is_forwarded": false,
      "original_message_id": null
    }
  ],
  "total": 1
}
```

---

### GET /messages/:id 🔒
Fetch a single message by ID. Requester must be the sender or recipient.

**Success — 200 OK:** Same shape as a single item from the list above.

**Errors:**
- `403 FORBIDDEN` — requester is neither sender nor recipient
- `404 NOT_FOUND` — message does not exist or was deleted

---

### POST /messages/:id/forward 🔒
Forward a received message to a third user. The server records the forward relationship.

The client must re-encrypt the plaintext for the new recipient before calling this endpoint — the server does not re-encrypt.

**Request:**
```json
{
  "forward_to_username": "charlie",
  "ciphertext": "base64url-encoded-re-encrypted-ciphertext",
  "encapsulated_key": "base64url-encoded-hpke-enc-for-charlie",
  "nonce": "base64url-encoded-nonce"
}
```

**Success — 201 Created:**
```json
{
  "message_id": "new-uuid-for-forwarded-copy",
  "forwarded_at": "2026-05-19T15:00:00Z",
  "original_message_id": "c9bf9e57-1685-4c89-bafb-ff5af830be8a"
}
```
---
## Conversations

### GET /conversations 🔒
Load all conversations for the authenticated user. Called on application startup.
Returns metadata only — no ciphertext. One entry per unique exchange.

**Success — 200 OK:**
```json
{
  "conversations": [
    {
      "conversation_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "with_user_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "with_username": "alice",
      "last_message_at": "2026-05-19T14:32:00Z",
      "unread_count": 3
    },
    {
      "conversation_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "with_user_id": "a3bb189e-8bf9-3888-9912-ace4e6543002",
      "with_username": "charlie",
      "last_message_at": "2026-05-18T09:00:00Z",
      "unread_count": 0
    }
  ],
  "total": 2
}
```

**Errors:**
- `401 UNAUTHORIZED` — missing or invalid token

---

### GET /conversations/:conversation_id/messages 🔒
Load all messages for a specific conversation. Called only when the user opens that conversation.
Returns full message objects including ciphertext.

**Query params:**

| Param | Type | Default | Notes |
|---|---|---|---|
| `limit` | integer | 50 | Max 100 |
| `before` | ISO 8601 string | — | For pagination — return messages before this timestamp |

**Example:** `GET /conversations/a1b2c3d4-e5f6-7890-abcd-ef1234567890/messages?limit=50`

**Success — 200 OK:**
```json
{
  "conversation_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "with_user_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "with_username": "alice",
  "messages": [
    {
      "message_id": "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
      "sender_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "sender_username": "alice",
      "recipient_id": "a3bb189e-8bf9-3888-9912-ace4e6543002",
      "recipient_username": "bob",
      "ciphertext": "base64url-encoded-aead-ciphertext",
      "session_key": "base64url-encoded-hpke-enc",
      "nonce": "base64url-encoded-nonce",
      "sent_at": "2026-05-19T14:32:00Z",
      "read_at": null,
      "is_forwarded": false,
      "original_message_id": null
    }
  ],
  "total": 12
}
```

**Errors:**
- `403 FORBIDDEN` — authenticated user is not a participant in this conversation
- `404 NOT_FOUND` — conversation does not exist

---

### POST /conversations/:conversation_id/read 🔒
Mark all unread messages in a conversation as read. Called when the user opens a conversation.

**Success — 200 OK:**
```json
{
  "conversation_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "marked_read": 3
}
```

**Errors:**
- `403 FORBIDDEN` — authenticated user is not a participant in this conversation
- `404 NOT_FOUND` — conversation does not exist
---

### DELETE /messages/:id/revoke 🔒
Revoke a recipient's access to a previously forwarded message. Only the original sender can revoke.

**Success — 200 OK:**
```json
{
  "revoked": true,
  "message_id": "new-uuid-for-forwarded-copy",
  "revoked_at": "2026-05-19T15:30:00Z"
}
```

**Errors:**
- `403 FORBIDDEN` — requester is not the original sender

---

### DELETE /messages/:id 🔒
Delete a message. Sender can delete from outbox; recipient can delete from inbox.

**Success — 200 OK:**
```json
{
  "deleted": true,
  "message_id": "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
  "deleted_at": "2026-05-19T15:45:00Z"
}
```

---

## Blockchain

### GET /blockchain/digest/:message_id 🔒
Retrieve the on-chain record for a message or batch containing a message.

**Success — 200 OK:**
```json
{
  "message_id": "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
  "batch_hash": "0xabc123...",
  "tx_hash": "0xdef456...",
  "block_number": 7291834,
  "recorded_at": "2026-05-19T14:35:00Z",
  "sepolia_url": "https://sepolia.etherscan.io/tx/0xdef456..."
}
```

**Errors:**
- `404 NOT_FOUND` — no on-chain record yet (batch may not have been submitted)

---

## Health

### GET /health
Public endpoint. No auth required. Used by nginx and during development to confirm the server is running.

**Success — 200 OK:**
```json
{
  "status": "ok",
  "team": "eternal-blue",
  "timestamp": "2026-05-19T14:32:00Z"
}
```

---

## Summary table

| Method | Path                                       | Auth | Description                                   |
|--------|--------------------------------------------|---|-----------------------------------------------|
| POST   | `/auth/register`                           | — | Register + publish public key                 |
| POST   | `/auth/login`                              | — | Login, receive JWT                            |
| GET    | `/keys/:username`                          | 🔒 | Get a user's public key                       |
| PUT    | `/keys/update`                             | 🔒 | Rotate own public key                         |
| POST   | `/messages`                                | 🔒 | Send encrypted message                        |
| GET    | `/messages`                                | 🔒 | List inbox / outbox                           |
| GET    | `/messages/:id`                            | 🔒 | Get single message                            |
| POST   | `/messages/:id/forward`                    | 🔒 | Forward to another user                       |
| DELETE | `/messages/:id/revoke`                     | 🔒 | Revoke forwarded access                       |
| GET    | `/conversations`                           | 🔒 | Load all conversations                        |
| GET    | `/conversations/:conversation_id/messages` | 🔒 | Load all messages for a specific conversation |
| GET    | `/conversations/:conversation_id/read` | 🔒 | Mark all unread messages in a conversation as read |
| GET    | `/keys/:username`                          | 🔒 | Get a user's public key                       |
| GET    | `/blockchain/digest/:id`                   | 🔒 | Get on-chain record for message               |
| GET    | `/health`                                  | — | Server health check                           |