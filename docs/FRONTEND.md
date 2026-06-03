# Frontend Client

The frontend is an optional, browser-based alternative to the [C++ client](../cpp_client/README.md). It provides the same end-to-end encrypted messaging through any modern browser, with no installation required. It is served as static files directly by the Fastify backend.

---

## Overview

The frontend lives in `frontend/` and is split into two independent pages:

| Path | Purpose |
|---|---|
| `frontend/app/` | Main messaging application (login, register, send/receive messages) |
| `frontend/verification/` | Standalone public tool for verifying message integrity against the blockchain |

Neither page uses a build step or framework. Both are plain ES modules loaded by the browser.

---

## Main Application (`frontend/app/`)

### Architecture

The app is a single-page application built from two files:

- **`index.html`** — full UI markup (auth screen + app shell) with all CSS inline
- **`app.js`** — all logic as a single ES module; no bundler

The HPKE library is the only third-party dependency. It is **npm-installed** (in `backend/`) and served locally — nothing is loaded from a CDN:

```js
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core'
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305'
```

These bare specifiers are resolved by a browser-native **import map** in `index.html`. `@hpke/core` and `@hpke/chacha20poly1305` import `@hpke/common` internally, so all three are mapped:

```html
<script type="importmap">
{ "imports": {
  "@hpke/core": "/vendor/@hpke/core/esm/mod.js",
  "@hpke/chacha20poly1305": "/vendor/@hpke/chacha20poly1305/esm/mod.js",
  "@hpke/common": "/vendor/@hpke/common/esm/mod.js"
} }
</script>
```

The backend serves the installed package's ESM files at `/vendor/@hpke/` via a second `@fastify/static` mount rooted at `backend/node_modules/@hpke` (`server.js`). Running `npm install` in `backend/` is therefore all that's needed — there is no bundler and no build step. (The inline import map is the only inline script; the CSP allows it by its `sha256` hash, so `'unsafe-inline'` is never required. If the import map text changes, recompute that hash in `server.js`.)

### Key generation and storage

On **registration**, the browser generates a fresh X25519 keypair using the HPKE library. The private key never leaves the device unencrypted:

1. A random 16-byte salt and 12-byte IV are generated.
2. PBKDF2 (SHA-256, 600 000 iterations) derives an AES-GCM-256 key from the user's password and the salt.
3. The raw private key bytes are encrypted with AES-GCM.
4. The resulting `{ salt, iv, ct }` blob (all base64url-encoded) is stored in `localStorage` under `eb_key:<username>` and also uploaded to the server as `encrypted_private_key`.

On **login**, the app loads the wrapped key from `localStorage` (or falls back to the server copy on a new device) and decrypts it using the password to recover the in-memory private key. The plaintext private key only ever exists in JavaScript memory for the lifetime of the session.

### Encryption (HPKE)

Every outgoing message is encrypted with **HPKE** (Hybrid Public Key Encryption):

- KEM: `DhkemX25519HkdfSha256`
- KDF: `HkdfSha256`
- AEAD: `ChaCha20-Poly1305`
- Mode: **Auth** — the sender's keypair is bound into the ciphertext, authenticating the sender to the recipient.
- AAD: `"<sender_id>|<recipient_id>|<sent_at_ms>"` — ties the ciphertext to a specific sender, recipient, and timestamp.
- Info label: `"eternal-blue-msg-v1"`

Before encrypting, the app fetches the recipient's current public key from `GET /api/keys/:username` and applies TOFU pinning (see below). The `enc` (encapsulated key) and ciphertext are sent separately to the server; the server stores only ciphertext and never sees plaintext.

### Decryption

Incoming messages are decrypted client-side in the browser. The recipient's private key (held in memory) and the sender's public key (from the TOFU store or fetched on demand) are used to open the HPKE ciphertext. If decryption fails, the message is shown with an error indicator rather than crashing.

Because the sender encrypts *for the recipient*, the sender cannot decrypt their own sent messages on a different device. To work around this, plaintext of sent messages is cached in `localStorage` under `eb_sent` immediately after a successful send.

### TOFU key pinning

The app implements **Trust On First Use** key pinning, matching the behavior of the C++ client:

- On first contact with a user, their public key and `key_version` are saved to `localStorage` under `eb_tofu`.
- On subsequent contact, if the server returns a different public key for the same username, a warning toast is shown before the message is sent or the conversation is opened.

### Session state

All sensitive state lives in a single in-memory object `S`:

```js
const S = {
  token, userId, username,
  privateKey, publicKey,
  suite,
  currentConvId, currentPeer,
  forwardTargetMsgId,
}
```

Nothing in `S` is written to disk. Logging out clears the object and the plaintextCache. The JWT token is valid for 24 hours.

### Password change

Changing the password re-wraps the in-memory private key under the new password (PBKDF2 + AES-GCM with a fresh salt/IV), then sends the new wrapped blob alongside the password change request to `PATCH /api/auth/password`. Both the server copy and the `localStorage` copy are updated atomically from the browser's perspective.

### UI features

| Feature | Description |
|---|---|
| Login / Register | Tab-switched forms on the auth screen |
| Conversation list | Sidebar showing all conversations with unread counts |
| New conversation | Modal — looks up the recipient's public key before opening the compose view |
| Send message | HPKE-encrypts and posts to `POST /api/messages`; Enter to send, Shift+Enter for newline |
| Download | Saves the decrypted plaintext of any message as a `.txt` file |
| Forward | Re-encrypts the plaintext for a different recipient via `POST /api/messages/:id/forward` |
| Revoke | Removes a forwarded message copy via `DELETE /api/messages/:id/revoke` |
| Delete | Deletes a message from the server via `DELETE /api/messages/:id` |
| Change password | Modal that re-wraps the private key and updates both server and localStorage |
| TOFU warnings | Toast notification if a peer's public key has changed since last contact |

### Security notes

- Raw backend error strings are never shown to the user; all HTTP error codes are mapped to safe generic messages in `API_ERRORS`.
- All user-supplied content written to the DOM is escaped through `esc()` before insertion.
- Message action buttons use `data-*` attributes for IDs — no user content is ever placed in HTML attributes.
- The Content-Security-Policy served by the backend restricts `script-src`/`connect-src` to `'self'` (plus a `sha256` hash for the inline import map) and blocks all other inline scripts. With HPKE served locally there are no external script or connection origins.

---

## Verification Page (`frontend/verification/`)

The verification page is a standalone, publicly accessible tool. It does not require login.

### Purpose

Eternal Blue's digest service periodically batches message ciphertexts, hashes them, and records the hash on the Ethereum Sepolia testnet. The verification page lets anyone confirm that a specific message's ciphertext matches the on-chain record — proving the stored ciphertext has not been altered since it was recorded.

### How it works

1. The user enters a **Message ID** (UUID) and the **ciphertext** (base64 or base64url, pasted from a message export).
2. The page calls `GET /api/blockchain/digest/:message_id` to fetch the on-chain record.
3. It imports `ethers` from `esm.sh` and computes `keccak256` of the raw ciphertext bytes.
4. The computed digest is compared against the `digest` field returned by the API.
5. Results (PASS / FAIL) are displayed alongside the batch hash, transaction hash, block number, timestamp, and a direct Etherscan link.

### What it proves (and doesn't)

- **PASS** means the ciphertext bytes have not changed since the batch was recorded on-chain.
- It does **not** prove who sent the message or decrypt any content — the ciphertext remains opaque without the recipient's private key.
- The blockchain record is append-only; a PASS result provides a tamper-evident audit trail.

---

## Serving

The Fastify backend registers `@fastify/static` and serves the `frontend/` directory. The app is accessible at:

```
https://eternal-blue.theburkenator.com/app/
https://eternal-blue.theburkenator.com/verification/
```

For local development, set `CORS_ORIGIN` in `backend/.env` to match your local origin (e.g. `http://localhost:3000`).
