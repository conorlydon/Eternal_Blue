# CS4455 Cybersecurity — Epic Project 2026
## Cover Document

---

## Group Details

| | |
|---|---|
| **Group Name** | Eternal Blue |
| **Project URL** | https://eternal-blue.theburkenator.com |
| **GitHub Repository** | https://github.com/conorlydon/Eternal_Blue |
| **Submission Date** | 3rd June 2026 |
| **Module** | CS4455 Cybersecurity — Immersive Software Engineering, 2nd Year |

---

## Group Members

| Name | Student ID |
|---|---|
| Conor Lydon | 24429635 |
| Emmett Macken | 24403156 |
| Nathan Dobbyn | 24424609 |

---

## Contributions Breakdown

### Conor Lydon — 24429635 (~33%)

**Blockchain (Andrew Le Gear — 25%)**
- Wrote and deployed `MessageDigest.sol` Solidity smart contract to Ethereum Sepolia testnet; initial version with `recordDigest`, `batches` mapping, `batchCount`, and `DigestRecorded` event; followed up with `onlyOwner` access control after identifying that the initial version allowed any wallet to write arbitrary hashes
- Built `digest-service/index.js` — long-lived Node.js daemon that batches pending message digests every 10 minutes, computes `keccak256(digest_0 + digest_1 + ...)` batch hash, submits to contract via ethers.js v6, waits for Sepolia confirmation, stores `tx_hash` and `block_number` in `blockchain_records`, and updates `digest_queue` with the `batch_id`; includes exponential backoff retry with 5 attempts
- Built `digest-service/flush.js` — one-shot manual flush script for triggering an immediate batch from the command line
- Built three blockchain API endpoints in `backend/routes/blockchain.js`: `GET /api/blockchain/digest/:message_id`, `GET /api/blockchain/batch/:batch_id`, and `GET /api/blockchain/tx/:tx_hash` (Sepolia RPC proxy to avoid browser CORS restrictions)
- Built standalone verification page `frontend/verification/index.html` — five-step independent chain check: local keccak256 of ciphertext, comparison against server digest record, independent batch hash recomputation from all batch members, on-chain batch hash fetch via backend proxy, PASS/FAIL verdict requiring both checks; optional user-supplied tx hash for fully server-independent verification
- Wired digest queuing into `POST /api/messages` inside the same database transaction as the message insert so a message is never saved without its digest being queued
- Fixed CORS issue preventing browser from calling Sepolia RPC directly; resolved by routing the RPC call through the backend proxy endpoint

**C++ (Kashif Memon — 25%)**
- Implemented `LocalStore` class (`cpp_client/src/LocalStore.cpp`) — SQLite-backed local message and key store using the raw SQLite C API with `sqlite3_prepare_v2` + `sqlite3_bind_*` throughout for SQL injection prevention; RAII constructor/destructor pattern; two tables (`messages`, `pinned_keys`); methods: `save_message`, `get_message` (`std::optional<Message>`), `list_messages` (`std::vector<Message>`), `mark_deleted` (soft delete), `mark_revoked` (wipes plaintext, tombstone pattern), `save_pin`, `get_pin` (`std::optional<User>`); migration for `revoked` column on existing databases
- Implemented `delete_message` and `revoke_message` in `Client.cpp` — delete sends `DELETE /api/messages/:id` and soft-deletes locally on 200; revoke checks local sender ownership before hitting the server, sends `DELETE /api/messages/:id/revoke`, then wipes local plaintext and marks the row revoked; forwarded copies are independent and unaffected
- Written LocalStore tests (`cpp_client/tests/store_test.cpp`)

---

### Emmett Macken — 24403156 (~33%)

**Computer Networks & Cybersecurity (Mark Burkley — 25%)**
- Authored the penetration testing report (`docs/penetration-testing-report.md`) covering: testssl.sh TLS analysis, nikto web server scanning, nmap port/service discovery, sqlmap SQL injection testing, npm audit dependency vulnerability review; documented all findings and mitigations including the ws/ethers@6 vulnerability justification
- Implemented rate limiting on all routes via `@fastify/rate-limit` (100 req/min); debugged trust proxy configuration for correct IP detection behind nginx
- Implemented and enforced security headers via `@fastify/helmet`: `X-Frame-Options: DENY`, `noSniff`, Content Security Policy with `scriptSrc`, `connectSrc`, `imgSrc`, `styleSrc` directives
- Built the HTML/JavaScript frontend web client (`frontend/`) with full messaging UI including send, receive, forward, revoke, and conversation threading; network architecture diagram (`docs/network-architecture-diagram.drawio`)

**Backend (Cryptography — Eoin O'Brien — 25%)**
- Scaffolded the Fastify backend server (`backend/server.js`) including CORS, JWT (`@fastify/jwt`), helmet, rate limiting, TLS configuration, and static file serving
- Implemented all backend routes: `auth.js` (signup, login, change password with Argon2id), `keys.js` (public key publication and lookup), `messages.js` (send, receive, delete, forward, revoke with `GET /messages/revoked` for client reconciliation), `conversations.js`
- Added `sent_at_ms` integer timestamp field across backend and C++ client for AEAD AAD binding
- Enforced revocation at all GET message endpoints; added `UNIQUE` constraint on `revocations.message_id` for idempotent revokes
- Documented schema (`docs/SCHEMA.md`), API contract (`docs/API.md`), and PBKDF2 deviation from Argon2id in the web client (`docs/protocol.draft.md` §6)

---

### Nathan Dobbyn — 24424609 (~34%)

**C++ (Kashif Memon — 25%)**
- Set up CMake build system (`cpp_client/CMakeLists.txt`) and full project scaffolding with `.hpp`/`.cpp` separation across all classes
- Implemented `TlsConnection` — low-level TLS using OpenSSL (`SSL_CTX`, `SSL_connect`), TCP socket via `getaddrinfo`, SNI via `SSL_set_tlsext_host_name`, hostname verification via `X509_VERIFY_PARAM_set1_host`, certificate bundle loading
- Implemented `HttpClient` — HTTP/1.1 over TLS, `GET`/`POST`/`DELETE` methods, bearer token injection, raw response parsing
- Implemented `CryptoContext` — full HPKE Mode_Auth (RFC 9180) built from libsodium primitives: HMAC-SHA256-based HKDF Extract/Expand, `LabeledExtract`/`LabeledExpand` with suite ID, DHKEM X25519 `AuthEncap`/`AuthDecap`, `KeySchedule` mode_auth, single-shot Seal/Open over ChaCha20-Poly1305-IETF; passes RFC 9180 interop test against pyhpke
- Implemented `Keystore` — encrypts X25519 secret key at rest under XChaCha20-Poly1305 with KEK derived from password via Argon2id (t=4, m=256MiB); `sodium_memzero` wipes key material after use
- Implemented `TrustStore` — TOFU key pinning over `LocalStore`; throws `KeyChangedError` on key mismatch; `fingerprint()` returns SHA-256 hex of pinned key for out-of-band comparison; prompts user to confirm key rotation explicitly
- Implemented `Client` class wiring all components: `signup`, `login`, `logout`, `send_message` (HPKE seal + POST), `fetch_messages` (GET + HPKE open + revocation reconciliation), `list_conversations`, `list_thread`, `forward_message`
- Implemented REPL in `main.cpp` with top-level commands and chat mode with 5-second auto-refresh polling for new messages
- Written tests for `CryptoContext` and `Keystore` (`cpp_client/tests/`)
- Authored protocol design document (`docs/protocol.draft.md`) covering threat model, HPKE construction walkthrough, Argon2id parameter justification, TOFU trust model

**Backend**
- Set up initial local dev HTTPS backend, `schema.sql`, and database migrations
- Rewrote `DELETE /messages/:id/revoke` to sender-only direct revocation (dropping prior forwarded-only gate); added `GET /messages/revoked` for client sync reconciliation
- Fixed `list_conversations` and `list_thread` bugs where third-party rows were incorrectly included; scoped `keys.bin` and `store.db` paths per backend host/port to prevent cross-environment conflicts

---

## Estimated Work Split

| Member | Estimated % |
|---|---|
| Conor Lydon | 33% |
| Emmett Macken | 33% |
| Nathan Dobbyn | 34% |

---

## Additional Notes

### AI Tool Usage
AI tools (Claude via Claude Code CLI) were used as a development aid throughout the project. All AI-generated code was reviewed, tested, and in several cases manually corrected before committing. A full AI interaction log with prompts, generated output, and critical evaluation is included in individual team member files.

### Deployed Contract
The `MessageDigest` smart contract is deployed on Ethereum Sepolia testnet at:
`0x932d2B7D1e0E5B43792D21a28849E8Cae85D0783`

Etherscan: https://sepolia.etherscan.io/address/0x932d2B7D1e0E5B43792D21a28849E8Cae85D0783

### Verification Page
Accessible independently at: https://eternal-blue.theburkenator.com/verify
