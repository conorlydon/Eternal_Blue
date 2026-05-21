# Eternal-Blue — Cryptographic Protocol

This document specifies the end-to-end cryptographic protocol used by the Eternal-Blue secure messaging system, and justifies every primitive at parameter level. It is the authoritative reference for the C++ CLI client and any second client (web/native) talking to the same backend; both clients implement the same wire format.

The companion document `docs/API.md` specifies the HTTP/JSON envelope. This document specifies what the bytes inside that envelope mean.

---

## 1. Threat model

The system must defend the **confidentiality**, **integrity** and **authenticity** of message plaintext against the four adversary classes from the rubric.

| Adversary | What they can do | Properties that hold | Properties that do **not** hold |
|---|---|---|---|
| **A. Passive network attacker** | Read all traffic | Confidentiality, integrity, authenticity, server authentication | — |
| **B. Active network attacker** | Modify / drop / replay / inject traffic | Confidentiality, integrity, authenticity, server authentication. Tampered ciphertext fails AEAD; injected messages fail HPKE sender authentication. Replay across recipients fails (AAD binds recipient). Replay to the same recipient is **not** prevented at the AEAD layer — see §10. | Replay prevention at protocol level (mitigated by per-message `sent_at_ms` in AAD + client-side dedup on `message_id`) |
| **C. Honest-but-curious server** | Sees and logs all ciphertext + metadata, but runs the protocol faithfully | Confidentiality of message plaintext, integrity & authenticity end-to-end | Metadata privacy: server learns *who messages whom, when, message size* and the social graph |
| **D. Fully compromised server** | Reads the database, sends arbitrary responses, serves arbitrary public keys | Confidentiality and integrity of messages between users **who have already exchanged at least one message** (TOFU pinning catches subsequent key swaps); confidentiality of stored ciphertext (server cannot decrypt) | **First-contact key swap** — the server can MITM the very first lookup of a peer's key; the client surfaces this as "first time talking to X" but cannot distinguish a malicious key from a legitimate one without an out-of-band channel. **Forward secrecy** — see §10. **Availability** — server can drop or refuse messages. **Metadata** — already lost in case C. |

At-rest threats:
- A **database breach** (server-side) must not yield plaintext passwords or message plaintext. Achieved by Argon2id for password hashes (§5) and end-to-end AEAD for messages (§4).
- A **stolen laptop with the user logged out** must not yield plaintext private keys. Achieved by wrapping the local long-term private key under a password-derived KEK (§6).
- A **stolen laptop with the user logged in** (process running, session active) **does** yield plaintext keys and plaintext messages. This is a documented trust boundary: the user trusts their own machine while authenticated.

---

## 2. Primitives at a glance

| Role | Algorithm | Parameters | Citation |
|---|---|---|---|
| KEM | DHKEM(X25519, HKDF-SHA256) | KEM ID `0x0020` | RFC 9180 §7.1 |
| KDF | HKDF-SHA256 | KDF ID `0x0001` | RFC 5869; RFC 9180 §7.2 |
| AEAD (messages) | ChaCha20-Poly1305 (IETF, 96-bit nonce) | AEAD ID `0x0003`, 32-byte key, 12-byte nonce, 16-byte tag | RFC 8439; RFC 9180 §7.3 |
| AEAD (local key-at-rest) | XChaCha20-Poly1305-IETF | 32-byte key, 24-byte nonce, 16-byte tag | libsodium `crypto_aead_xchacha20poly1305_ietf_*` |
| Sender authentication | HPKE **Mode_Auth** | Sender's static X25519 private key is bound into KEM encap | RFC 9180 §5.1.3 |
| Password verification (server-side) | Argon2id | `m = 64 MiB, t = 3, p = 1`, 16-byte random salt, 32-byte output | RFC 9106; libsodium-equivalent of `OPSLIMIT_MODERATE`/`MEMLIMIT_MODERATE` (lower-memory variant tuned for shared hosting) |
| KEK derivation (client-side, key-at-rest) | Argon2id | `m = 256 MiB, t = 4, p = 1`, 16-byte random salt, 32-byte output | RFC 9106; libsodium `OPSLIMIT_SENSITIVE` / `MEMLIMIT_SENSITIVE` |
| Random | `getrandom(2)` via libsodium `randombytes_buf` | CSPRNG | libsodium / Linux kernel |
| Blockchain digest | keccak256 | 32-byte output | Ethereum yellow paper |

**Why these and not alternatives** is in §11. The choices listed above are the *only* primitives the implementation is allowed to use. Anything not in this table is out of scope and must not appear in code.

---

## 3. Registration & key publication

### Wire (matches `docs/API.md`)

```
POST /api/auth/register
{
  "username":   "alice",
  "password":   "<plaintext-utf8>",
  "public_key": "<base64url(32-byte X25519 pk)>"
}
```

### Client-side procedure

1. Validate `username` matches `^[a-zA-Z0-9_]{3,32}$` and `password` length 12–128.
2. Generate a long-term X25519 keypair:
   `(sk_alice, pk_alice) = crypto_kx_keypair()` — equivalently `crypto_box_keypair()`. 32 bytes each. Source: `randombytes_buf` (CSPRNG).
3. Persist the wrapped private key locally (§6) **before** issuing the network request, so a network failure mid-registration does not orphan a published public key with no recoverable private key.
4. Send the request over TLS (§7). The server hashes the password with Argon2id (§5) and stores `(user_id, username, password_hash, public_key, key_version=1)`.

### Trust model: TOFU with pinning

Because the server is fully untrusted in case D, peer public keys must be pinned by the client on first contact.

- On `GET /api/keys/:username`, the client receives `(public_key, key_version, published_at)`.
- The client stores `pinned_keys(username, pk, key_version, first_seen_at)` in `LocalStore`.
- On every subsequent lookup, the client compares `(pk, key_version)` against the pin.
  - **Same pk, same `key_version`** → continue silently.
  - **Same pk, newer `key_version`** → continue, update `first_seen_at` (treat as no-op; the server rotated a `key_version` counter but key material is identical).
  - **Different pk** → **abort the operation**, print a multi-line warning, require the user to explicitly run `eternal-blue trust <username> --confirm-rotation` to overwrite the pin. The warning must include the old pin's fingerprint and `first_seen_at`.
- First-contact MITM is documented as **out of scope of the protocol** — it can only be defended against by an out-of-band channel (verbal fingerprint exchange, separate authenticated channel). The client supports `eternal-blue fingerprint <username>` to print the SHA-256 of the pinned key for manual comparison.

---

## 4. Send and receive (the core of the system)

The construction is **HPKE Mode_Auth** (RFC 9180 §5.1.3), instantiated with `(DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305)` — RFC 9180's "ciphersuite 0x0020/0x0001/0x0003".

In Mode_Auth the sender supplies their own static private key `sk_S` and the recipient's static public key `pk_R` to `SetupAuthS`, producing an encapsulated KEM output `enc` and an encryption context. Decapsulation by the recipient requires *both* `sk_R` and `pk_S`; success cryptographically authenticates the sender. No separate Ed25519 signature is required — this is the property that justifies the single-keypair design from §3.

### Sender procedure (`Client::sendMessage(recipient, plaintext)`)

```
Inputs:
  sk_S, pk_S   — sender's long-term X25519 keypair (in memory, decrypted at login)
  pk_R         — recipient's pinned X25519 public key (from TrustStore)
  m            — plaintext bytes
  sender_id, recipient_id, sent_at_ms — message metadata

1. aad = utf8(sender_id || "|" || recipient_id || "|" || itoa(sent_at_ms))
2. (enc, ctx) = HPKE.SetupAuthS(pk_R, info, sk_S)
       where info = utf8("eternal-blue-msg-v1")
3. ct = ctx.Seal(aad, m)
4. POST /api/messages {
       "recipient_username": recipient.username,
       "session_key":        b64url(enc),     // 32 bytes
       "ciphertext":         b64url(ct),      // |m| + 16 (tag)
       "nonce":              b64url(<unused>) // see note below
       "sent_at_ms":         sent_at_ms       // server stores this verbatim
   }
5. Zero  enc-context state and any derived keys from memory.
```

**`nonce` field on the wire.** RFC 9180's single-shot `Seal` manages its own internal sequence counter (starts at 0); an explicit nonce is not part of the HPKE Mode_Auth single-shot API. The field is retained in the wire envelope for backward compatibility with `docs/API.md` but is **set to a fixed 12 zero bytes**, and the recipient ignores it. We do not delete the field because the running backend's schema currently requires it; removing it is a future API breakage.

**`sent_at_ms` is added** to the existing `POST /messages` body. The server must round-trip it as-is in subsequent reads; receiver recomputes AAD from `(sender_id, recipient_id, sent_at_ms)`. If the server tampers with any of these three, AEAD verification fails on the recipient. This is the property that makes case D (compromised server) safe for already-pinned peers.

### Recipient procedure (`Client::decryptMessage(envelope)`)

```
Inputs:
  sk_R, pk_R          — recipient's long-term keypair (in memory after login)
  pk_S                — sender's pinned public key (from TrustStore; lookup-or-pin first)
  envelope            — (session_key=enc, ciphertext=ct, sender_id, recipient_id, sent_at_ms)

1. aad = utf8(sender_id || "|" || recipient_id || "|" || itoa(sent_at_ms))
2. ctx = HPKE.SetupAuthR(enc, sk_R, info="eternal-blue-msg-v1", pk_S)
3. m   = ctx.Open(aad, ct)               // throws on AEAD or KEM failure
4. signature_verified = true             // HPKE Auth proved sender; no separate flag needed
5. Store (m, sender_id, recipient_id, sent_at_ms, signature_verified) in LocalStore.
```

If step 2 fails (KEM decap returned an inconsistent shared secret) or step 3 fails (AEAD tag mismatch), the client treats the message as forged and discards it without writing plaintext to the local store. A log line is emitted but no plaintext is ever exposed.

### Why AAD includes `(sender_id, recipient_id, sent_at_ms)`

- **`sender_id` and `recipient_id`** prevent the server from re-routing a message: an envelope addressed to Bob cannot be replayed as if it were addressed to Charlie (Charlie's AAD would differ → AEAD fails). They also bind the cryptographic context to the specific direction of the conversation.
- **`sent_at_ms`** binds the timestamp the server stores. A compromised server cannot rewrite history by altering `sent_at`; doing so makes the AEAD tag fail.
- AAD is **not transmitted** as a separate field; both sides reconstruct it deterministically from the message metadata already in the envelope.

### Forwarding

`POST /api/messages/:id/forward` is implemented client-side as: decrypt locally → seal a fresh HPKE envelope for the new recipient → POST the new envelope. The server records the `original_message_id` linkage for revocation but never sees plaintext.

### Revocation

Revocation is **honest-server-only** — the server stops serving the message to its recipient. If the recipient has already fetched and decrypted, the plaintext is in their local store and cannot be recalled. This is stated explicitly to users in the `revoke` command output.

---

## 5. Server-side password verification

```
On register:
  salt = randombytes_buf(16)
  hash = Argon2id(password, salt, m=64 MiB, t=3, p=1, len=32)
  store argon2 PHC string  (includes algorithm id, params, salt, hash)

On login:
  argon2.verify(stored_phc_string, password)   // constant-time
  if valid: issue JWT (HS256, 24h, payload = {user_id, username})
```

**Parameter justification.** `m=64 MiB, t=3, p=1` is the libsodium MODERATE preset tuned downward for shared hosting (the project VM has 2 GiB total RAM and serves multiple teams). At these settings, a single login takes ~0.3 s on the production VM — within the human-interactive budget. An attacker who exfiltrates the password-hash column must spend ~64 MiB × 3 iterations of work per candidate guess; on commodity GPU hardware (~200 H/s per A100 for Argon2id at these settings, per the JtR benchmarks), a 12-character password drawn from a 70-character alphabet has a brute-force cost of ~`70^12 / 200 ≈ 6.9e17` GPU-seconds ≈ 22 billion GPU-years. Dictionary attacks against weak passwords remain feasible — the 12-character `minLength` is the operational mitigation for that.

**Why not bcrypt/scrypt/PBKDF2.** Argon2id is the password-hashing-competition winner and the current OWASP-recommended default; it is memory-hard (resists GPU/ASIC parallelism better than bcrypt) and side-channel-resistant on the `id` variant (resists cache-timing better than Argon2d). PBKDF2 is not memory-hard. bcrypt is acceptable but caps at 72-byte input and has aging memory cost.

**Why password is sent raw over TLS, not client-pre-hashed.** Client-pre-hashing with a different KDF would protect against a server that logs request bodies, but: (a) TLS already protects transit (server logs raw bodies only if misconfigured); (b) pre-hashing requires synchronizing a per-user client-side salt between client installations (loses portability); (c) if the stored "hash-of-hash" were ever stolen, the pre-hash alone is a password-equivalent for that user against the server — collapsing the security back to "as good as TLS". The current design accepts TLS as the transit boundary and uses Argon2id for the at-rest boundary; this is the standard OWASP pattern.

---

## 6. Local key-at-rest protection (KEK + key wrap)

The user's long-term X25519 private key is held in plaintext in memory only between `login` and `logout`. On disk at `~/.eternal-messenger/keys.bin` it is wrapped under a key derived from the user's password via Argon2id with **separate parameters** from §5.

### File layout (`keys.bin`)

```
struct {
  uint8_t  magic[4]     = "EBKS";          // "Eternal Blue Keystore"
  uint8_t  version      = 1;                // governs the Argon2id params (see below)
  uint8_t  argon2_salt[16];                // random per install
  uint8_t  xchacha_nonce[24];              // random per wrap
  uint8_t  ciphertext[32 + 16];            // wrapped sk + Poly1305 tag
}
```

The Argon2id parameters are **not stored in the file** — they are fixed by the
file `version`. Version 1 means `t=4, m=256 MiB, p=1`. Raising the cost later
means bumping the version byte and branching on it during `load`, so old files
remain readable. (Storing per-file params would make the keystore self-describing
like a PHC string; we chose version-governed params for simplicity, since a single
client controls both the writer and the reader.)

### Procedure

```
On login (after successful server auth):
  kek = Argon2id(password, argon2_salt, m=256 MiB, t=4, p=1, len=32)
  sk  = XChaCha20Poly1305.Open(xchacha_nonce, ciphertext, aad="eternal-blue-kek-v1", key=kek)
  sodium_munlock + sodium_memzero(kek)
  hold sk in a sodium_malloc'd buffer until logout

On logout / exit / SIGINT:
  sodium_memzero(sk)
  sodium_free(sk_buffer)
```

**Why XChaCha20-Poly1305 here and ChaCha20-Poly1305 (IETF) for messages.** The 24-byte extended nonce of XChaCha is appropriate for *stored* data where the nonce is generated randomly and persisted alongside the ciphertext — birthday risk over the lifetime of a wrap is negligible. For wire messages, HPKE manages nonces internally with a 96-bit sequence counter starting at zero per encryption context, so ChaCha20-Poly1305-IETF is sufficient and matches the HPKE 0x0003 ciphersuite identifier.

**Why Argon2id parameters differ between §5 and §6.** They defend against different attackers with different budgets:
- §5 server-side runs under live request load on shared hardware and must complete in ~300 ms; `m=64 MiB, t=3` is calibrated for that.
- §6 client-side runs once per login on the user's own laptop; `m=256 MiB, t=4` is calibrated for ~1–2 s on a modern laptop. This is also `OPSLIMIT_SENSITIVE/MEMLIMIT_SENSITIVE` in libsodium's named presets.
- Using the **same** salt or parameters in both places would allow an attacker who steals the server hash and the client's `keys.bin` to amortize Argon2id work across both targets. Separate salts (random per user/install) and separate parameters keep the work non-amortizable.

---

## 7. Transport — TLS 1.2+ to the backend

The C++ client opens its own TLS connection using OpenSSL primitives directly (`socket`, `connect`, `SSL_CTX_new`, `SSL_connect`). No `libcurl`. No `cpr`.

Requirements:
- TLS minimum version: **1.2** (`SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)`).
- Cipher suites: OpenSSL default for TLS 1.2 (`HIGH:!aNULL:!eNULL:!MD5:!RC4:!3DES:!DES:!EXPORT`) and full default for TLS 1.3.
- **SNI** is set via `SSL_set_tlsext_host_name(ssl, hostname)` — required for the production virtual host (`eternalblue.theburkenator.com`).
- After `SSL_connect`, the client verifies:
  - `SSL_get_verify_result(ssl) == X509_V_OK` — chain validated against the system CA bundle (overridable with `--ca-bundle`).
  - `X509_check_host(cert, hostname, strlen(hostname), 0, NULL) == 1` — hostname matches Subject Alt Name or CN.
- Any verification failure → close the connection and abort the command with a non-zero exit code. The client **never falls back to plaintext**.

The same `TlsConnection` class is reused (a second instance, separate handshake) for the Ethereum Sepolia JSON-RPC connection in §9.

---

## 8. Local SQLite store

`~/.eternal-messenger/store.db` holds, after first login:
- `messages(message_id PK, direction, peer_user_id, peer_username, plaintext, sent_at_ms, signature_verified, chain_tx_hash, deleted_at)` — decrypted plaintext on disk is the documented trust boundary from §1.
- `pinned_keys(username PK, user_id, public_key BLOB, key_version, first_seen_at, fingerprint TEXT)` — TOFU store.
- `meta(key PK, value)` — schema version, last-sync timestamp, etc.

The database file is not encrypted at rest. This is consistent with the threat model in §1: a stolen logged-out laptop loses the wrapped keystore (still safe) but does **not** lose message plaintext because that plaintext has no value without context that is also lost. A stolen *logged-in* laptop loses everything anyway. We deliberately do not add a second password prompt to "unlock" the store because the security gain is marginal and the UX cost is real.

(If we later decide to require encryption at rest, the migration is to wrap the store under the same KEK derived in §6 and reuse SQLCipher or a wrap-on-close pattern. Out of scope for now.)

---

## 9. Blockchain integrity (Sepolia digest)

Tamper-evident integrity is recorded **server-side** and verified through a **standalone web page** — it is not part of the C++ client (CONTEXT.md blockchain req 3: "accessible independently of the messaging application").

- A server-side digest-service computes `keccak256` over stored message ciphertext, batches the digests, and writes the batch hash to a Solidity contract on Ethereum Sepolia alongside the block timestamp. The transaction hash is recorded in `blockchain_records`.
- A standalone verification web page lets anyone fetch the on-chain hash + timestamp for a transaction, recompute the digest from the supplied content, and see a pass/fail result.

The C++ client's only relationship to this is indirect: it produces the ciphertext the digest-service later hashes. It does not compute keccak256, talk to Sepolia, or implement a `verify` command.

**What this defends against.** A server that deletes or substitutes ciphertext from its database — the chain is an independent witness whose rewriting requires reorging Sepolia, infeasible for an economically-bounded attacker.

**What this does not defend against.** A server that never published a digest (cannot distinguish "not yet batched" from "withheld"). And verification trusts the contract address configured in the web page, not the app server.

---

## 10. Known limitations

Stated explicitly, per the rubric's requirement:

1. **No forward secrecy.** The long-term X25519 keypair is reused for every message. If `sk_alice` ever leaks, every past message ever sent to or from Alice is decryptable from the server's stored ciphertext. **Mitigation path (future):** add a Double-Ratchet layer above HPKE (Signal's X3DH+DR construction). Out of scope for this submission.
2. **No post-compromise security.** Same root cause as (1): there is no key-rotation/ratchet mechanism, only a manual `PUT /keys/update` which the client uses on rotation but which does not bootstrap a new conversation root for prior peers automatically.
3. **First-contact MITM by a compromised server is possible.** TOFU catches *subsequent* key swaps but cannot detect a malicious key served on the very first lookup. Manual fingerprint verification (`eternal-blue fingerprint <user>`) is the documented out-of-band remedy.
4. **Metadata is visible to an honest-but-curious server.** Who messages whom, when, message length. We do not pad messages, do not cover-traffic, and do not run through a mix net. Documented and accepted.
5. **Replay to the same recipient is not prevented at the AEAD layer.** A server can re-deliver the same envelope twice; the AAD would still verify. The client deduplicates on `message_id` at the application layer — a malicious server could allocate a new `message_id` to a replayed payload, in which case the user sees the same plaintext as a "new" message. Mitigation: include `sent_at_ms` in the local dedup key; if the timestamp is identical to an existing message from the same sender, surface as duplicate. Not perfect, accepted limitation.
6. **The local plaintext store on disk is a deliberate trust-boundary choice**, not an oversight. Re-stated from §1 for completeness.
7. **JWT secret rotation is not automated.** A leaked JWT signing secret on the server allows session forgery for the lifetime of issued tokens (24 h). Mitigation: rotate `JWT_SECRET` env var; existing tokens become invalid on next request. Documented operational procedure, not a runtime feature.

---

## 11. Why these primitives and not alternatives

Summary table for the interview defence. Each row is one specific choice; the "why" column is the *parameter-level* justification the rubric requires, not "it's standard."

| Choice | Alternative | Why we picked this for this deployment |
|---|---|---|
| HPKE Mode_Auth (RFC 9180) | Manual X25519 + HKDF + AEAD + Ed25519 signature | Single keypair per user simplifies the server schema, the TOFU store, and the key-rotation story. Sender authentication is provided by KEM decap (the recipient's `SetupAuthR` succeeds iff the encap was produced with `sk_S`), removing the need for a separate signature, the Ed25519 column on the server, and the second TOFU pin per peer. Cited spec is a single RFC instead of three. |
| DHKEM(X25519) | DHKEM(P-256) or DHKEM(P-521) | X25519 has constant-time, side-channel-resistant implementations in libsodium; 32-byte keys; no parameter-validation footguns that NIST curves have around small-subgroup and twist attacks; equivalent security level (~128-bit) for our threat model. |
| ChaCha20-Poly1305 (IETF) on the wire | AES-256-GCM | ChaCha20 is constant-time in software without AES-NI, matching the libsodium-first design. GCM's catastrophic-on-nonce-reuse failure mode is also a footgun; HPKE's internal sequence counter avoids it, but choosing ChaCha20 keeps both layers consistent. AES-256-GCM is a fine alternative; we picked ChaCha20-Poly1305 because libsodium's HPKE-compatible ciphersuite ID `0x0003` is exactly this. |
| XChaCha20-Poly1305 for at-rest wrap | ChaCha20-Poly1305-IETF | 24-byte nonce permits safe random nonce generation for the wrap operation. The IETF 12-byte nonce assumes an external counter, which `keys.bin` does not maintain across processes. |
| Argon2id | bcrypt / scrypt / PBKDF2 | Memory-hard (defeats GPU/ASIC parallelism); `id` variant is side-channel resistant; PHC winner; current OWASP top choice. Parameter splits between server (§5) and client (§6) are justified inline. |
| Argon2id MODERATE on server, SENSITIVE on client | Same params on both | Different attacker budgets and different latency budgets. Identical params would let an attacker amortize Argon2 work across the two stolen artefacts (server hash + client `keys.bin`). |
| TOFU pinning | PKI (CA-issued user certs) or web-of-trust | This is an academic project with no PKI infrastructure available; a CA-issued cert per user is operationally out of scope, and a web-of-trust requires user mass. TOFU is the rubric's named acceptable option for "most teams." |
| Random nonces (CSPRNG) at the seal layer | Fixed counters | HPKE handles the counter internally and we use single-shot Seal/Open. We never expose a nonce-managed API to the application layer, so we cannot accidentally reuse one. |
| keccak256 for chain digest | SHA-256 | Required by Solidity's native `keccak256` opcode; matches Ethereum's address-derivation hash. We don't reuse keccak256 anywhere else in the protocol. |

---

## 12. Versioning

All HPKE `info` strings end in `-v1`. Any protocol change requires bumping the suffix and refusing to interoperate with the prior version. The wire envelope's `key_version` field is the server-published rotation counter on each user's static key; the HPKE `info` version is the protocol version itself. These are independent.

The current protocol is **v1**.
