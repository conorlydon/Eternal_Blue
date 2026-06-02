# Penetration Testing Report — Round 2

Team: Eternal Blue
Members: Emmett Macken, Conor Lydon, Nathan Dobbyn

This supplements the original report (`penetration-testing-report.md`) with two
additional tests targeting areas the first pass did not exercise. Round 1 tested
the **transport** (TLS) and the **anonymous** attacker; round 2 tests the **end-to-end
trust model** and the **authenticated** attacker.

## Scope addendum

All round-2 testing was performed against a **local instance** of the backend
(`http://localhost:3000`) running the production code. Production
(`eternal-blue.theburkenator.com`) is reached only through the **shared** college
nginx/SNI proxy, which our original scope marks out of scope; an authenticated
flood there would also affect other teams on the shared VM. The key-substitution
threat model assumes a *malicious server*, so testing the client against a hostile
local endpoint is the correct and faithful reproduction — no production traffic was
generated.

Tools used: custom C++ harness (doctest, links the real client objects), Node.js
test scripts, `curl`. Harnesses live in `pentest/`.

---

## 3.9 End-to-End Key Substitution (TOFU Trust Model)

**Severity:** Low (case D defended) / Informational (case A — accepted TOFU limitation), with one **Low** hardening recommendation
**OWASP:** A02 Cryptographic Failures / peer authentication
**Tool:** `pentest/test2_key_substitution/trust_pentest.cpp`, `rogue_keys_proxy.mjs`

### What we tested

The original report's "Cryptographic Issues" section tested only TLS with
`testssl.sh` — i.e. confidentiality of the *transport*. It never tested the
end-to-end trust decision, which is the whole purpose of an E2EE messenger: does
the client correctly decide *whose* public key to encrypt to?

We modelled a malicious server (or a hostile proxy with a mis-issued certificate)
that tampers with `GET /api/keys/:username`, substituting an attacker-controlled
public key for the victim's. We drove the **real** `TrustStore`, `LocalStore` and
`CryptoContext` from a harness (`trust-pentest`) and reproduced the observable CLI
behaviour with a rogue HTTPS proxy. Three cases:

- **Case A** — substitution on *first contact* (no pin exists yet).
- **Case D** — substitution against an *already-pinned* peer.
- **Rotation** — whether `trust <user> --confirm-rotation` can be abused.

### What we found

Harness output (`./cpp_client/build/trust-pentest`, 3 cases / 8 assertions, all pass):

```
case A: first-contact substitution silently MITMs the message
  CHECK( trusted.public_key == mallory.public_key )            correct   (attacker key pinned as "bob")
  MESSAGE: attacker decrypted: "transfer the funds at midnight"
  CHECK_THROWS_AS( open with bob.secret_key, CryptoError )     threw     (honest peer cannot read it)

case D: substitution after pinning the real key is rejected
  CHECK_THROWS_AS( lookup_or_pin(mallory key), KeyChangedError ) threw   ("...does not match...")
  CHECK( db.get_pin("bob")->public_key == bob.public_key )      correct  (pin unchanged — defense held)

confirm_rotation blindly overwrites the pin (no out-of-band check)
  CHECK( trusted.public_key == mallory.public_key )            correct   (attacker re-trusted)
  CHECK( stolen == secret )                                    correct   (attacker reads again)
```

- **Case D is correctly defended (strength).** Once a peer's key is pinned,
  `TrustStore::lookup_or_pin` (`cpp_client/src/TrustStore.cpp:14-22`) throws
  `KeyChangedError` on any mismatch, and `Client::send_message`
  (`cpp_client/src/Client.cpp:212`) catches it and **aborts the send**. The pin is
  never silently overwritten. This is the meaningful protection against an
  after-the-fact compromised server, and it works.

- **Case A is an inherent TOFU limitation (informational).** On first contact there
  is no pin to compare against, so a substituted key is accepted silently. Our
  harness confirms the full impact: the victim encrypts to the attacker's key, the
  **attacker decrypts the plaintext**, and the honest peer cannot open the message
  (interception is silent). This matches `protocol.draft.md §10` item 3 — first-contact
  MITM is out of scope and is mitigated only by out-of-band fingerprint comparison
  (`fingerprint <username>`).

- **`confirm_rotation` overwrites the pin with no fingerprint challenge (Low — actionable).**
  `Client::confirm_rotation` (`cpp_client/src/Client.cpp:176-204`) re-fetches the key
  and calls `save_pin(fetched)` **unconditionally** after merely *printing* a warning
  string. There is no step that forces the user to confirm the new fingerprint. A
  user who is social-engineered ("I rotated my key, please re-trust me") and runs
  `trust bob --confirm-rotation` re-enables the case-D MITM in a single command — the
  warning is advisory only.

### Mitigation / Recommendation

- The pinning defense (case D) is sound and the `fingerprint` command exists for
  out-of-band verification — keep documenting first-contact verification as a user
  responsibility (already in `protocol.draft.md §10`).
- **Harden the rotation flow:** make `trust --confirm-rotation` *interactive* — print
  the new fingerprint and require the user to re-type it (or an explicit y/N at a
  prompt that shows old vs new) before `save_pin`. This converts a one-word bypass
  into a deliberate, verified action and closes the social-engineering path without
  weakening legitimate rotation.

---

## 3.10 Authenticated Resource Exhaustion & Timestamp Integrity

**Severity:** Low–Medium
**OWASP:** A04 Insecure Design (business-logic abuse) / A05 Security Misconfiguration
**Tool:** `pentest/test3_dos_abuse/dos_abuse.mjs`

### What we tested

The original "Broken Authentication" section showed that `@fastify/rate-limit`
blocks an **anonymous** scanner (sqlmap → 359/400 requests got 429). It did not test
an attacker who holds a **valid token**. We registered test accounts against the
local backend and, as a legitimately authenticated user, probed three things:

- **C.** Does the server validate the client-supplied `sent_at_ms`?
- **B.** Is there any per-account cap on conversations / messages / queued digests?
- **A.** At what granularity does rate limiting apply (per-IP vs per-account)?

### What we found

Script output (`node dos_abuse.mjs` against `http://localhost:3000`):

```
-- C. sent_at_ms timestamp integrity --
  epoch 0 (1970)             -> HTTP 201  stored sent_at_ms=0              ACCEPTED VERBATIM
  far future (year ~2286)    -> HTTP 201  stored sent_at_ms=9999999999999  ACCEPTED VERBATIM
  1 hour in the future       -> HTTP 201  stored sent_at_ms=1780365722086  ACCEPTED VERBATIM

-- B. resource exhaustion: conversations + digest rows per account --
  pt_..._alice now owns 16 conversations from a single session
  each /messages also inserts a permanent digest_queue row (soft-delete never frees it)

-- A. rate-limit granularity (burst from one IP) --
  fired 90 authenticated sends: {"201":64,"429":26}
  first 429 at request #65
```

- **C — `sent_at_ms` is stored verbatim, unvalidated.** The schema only enforces
  `{ type: 'integer', minimum: 0 }` (`backend/routes/messages.js:17`); there is no
  upper bound or clock-skew check. The server stores and echoes any value
  (`messages.js:66`). Because `sent_at_ms` is part of the AEAD AAD, a tampering
  *server* breaks decryption — but a malicious *sender* fully controls it, so a peer
  can place messages arbitrarily in the past/future and control conversation
  ordering in the recipient's UI. Severity is bounded (it cannot break
  confidentiality) but it is an integrity/UX-spoofing gap.

- **B — no per-account caps.** A single session created 16 conversations with no
  throttle other than the shared per-IP window; each message also writes a permanent
  `digest_queue` row that is never freed (soft-delete keeps it for the blockchain
  audit trail). An authenticated account can grow `conversations`, `messages` and
  `digest_queue` without bound over time, and every queued digest adds to the
  Sepolia batching workload (a cost amplification, since batching writes on-chain).

- **A — rate limiting collapses to a single global bucket in production (Medium).**
  A 90-send burst yielded 64×`201` then 26×`429`, first `429` at request #65 —
  consistent with the `100 req / 1 min` budget (`backend/server.js:59-62`). The more
  important issue is the *key* that budget is counted against. `@fastify/rate-limit`
  is registered with **no `keyGenerator`**, so it uses the default `(req) => req.ip`,
  and the Fastify instance is created with **no `trustProxy`** option
  (`backend/server.js:24-32`). In production nginx terminates TLS and proxies to
  Fastify on `localhost:3000`, so without `trustProxy` every request's `req.ip` is the
  proxy's loopback address — identical for all clients. The consequence:

  - The `100/min` limit (and the tighter per-route `10/min` login, `5/min` password
    limits) are **one shared counter for the entire service**, not per client. A
    single actor — even anonymous — can exhaust the global budget and force `429` on
    **every other user**, including a one-actor lockout of *all* logins for the window.
    This is a trivial whole-service DoS.
  - It is also keyed on neither the real client IP nor the authenticated account, so
    there is no per-account quota, lockout, or accountability, and an attacker with a
    pool of tokens/IPs is not additionally constrained.
  - Note this reframes the round-1 result (sqlmap 359/400 → `429`): that was sqlmap
    tripping a *global* bucket almost instantly, not evidence of per-IP defense. The
    `429` body in both round-1 and our tests is the `@fastify/rate-limit` JSON
    (`"Rate limit exceeded, retry in N seconds"`), confirming the limiter is the team's
    Fastify backend rather than the shared upstream proxy.

### Mitigation / Recommendation

- **Validate `sent_at_ms`** server-side: reject values outside a sane window of
  server time (e.g. ±5 min), or simply ignore the client value and stamp `sent_at`
  authoritatively while keeping the client value only for display. (Confirm the AAD
  contract still holds — if `sent_at_ms` is part of AAD, both peers must agree on the
  exact value, so prefer a bounded-skew *rejection* over silent rewriting.)
- **Fix the rate-limit key (priority).** Add a `keyGenerator` that keys on the
  authenticated identity for authenticated routes, e.g.
  `keyGenerator: (req) => req.headers.authorization ?? req.ip`. Key on the raw token
  string (or decode the JWT inside the keyGenerator) rather than `req.user` — the
  limiter runs at `onRequest`, the same phase as `authenticate`, so `req.user` may not
  be populated yet. This stops one actor from throttling the whole service and gives
  per-account accountability.
  - **Do _not_ "fix" this with `trustProxy: true`** — that trusts the entire
    `X-Forwarded-For` chain, letting a client spoof the header for a fresh bucket per
    request (worse than today). If per-IP limiting is wanted, set `trustProxy` to the
    specific trusted hop (e.g. `trustProxy: 1` or the nginx/loopback CIDR) **and**
    ensure nginx sets `X-Forwarded-For` with `$proxy_add_x_forwarded_for`.
  - In this deployment a shared college SNI proxy also sits upstream; unless it
    forwards real client IPs (not under the team's control), per-IP limiting is
    unreliable regardless of `trustProxy`. Per-token keying is the robust choice here.
- **Rate-limit / cost `/auth/register`** and keep a conservative global limit as a
  backstop, since cheap registration lets an attacker mint many tokens to dilute a
  per-token limit.
- **Add per-account application caps** (conversations/messages per account per window)
  and **bound `digest_queue` growth** — neither IP nor token rate limits bound *total*
  resource growth or on-chain batching cost over time.

---

## Summary (round 2)

| # | OWASP Item | Finding | Severity | Status |
|---|------------|---------|----------|--------|
| 9  | Cryptographic Failures | Case-D key substitution correctly rejected; case-A first-contact MITM is an accepted TOFU limit | Info / Low | Defended (case D) |
| 9a | Insecure Design | `trust --confirm-rotation` overwrites the pin with no fingerprint challenge | Low | Recommend interactive confirm |
| 10 | Insecure Design | `sent_at_ms` accepted unvalidated → ordering/timestamp spoofing | Low | Recommend bounded validation |
| 10a| Security Misconfiguration | Rate limit keys on `req.ip` with no `trustProxy` → one global bucket behind nginx; one actor can `429` the whole service. No per-account quota | Medium | Recommend per-token keyGenerator |

## Notes

- The key-substitution defense (case D) is a genuine strength and worth calling out
  in the conclusion alongside the round-1 controls.
- Round-2 test accounts on the local DB are prefixed `pt_<tag>_`. The schema's
  foreign keys have **no** `ON DELETE CASCADE`, so cleanup must remove dependent rows
  first, e.g. on the dev database:
  ```sql
  DELETE FROM digest_queue WHERE message_id IN (
    SELECT m.id FROM messages m JOIN users u ON u.id IN (m.sender_id, m.recipient_id)
    WHERE u.username LIKE 'pt\_%');
  DELETE FROM messages      WHERE sender_id IN (SELECT id FROM users WHERE username LIKE 'pt\_%')
                               OR recipient_id IN (SELECT id FROM users WHERE username LIKE 'pt\_%');
  DELETE FROM conversations WHERE user_a_id IN (SELECT id FROM users WHERE username LIKE 'pt\_%')
                               OR user_b_id IN (SELECT id FROM users WHERE username LIKE 'pt\_%');
  DELETE FROM users         WHERE username LIKE 'pt\_%';
  ```
