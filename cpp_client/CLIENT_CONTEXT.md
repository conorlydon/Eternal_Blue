# C++ Client — Context for Contributors

Compressed brief for anyone implementing a piece of the client. Authoritative specs: `../docs/API.md` (wire), `../docs/SCHEMA.md` (server DB), `../docs/protocol.draft.md` (crypto). This file is the shortcut, those win on conflict.

## What the client is

Standalone C++17 CLI for the Eternal-Blue secure messenger. Hand-written TLS (OpenSSL) + HTTP/1.1 over raw sockets, libsodium for crypto, SQLite for local storage. End-to-end encryption happens here; the server only ever sees ciphertext.

Build system: CMake. `CMakeLists.txt` already lists all source files — you just fill in the `.cpp` for your piece. Tests use doctest (`tests/`).

```bash
cmake -S . -B build && cmake --build build -j   # build
ctest --test-dir build                           # test
```

## Things every piece relies on

- **base64url, no padding** is the wire encoding for every binary field (keys, ciphertext, nonces). Use `Base64.hpp` (`to_base64url` / `from_base64url`) — don't hand-roll it. It wraps libsodium's `VARIANT_URLSAFE_NO_PADDING`.
- **Typed exceptions**: each subsystem throws its own (`TlsError`, `HttpError`, `CryptoError`, `KeystoreError`, `LocalStoreError`). Throw the matching one; `main` catches `std::exception` centrally.
- **Comment style**: concise, lowercase, only where the *why* isn't obvious. No capitalized full-sentence comments.
- **Crypto is already done** in `CryptoContext` (keypairs, KEK, wrap/unwrap). You don't touch crypto — you model data and move bytes.

## Already built (stable, depend on freely)

- `TlsConnection` — verified TLS connection; `write` / `read_all`.
- `HttpClient` — `get(path)` / `post(path, body)` returning `HttpResponse{status_code, body}`; `set_bearer_token`.
- `CryptoContext` — `generate_keypair`, `random_salt`, `derive_kek`, `wrap_key`, `unwrap_key`. Types: `PublicKey`, `SecretKey`, `Kek`, `Salt` (all `std::array<unsigned char,N>`).
- `Keystore` (interface done) — `keys.bin` read/write.

## Work orders

### `User` (`User.hpp` → `src/User.cpp`)
- **Does**: models another user's directory entry; parses a `GET /api/keys/:username` response.
- **Implement**: `User::from_json` — parse `{username, user_id, public_key, key_version}` (nlohmann/json), base64url-decode `public_key`, verify it's exactly `crypto_kx_PUBLICKEYBYTES` (32) bytes and copy into the `PublicKey` array (throw `std::runtime_error` otherwise).
- **Depends on**: nlohmann/json (already fetched by CMake — `#include <nlohmann/json.hpp>`), `Base64.hpp`.

### `Message` (`Message.hpp` → `src/Message.cpp`)
- **Does**: models a message in wire + storage form; serializes to/from JSON. No crypto.
- **Implement**:
  - `to_send_json()` → JSON body for `POST /api/messages`: `recipient_username`, `ciphertext` (base64url), `session_key` (base64url of `encapsulated_key`), `nonce` (base64url of **12 zero bytes** — required by the backend schema but unused under HPKE, see protocol §4), `sent_at_ms`.
  - `from_json()` → parse a message object from a GET response; base64url-decode `ciphertext` and `session_key` into the byte vectors.
- **Field-name mapping gotcha**: the struct field is `encapsulated_key`, but on the wire it's called `session_key` (API.md). Map accordingly.
- **Depends on**: nlohmann/json, `Base64.hpp`.

### `LocalStore` (`LocalStore.hpp` → `src/LocalStore.cpp`)
- **Does**: SQLite persistence for decrypted messages + TOFU pins. RAII over `sqlite3*`.
- **Implement**:
  - Constructor: `sqlite3_open` the path, `CREATE TABLE IF NOT EXISTS` for `messages` and `pinned_keys` (mirror the relevant columns from `../docs/SCHEMA.md`, plus a `plaintext` column and `signature_verified` — those are client-only and never leave the machine).
  - Destructor: `sqlite3_close`.
  - `save_message` / `get_message` / `list_messages` (exclude soft-deleted, newest first) / `mark_deleted`.
  - `save_pin` / `get_pin` (store `username, user_id, public_key, key_version`; `public_key` as a BLOB or base64url text — your call, just be consistent).
  - **Always use prepared statements (`sqlite3_prepare_v2` + bind)** — never string-concatenate SQL. This is graded (injection, networks rubric).
- **Depends on**: `<sqlite3.h>` (link is already set up), `Message.hpp`, `User.hpp`.
- **Threat-model note**: decrypted plaintext on disk is a deliberate, documented boundary (the user trusts their own machine). Not a bug — see protocol §1/§8.

## Coordination (avoid merge pain)

- **JSON field names** come from `API.md`. If API.md and reality disagree, flag it — don't silently pick one.
- **`main.cpp` dispatch**: each CLI command is its own `case`. Add yours, don't restructure others'.
- **`CMakeLists.txt`** already lists every `.cpp`; no edits needed unless you add a new file (e.g. a test).
- **Tests**: add cases to an existing `tests/*.cpp`. Exactly one file defines `DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN` (`crypto_test.cpp`) — don't add it elsewhere.
- **Interview reality**: marks are individual and everyone must be able to explain any code, authored or not. Comment your *why*, keep it explainable.
