# eternal-blue (C++ client)

Command-line client for the Eternal-Blue secure messaging system. Hand-written
TLS (OpenSSL) and HTTP/1.1 over raw sockets; libsodium for crypto; SQLite for
local storage.

## Dependencies

```bash
sudo apt install build-essential cmake pkg-config \
    libssl-dev libsodium-dev libsqlite3-dev
```

nlohmann/json and doctest are fetched automatically by CMake.

## Build

From the repository root:

```bash
cmake -S cpp_client -B cpp_client/build
cmake --build cpp_client/build -j
```

Produces `cpp_client/build/eternal-blue` and `cpp_client/build/eternal-blue-tests`.

## Run

The client expects a reachable backend (default `https://localhost:8991`). With
the dev backend running and its self-signed cert at
`backend/certs/dev-cert.pem`, launch the interactive shell from the repo root:

```bash
./cpp_client/build/eternal-blue --ca-bundle backend/certs/dev-cert.pem
```

| Flag | Default | Meaning |
|---|---|---|
| `--host` | `localhost` | server hostname (must match the cert's SAN/CN — used for SNI and `X509_check_host`) |
| `--port` | `8991` | server port |
| `--ca-bundle` | (system CAs) | additional trust anchor on top of the system CAs — point this at the dev self-signed cert during local development; omit against a server with a publicly-trusted cert (e.g. Let's Encrypt) |

### Against the VM

Point the client at the deployed backend (the team VM on `theburkenator.com`)
by overriding `--host` and `--port`. If the VM presents a publicly-trusted
certificate (Let's Encrypt), drop `--ca-bundle`:

```bash
./cpp_client/build/eternal-blue --host eternal-blue.theburkenator.com --port 443
```

The hostname passed to `--host` must match the certificate's SAN —
`TlsConnection` sets SNI to it and `X509_check_host` verifies against it.
Passing the raw IP (`--host 200.69.13.70`) will fail hostname verification
unless the cert explicitly covers that IP.

If DNS for the subdomain isn't resolving locally yet, override it on your
machine so the hostname stays in the SNI / verification path while bypassing
the unresolved record:

```bash
echo "200.69.13.70 eternal-blue.theburkenator.com" | sudo tee -a /etc/hosts
```

If the VM is still serving a self-signed dev cert rather than a publicly-trusted
one, copy that cert locally and pass it via `--ca-bundle <path>` just like the
localhost flow above.

### Test

From the repository root:

```bash
ctest --test-dir cpp_client/build
# or directly:
./cpp_client/build/eternal-blue-tests
```

### Shell

The session (JWT + unlocked key) lives in memory for the life of the process —
nothing authenticated is persisted. Running with no command opens the
interactive shell; `health` is the only one-shot:
`./cpp_client/build/eternal-blue health`.

For a two-party demo on one machine, run each identity under a separate
`HOME` so their `keys.bin` and `store.db` don't collide:

```bash
HOME=/tmp/eb_alice ./cpp_client/build/eternal-blue --ca-bundle backend/certs/dev-cert.pem
HOME=/tmp/eb_bob   ./cpp_client/build/eternal-blue --ca-bundle backend/certs/dev-cert.pem
```

| Command | Action |
|---|---|
| `signup <username>` | create an account on this machine (generates + wraps a keypair, publishes the public key) |
| `login <username>` | authenticate and unlock the local key |
| `logout` | end the session, wipe the key from memory |
| `sync` (alias `inbox`) | fetch new ciphertexts, decrypt, save locally |
| `conversations` (alias `convos`) | list peers grouped by last activity (from LocalStore) |
| `chat <username>` | open a conversation sub-prompt with that peer |
| `send <username> <text...>` | one-shot send without entering chat mode |
| `read <message_id>` | print the plaintext of a locally-stored message |
| `delete <message_id>` | server- and locally-delete a message |
| `forward <message_id> <user>` | re-encrypt and forward to another user |
| `health` | check server reachability |
| `help` | list commands |
| `quit` | exit (also wipes the key) |

Passwords are prompted for separately, with terminal echo off — never passed as
arguments. The prompt shows the logged-in username.

Sender keys are fetched via `/api/keys/:username` and run through TOFU
(`TrustStore`) — first contact pins, subsequent lookups must match or the
operation aborts.

#### Chat sub-mode

`chat <user>` enters a per-conversation sub-prompt. The thread is rendered
once; index numbers refer to that printed list and stay valid until the next
reprint.

| In chat | Action |
|---|---|
| *any non-`/` line* | send to the current peer |
| `/sync` | pull new messages and reprint the thread |
| `/list` | reprint the thread |
| `/delete <#>` | delete the Nth message in the printed thread |
| `/forward <#> <user>` | forward the Nth message in the printed thread |
| `/back` or `/quit` | return to the top-level prompt |

```
> login alice
password:
logged in as alice (token expires …)
alice> conversations
  bob   last 2026-05-29T13:52Z  (1 message)
alice> chat bob
── chat with bob ──
[you 2026-05-29T13:52Z] hello from alice
bob| the quick brown fox jumps over the lazy dog
sent to bob [<id>]
bob| /back
alice>
```

```
> login bob
password:
bob> sync
  [<id>] from alice 2026-05-29T13:52Z
inbox: 2 new, 0 skipped
bob> chat alice
── chat with alice ──
[alice 2026-05-29T13:52Z] hello from alice
[alice 2026-05-29T13:52Z] the quick brown fox jumps over the lazy dog
alice| hi back
sent to alice [<id>]
alice| /back
bob>
```

`sync` is the only command that touches the network for inbox traffic;
`conversations` and `chat` query LocalStore. `read <id>` still works for direct
lookup by id outside chat mode.

The wrapped private key is stored at `~/.eternal-messenger/keys.bin` and the
local message + pin database at `~/.eternal-messenger/store.db` (one user per
machine — see Notes).

### Notes

`keys.bin` holds a single user's wrapped key, so one machine maps to one local
identity. To run a second identity (e.g. for a two-party demo), use a separate
`HOME` (see Run, above).
