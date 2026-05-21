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

```bash
cmake -S . -B build
cmake --build build -j
```

Produces `build/eternal-blue` and `build/eternal-blue-tests`.

## Run

Launch the interactive shell:

```bash
./build/eternal-blue --ca-bundle ../backend/certs/dev-cert.pem
```

| Flag | Default | Meaning |
|---|---|---|
| `--host` | `localhost` | server hostname |
| `--port` | `8991` | server port |
| `--ca-bundle` | (system CAs) | extra CA/cert to trust, e.g. the dev self-signed cert |

Against a production server with a publicly-trusted cert, omit `--ca-bundle`.

### Shell

The session (JWT + unlocked key) lives in memory for the life of the process —
nothing authenticated is persisted. `health` also works as a one-shot:
`./build/eternal-blue health`.

| Command | Action |
|---|---|
| `signup <username>` | create an account on this machine (generates + wraps a keypair, publishes the public key) |
| `login <username>` | authenticate and unlock the local key |
| `logout` | end the session, wipe the key from memory |
| `health` | check server reachability |
| `help` | list commands |
| `quit` | exit (also wipes the key) |

Passwords are prompted for separately, with terminal echo off — never passed as
arguments. The prompt shows the logged-in username.

```
> signup alice
password:
registered alice
> login alice
password:
logged in as alice (token expires 2026-05-22T15:27:34Z)
alice> logout
logged out alice
> quit
```

The wrapped private key is stored at `~/.eternal-messenger/keys.bin` (one user
per machine — see Notes).

### Notes

`keys.bin` holds a single user's wrapped key, so one machine maps to one local
identity. To run a second identity (e.g. for a two-party demo), use a separate
home: `HOME=/tmp/bob ./build/eternal-blue …`.

## Test

```bash
ctest --test-dir build        # or: ./build/eternal-blue-tests
```
