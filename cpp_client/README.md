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

```bash
./build/eternal-blue health --host localhost --port 8991 --ca-bundle ../backend/certs/dev-cert.pem
```

| Flag | Default | Meaning |
|---|---|---|
| `--host` | `localhost` | server hostname |
| `--port` | `8991` | server port |
| `--ca-bundle` | (system CAs) | extra CA/cert to trust, e.g. the dev self-signed cert |

Against a production server with a publicly-trusted cert, omit `--ca-bundle`.

## Test

```bash
ctest --test-dir build        # or: ./build/eternal-blue-tests
```
