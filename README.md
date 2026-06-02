# Eternal Blue — Secure Messaging

End-to-end encrypted messaging with HPKE Mode_Auth (libsodium), Argon2id key derivation, and tamper-evident message digests anchored to the Ethereum Sepolia testnet.

## Deployed Contract

| Field | Value |
|---|---|
| Network | Ethereum Sepolia testnet |
| Contract address | `0x932d2B7D1e0E5B43792D21a28849E8Cae85D0783` |
| ABI | `backend/digest-service/abi.json` |
| Etherscan | https://sepolia.etherscan.io/address/0x932d2B7D1e0E5B43792D21a28849E8Cae85D0783 |

## Verification Page

`https://eternal-blue.theburkenator.com/verify/index.html`

Paste a message ID and its base64-encoded ciphertext to verify the message has not been tampered with. The page:
1. Computes `keccak256(ciphertext)` locally
2. Fetches the batch from the server and recomputes the batch hash
3. Fetches the live Ethereum transaction receipt from Sepolia and reads the `DigestRecorded` event
4. Shows PASS only if both the digest and the on-chain batch hash match

## Building the C++ Client

Requires: CMake ≥ 3.16, OpenSSL, libsodium, SQLite3, C++17 compiler (Linux/macOS/WSL).

```bash
cd cpp_client
cmake -B build -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build build -j
```

Run against the production server:
```bash
./build/eternal-blue --host eternal-blue.theburkenator.com --port 443
```

Run against localhost (plain HTTP, no TLS):
```bash
./build/eternal-blue --host localhost --port 3000
```

## Running the Backend

```bash
cd backend
cp .env.example .env   # fill in DB credentials, JWT secret, Sepolia wallet key
npm install
node server.js
```

## Running the Digest Service

```bash
cd backend/digest-service
cp .env.example .env   # fill in DB credentials, SEPOLIA_RPC_URL, WALLET_PRIVATE_KEY, CONTRACT_ADDRESS
npm install
node index.js
```

Batches unrecorded message digests every 10 minutes and writes `keccak256(all digests)` to the Sepolia contract with 5-attempt exponential backoff.
