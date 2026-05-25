#pragma once
#include <array>
#include <string_view>
#include <stdexcept>
#include <vector>
#include <sodium.h>

class CryptoError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

using PublicKey = std::array<unsigned char, crypto_kx_PUBLICKEYBYTES>;
using SecretKey = std::array<unsigned char, crypto_kx_SECRETKEYBYTES>;
using Kek       = std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>;
using Salt      = std::array<unsigned char, crypto_pwhash_SALTBYTES>;

struct KeyPair {
    PublicKey public_key;
    SecretKey secret_key;
};

// a secret key encrypted at rest: xchacha nonce + (ciphertext || poly1305 tag)
struct WrappedKey {
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce;
    std::array<unsigned char, crypto_kx_SECRETKEYBYTES +
                              crypto_aead_xchacha20poly1305_ietf_ABYTES> ciphertext;
};

// output of an HPKE seal: the KEM encapsulation (ephemeral public key) + AEAD ciphertext
struct Sealed {
    PublicKey                  enc;
    std::vector<unsigned char> ciphertext;
};

// libsodium wrapper. constructing it runs sodium_init, so any instance proves
// the library is ready. holds no state for now (key-at-rest ops only).
class CryptoContext {
public:
    CryptoContext();

    KeyPair generate_keypair();

    Salt random_salt();
    Kek  derive_kek(std::string_view password, const Salt& salt);   // argon2id, protocol §6

    WrappedKey wrap_key(const SecretKey& sk, const Kek& kek);
    SecretKey  unwrap_key(const WrappedKey& wrapped, const Kek& kek);   // throws on wrong key / tamper

    // HPKE Mode_Auth (RFC 9180): DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305.
    // sender authentication comes from the KEM (sender_sk folded into the shared secret),
    // so a successful open proves the sender held sender_sk — no separate signature.
    Sealed seal_auth(const PublicKey& recipient_pk, const SecretKey& sender_sk,
                     std::string_view info, std::string_view aad,
                     const std::vector<unsigned char>& plaintext);

    std::vector<unsigned char> open_auth(const PublicKey& enc,
                     const SecretKey& recipient_sk, const PublicKey& sender_pk,
                     std::string_view info, std::string_view aad,
                     const std::vector<unsigned char>& ciphertext);   // throws CryptoError on failure
};
