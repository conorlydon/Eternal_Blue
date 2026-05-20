#include "CryptoContext.hpp"

namespace {

// argon2id params for the at-rest kek (protocol §6): t=4, 256 MiB, argon2id
constexpr unsigned long long kKekOps = 4;
constexpr size_t             kKekMem = 256ull * 1024 * 1024;

// domain-separation tag bound into the wrap as associated data
constexpr unsigned char kKekAad[]   = "eternal-blue-kek-v1";
constexpr size_t        kKekAadLen  = sizeof(kKekAad) - 1;   // drop null terminator

}  // namespace

CryptoContext::CryptoContext() {
    if (sodium_init() < 0)
        throw CryptoError("sodium_init failed");
}

KeyPair CryptoContext::generate_keypair() {
    KeyPair kp{};
    crypto_kx_keypair(kp.public_key.data(), kp.secret_key.data());
    return kp;
}

Salt CryptoContext::random_salt() {
    Salt s{};
    randombytes_buf(s.data(), s.size());
    return s;
}

Kek CryptoContext::derive_kek(std::string_view password, const Salt& salt) {
    Kek kek{};
    if (crypto_pwhash(kek.data(), kek.size(),
                      password.data(), password.size(),
                      salt.data(),
                      kKekOps, kKekMem,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        throw CryptoError("derive_kek failed (argon2 out of memory?)");
    return kek;
}

WrappedKey CryptoContext::wrap_key(const SecretKey& sk, const Kek& kek) {
    WrappedKey w{};
    randombytes_buf(w.nonce.data(), w.nonce.size());
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        w.ciphertext.data(), nullptr,
        sk.data(), sk.size(),
        kKekAad, kKekAadLen,
        nullptr, w.nonce.data(), kek.data());
    return w;
}

SecretKey CryptoContext::unwrap_key(const WrappedKey& wrapped, const Kek& kek) {
    SecretKey sk{};
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            sk.data(), nullptr,
            nullptr,
            wrapped.ciphertext.data(), wrapped.ciphertext.size(),
            kKekAad, kKekAadLen,
            wrapped.nonce.data(), kek.data()) != 0)
        throw CryptoError("unwrap failed: wrong password or corrupt keystore");
    return sk;
}
