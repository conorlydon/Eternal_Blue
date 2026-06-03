#include "CryptoContext.hpp"

#include <algorithm>
#include <cstdint>

namespace {

// argon2id params for the at-rest kek (protocol §6): t=4, 256 MiB, argon2id
constexpr unsigned long long kKekOps = 4;
constexpr size_t             kKekMem = 256ull * 1024 * 1024;

// domain-separation tag bound into the wrap as associated data
constexpr unsigned char kKekAad[]   = "eternal-blue-kek-v1";
constexpr size_t        kKekAadLen  = sizeof(kKekAad) - 1;   // drop null terminator

}  // namespace

// ---------------------------------------------------------------------------
// HPKE Mode_Auth (RFC 9180), suite DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/
// ChaCha20Poly1305, built from libsodium primitives. 1.0.18 ships no HKDF,
// so HKDF is done from HMAC-SHA256 (RFC 5869).
// ---------------------------------------------------------------------------
namespace {

using Bytes = std::vector<unsigned char>;
using Hash  = std::array<unsigned char, 32>;

void put(Bytes& v, std::string_view s)              { v.insert(v.end(), s.begin(), s.end()); }
void put(Bytes& v, const unsigned char* p, size_t n) { v.insert(v.end(), p, p + n); }
template <size_t N>
void put(Bytes& v, const std::array<unsigned char, N>& a) { v.insert(v.end(), a.begin(), a.end()); }

// big-endian encode n into len bytes (RFC 8017 I2OSP)
Bytes i2osp(uint64_t n, size_t len) {
    Bytes out(len, 0);
    for (size_t i = 0; i < len; ++i)
        out[len - 1 - i] = static_cast<unsigned char>((n >> (8 * i)) & 0xff);
    return out;
}

// HMAC-SHA256, arbitrary-length key (streaming API)
Hash hmac(const unsigned char* key, size_t keylen, const Bytes& msg) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, keylen);
    crypto_auth_hmacsha256_update(&st, msg.data(), msg.size());
    Hash out{};
    crypto_auth_hmacsha256_final(&st, out.data());
    return out;
}

// HKDF-SHA256 (RFC 5869). empty salt == HashLen zeros (HMAC pads to the same block).
Hash hkdf_extract(const Bytes& salt, const Bytes& ikm) {
    return hmac(salt.data(), salt.size(), ikm);
}

Bytes hkdf_expand(const Hash& prk, const Bytes& info, size_t L) {
    Bytes okm;
    Hash t{};
    size_t tlen = 0;
    for (unsigned char counter = 1; okm.size() < L; ++counter) {
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk.data(), prk.size());
        crypto_auth_hmacsha256_update(&st, t.data(), tlen);
        crypto_auth_hmacsha256_update(&st, info.data(), info.size());
        crypto_auth_hmacsha256_update(&st, &counter, 1);
        crypto_auth_hmacsha256_final(&st, t.data());
        tlen = t.size();
        okm.insert(okm.end(), t.begin(), t.begin() + std::min(t.size(), L - okm.size()));
    }
    return okm;
}

const Bytes& kem_suite_id() {
    static const Bytes id = [] {
        // 0x0020 is the id for the x25519 kem
        Bytes b; put(b, "KEM"); auto k = i2osp(0x0020, 2); put(b, k.data(), k.size()); return b;
    }();
    return id;
}
const Bytes& hpke_suite_id() {
    static const Bytes id = [] {
        Bytes b; put(b, "HPKE");
        // ids for x25519 kem, hkdf-sha256 kdf, chacha20poly1305 aead
        for (uint64_t v : {0x0020ULL, 0x0001ULL, 0x0003ULL}) { auto x = i2osp(v, 2); put(b, x.data(), x.size()); }
        return b;
    }();
    return id;
}

// LabeledExtract / LabeledExpand (RFC 9180 §4)
Hash labeled_extract(const Bytes& suite, const Bytes& salt, std::string_view label, const Bytes& ikm) {
    Bytes li;
    put(li, "HPKE-v1"); put(li, suite.data(), suite.size()); put(li, label); put(li, ikm.data(), ikm.size());
    return hkdf_extract(salt, li);
}
Bytes labeled_expand(const Bytes& suite, const Hash& prk, std::string_view label, const Bytes& info, size_t L) {
    Bytes li;
    auto l = i2osp(L, 2); put(li, l.data(), l.size());
    put(li, "HPKE-v1"); put(li, suite.data(), suite.size()); put(li, label); put(li, info.data(), info.size());
    return hkdf_expand(prk, li, L);
}

// X25519 DH; aborts on a low-order/all-zero result (RFC 9180 requires it)
Hash dh(const SecretKey& sk, const PublicKey& pk) {
    Hash out{};
    if (crypto_scalarmult(out.data(), sk.data(), pk.data()) != 0)
        throw CryptoError("X25519 DH produced a low-order point");
    return out;
}

PublicKey pk_of(const SecretKey& sk) {
    PublicKey pk{};
    crypto_scalarmult_base(pk.data(), sk.data());
    return pk;
}

// DHKEM ExtractAndExpand -> 32-byte shared secret (RFC 9180 §4.1)
Hash extract_and_expand(const Bytes& dh_bytes, const Bytes& kem_context) {
    const Bytes& s = kem_suite_id();
    Hash  eae_prk = labeled_extract(s, {}, "eae_prk", dh_bytes);
    Bytes ss      = labeled_expand(s, eae_prk, "shared_secret", kem_context, 32);
    Hash out{}; std::copy(ss.begin(), ss.end(), out.begin());
    return out;
}

struct Encap { Hash shared_secret; PublicKey enc; };

// AuthEncap with a caller-supplied ephemeral key (RFC 9180 §4.1)
Encap auth_encap(const PublicKey& pkR, const SecretKey& skS, const SecretKey& skE, const PublicKey& pkE) {
    Bytes dh_cat; put(dh_cat, dh(skE, pkR)); put(dh_cat, dh(skS, pkR));
    PublicKey pkS = pk_of(skS);
    Bytes ctx; put(ctx, pkE); put(ctx, pkR); put(ctx, pkS);
    return { extract_and_expand(dh_cat, ctx), pkE };
}

// AuthDecap (RFC 9180 §4.1)
Hash auth_decap(const PublicKey& enc, const SecretKey& skR, const PublicKey& pkS) {
    Bytes dh_cat; put(dh_cat, dh(skR, enc)); put(dh_cat, dh(skR, pkS));
    PublicKey pkR = pk_of(skR);
    Bytes ctx; put(ctx, enc); put(ctx, pkR); put(ctx, pkS);
    return extract_and_expand(dh_cat, ctx);
}

struct AeadCtx { std::array<unsigned char, 32> key; std::array<unsigned char, 12> base_nonce; };

// KeySchedule for mode_auth (0x02), no PSK (RFC 9180 §5.1)
AeadCtx key_schedule_auth(const Hash& shared_secret, std::string_view info) {
    const Bytes& s = hpke_suite_id();
    Bytes empty;
    Hash psk_id_hash = labeled_extract(s, {}, "psk_id_hash", empty);
    Bytes info_bytes(info.begin(), info.end());
    Hash info_hash   = labeled_extract(s, {}, "info_hash", info_bytes);

    Bytes ks_ctx; ks_ctx.push_back(0x02); put(ks_ctx, psk_id_hash); put(ks_ctx, info_hash);

    Bytes ss(shared_secret.begin(), shared_secret.end());
    Hash secret = labeled_extract(s, ss, "secret", empty);   // salt=shared_secret, ikm=psk("")

    Bytes key   = labeled_expand(s, secret, "key", ks_ctx, 32);
    Bytes nonce = labeled_expand(s, secret, "base_nonce", ks_ctx, 12);
    AeadCtx c{};
    std::copy(key.begin(), key.end(), c.key.begin());
    std::copy(nonce.begin(), nonce.end(), c.base_nonce.begin());
    return c;
}

}  // namespace

CryptoContext::CryptoContext() {
    if (sodium_init() < 0)
        throw CryptoError("sodium_init failed");
}

KeyPair CryptoContext::generate_keypair() {
    KeyPair kp{};
    crypto_kx_keypair(kp.public_key.data(), kp.secret_key.data());   // x25519 keypair
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
        w.ciphertext.data(), nullptr,   // nullptr: ciphertext length out, unused (size is fixed)
        sk.data(), sk.size(),
        kKekAad, kKekAadLen,
        nullptr, w.nonce.data(), kek.data());   // first nullptr: secret nonce, unused by this aead
    return w;
}

SecretKey CryptoContext::unwrap_key(const WrappedKey& wrapped, const Kek& kek) {
    SecretKey sk{};
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            sk.data(), nullptr,   // nullptr: plaintext length out, unused (size is fixed)
            nullptr,              // secret nonce, unused by this aead
            wrapped.ciphertext.data(), wrapped.ciphertext.size(),
            kKekAad, kKekAadLen,
            wrapped.nonce.data(), kek.data()) != 0)
        throw CryptoError("unwrap failed: wrong password or corrupt keystore");
    return sk;
}

Sealed CryptoContext::seal_auth(const PublicKey& recipient_pk, const SecretKey& sender_sk,
                                std::string_view info, std::string_view aad,
                                const std::vector<unsigned char>& plaintext) {
    SecretKey skE{};
    PublicKey pkE{};
    crypto_kx_keypair(pkE.data(), skE.data());                 // fresh ephemeral per message
    Encap e = auth_encap(recipient_pk, sender_sk, skE, pkE);
    sodium_memzero(skE.data(), skE.size());

    AeadCtx ctx = key_schedule_auth(e.shared_secret, info);

    std::vector<unsigned char> ct(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ct.data(), &clen,
        plaintext.data(), plaintext.size(),
        reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
        nullptr, ctx.base_nonce.data(), ctx.key.data());   // nullptr: secret nonce, unused by this aead
    ct.resize(clen);
    sodium_memzero(ctx.key.data(), ctx.key.size());

    Sealed out;
    out.enc = e.enc;
    out.ciphertext = std::move(ct);
    return out;
}

std::vector<unsigned char> CryptoContext::open_auth(const PublicKey& enc,
                                const SecretKey& recipient_sk, const PublicKey& sender_pk,
                                std::string_view info, std::string_view aad,
                                const std::vector<unsigned char>& ciphertext) {
    Hash    shared_secret = auth_decap(enc, recipient_sk, sender_pk);
    AeadCtx ctx           = key_schedule_auth(shared_secret, info);

    std::vector<unsigned char> pt(ciphertext.size());
    unsigned long long ptlen = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
        pt.data(), &ptlen, nullptr,   // nullptr: secret nonce, unused by this aead
        ciphertext.data(), ciphertext.size(),
        reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
        ctx.base_nonce.data(), ctx.key.data());
    sodium_memzero(ctx.key.data(), ctx.key.size());
    if (rc != 0)
        throw CryptoError("HPKE open failed: authentication or decryption error");
    pt.resize(ptlen);
    return pt;
}
