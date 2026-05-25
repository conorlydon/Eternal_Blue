#include "TrustStore.hpp"

#include <sodium.h>
#include <array>

TrustStore::TrustStore(LocalStore& store) : store_(store) {}

User TrustStore::lookup_or_pin(const User& fetched) {
    auto existing = store_.get_pin(fetched.username);
    if (!existing) {
        store_.save_pin(fetched);                            // first contact: TOFU
        return fetched;
    }
    if (existing->public_key == fetched.public_key) {
        return *existing;                                    // match — proceed
    }
    throw KeyChangedError(
        "pinned key for '" + fetched.username +
        "' does not match the server's response. pinned: " +
        fingerprint(existing->public_key) +
        "  ; received: " + fingerprint(fetched.public_key));
}

std::string TrustStore::fingerprint(const PublicKey& pk) {
    std::array<unsigned char, crypto_hash_sha256_BYTES> h{};
    crypto_hash_sha256(h.data(), pk.data(), pk.size());

    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(h.size() * 2 + h.size() / 2);
    for (size_t i = 0; i < h.size(); ++i) {
        out += hex[(h[i] >> 4) & 0x0F];
        out += hex[h[i] & 0x0F];
        if (((i + 1) % 2 == 0) && (i + 1 != h.size())) out += ' ';
    }
    return out;
}
