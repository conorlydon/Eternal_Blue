#pragma once
#include "LocalStore.hpp"
#include "User.hpp"
#include <stdexcept>
#include <string>

class KeyChangedError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// TOFU over LocalStore's pinned_keys: pin on first contact, accept on match,
// throw on mismatch. the throw is the case-D defence for already-known peers.
class TrustStore {
public:
    explicit TrustStore(LocalStore& store);

    User lookup_or_pin(const User& fetched);

    // sha-256 of a public key, formatted as space-separated 2-byte groups
    static std::string fingerprint(const PublicKey& pk);

private:
    LocalStore& store_;
};
