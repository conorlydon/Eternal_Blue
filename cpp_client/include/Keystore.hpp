#pragma once
#include "CryptoContext.hpp"
#include <string>
#include <stdexcept>

class KeystoreError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// what keys.bin holds: the kdf salt + the wrapped long-term secret key
struct KeystoreData {
    Salt salt;
    WrappedKey wrapped;
};

// reads/writes the on-disk keystore (default ~/.eternal-messenger/keys.bin).
// argon2 params are not stored — they are fixed by the file version (protocol §6).
class Keystore {
public:
    explicit Keystore(std::string path);

    bool exists() const;
    void save(const KeystoreData& data);   // creates the file 0600
    KeystoreData load();                    // throws KeystoreError on missing/corrupt file

private:
    std::string path_;
};
