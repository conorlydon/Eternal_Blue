#include <doctest/doctest.h>
#include "Keystore.hpp"
#include "CryptoContext.hpp"

#include <cstdio>
#include <fstream>
#include <string>

namespace {
const std::string kTmp = "/tmp/eb_keystore_roundtrip.bin";
}

TEST_CASE("keystore save then load roundtrips") {
    std::remove(kTmp.c_str());

    CryptoContext cx;
    KeyPair kp = cx.generate_keypair();
    Kek kek;
    kek.fill(0x33);

    KeystoreData in{};
    in.salt = cx.random_salt();
    in.wrapped = cx.wrap_key(kp.secret_key, kek);

    Keystore ks(kTmp);
    CHECK_FALSE(ks.exists());
    ks.save(in);
    CHECK(ks.exists());

    KeystoreData out = ks.load();
    CHECK(out.salt == in.salt);
    CHECK(out.wrapped.nonce == in.wrapped.nonce);
    CHECK(out.wrapped.ciphertext == in.wrapped.ciphertext);

    // loaded bytes still unwrap to the original key
    SecretKey sk = cx.unwrap_key(out.wrapped, kek);
    CHECK(sk == kp.secret_key);

    std::remove(kTmp.c_str());
}

TEST_CASE("keystore load rejects a corrupt file") {
    std::remove(kTmp.c_str());
    { std::ofstream f(kTmp, std::ios::binary); f << "not a keystore"; }

    Keystore ks(kTmp);
    CHECK_THROWS_AS(ks.load(), KeystoreError);

    std::remove(kTmp.c_str());
}

TEST_CASE("keystore exists is false for a missing file") {
    Keystore ks("/tmp/eb_definitely_missing_keystore.bin");
    CHECK_FALSE(ks.exists());
}
