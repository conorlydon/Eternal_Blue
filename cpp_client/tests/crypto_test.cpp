#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "CryptoContext.hpp"

TEST_CASE("wrap then unwrap recovers the secret key") {
    CryptoContext cx;
    KeyPair kp = cx.generate_keypair();
    Kek kek;
    kek.fill(0x11);

    WrappedKey w = cx.wrap_key(kp.secret_key, kek);
    SecretKey out = cx.unwrap_key(w, kek);
    CHECK(out == kp.secret_key);
}

TEST_CASE("unwrap with a different key throws") {
    CryptoContext cx;
    KeyPair kp = cx.generate_keypair();
    Kek kek1;
    kek1.fill(0x11);
    Kek kek2;
    kek2.fill(0x22);

    WrappedKey w = cx.wrap_key(kp.secret_key, kek1);
    CHECK_THROWS_AS(cx.unwrap_key(w, kek2), CryptoError);
}

TEST_CASE("tampered ciphertext is rejected") {
    CryptoContext cx;
    KeyPair kp = cx.generate_keypair();
    Kek kek;
    kek.fill(0x11);

    WrappedKey w = cx.wrap_key(kp.secret_key, kek);
    w.ciphertext[0] ^= 0x01;
    CHECK_THROWS_AS(cx.unwrap_key(w, kek), CryptoError);
}

TEST_CASE("tampered nonce is rejected") {
    CryptoContext cx;
    KeyPair kp = cx.generate_keypair();
    Kek kek;
    kek.fill(0x11);

    WrappedKey w = cx.wrap_key(kp.secret_key, kek);
    w.nonce[0] ^= 0x01;
    CHECK_THROWS_AS(cx.unwrap_key(w, kek), CryptoError);
}

TEST_CASE("derive_kek is deterministic and a wrong password fails to unwrap") {
    CryptoContext cx;
    Salt salt = cx.random_salt();

    Kek a = cx.derive_kek("correct horse battery staple", salt);
    Kek b = cx.derive_kek("correct horse battery staple", salt);
    CHECK(a == b);   // same password + salt -> same kek

    KeyPair kp = cx.generate_keypair();
    WrappedKey w = cx.wrap_key(kp.secret_key, a);

    Kek wrong = cx.derive_kek("wrong password", salt);
    CHECK(wrong != a);
    CHECK_THROWS_AS(cx.unwrap_key(w, wrong), CryptoError);
}

TEST_CASE("two generated keypairs differ") {
    CryptoContext cx;
    KeyPair a = cx.generate_keypair();
    KeyPair b = cx.generate_keypair();
    CHECK(a.public_key != b.public_key);
    CHECK(a.secret_key != b.secret_key);
}
