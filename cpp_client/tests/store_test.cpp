#include <doctest/doctest.h>
#include "Keystore.hpp"
#include "CryptoContext.hpp"
#include "LocalStore.hpp"

#include <cstdio>
#include <fstream>
#include <string>

namespace {
const std::string kTmp    = "/tmp/eb_keystore_roundtrip.bin";
const std::string kDbTmp  = "/tmp/eb_localstore_test.db";

Message make_message(const std::string& id) {
    Message m;
    m.message_id          = id;
    m.sender_id           = "sender-uuid";
    m.sender_username     = "alice";
    m.recipient_id        = "recipient-uuid";
    m.recipient_username  = "bob";
    m.encapsulated_key    = {0x01, 0x02, 0x03};
    m.ciphertext          = {0xAA, 0xBB, 0xCC};
    m.sent_at_ms          = 1000;
    m.is_forwarded        = false;
    m.original_message_id = "";
    m.plaintext           = "hello";
    m.signature_verified  = true;
    return m;
}
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

TEST_CASE("localstore save and retrieve message") {
    std::remove(kDbTmp.c_str());
    LocalStore db(kDbTmp);

    Message m = make_message("msg-1");
    db.save_message(m);

    auto result = db.get_message("msg-1");
    REQUIRE(result.has_value());
    CHECK(result->message_id         == m.message_id);
    CHECK(result->sender_username    == m.sender_username);
    CHECK(result->recipient_username == m.recipient_username);
    CHECK(result->encapsulated_key   == m.encapsulated_key);
    CHECK(result->ciphertext         == m.ciphertext);
    CHECK(result->sent_at_ms         == m.sent_at_ms);
    CHECK(result->plaintext          == m.plaintext);
    CHECK(result->signature_verified == m.signature_verified);

    std::remove(kDbTmp.c_str());
}

TEST_CASE("localstore get_message returns nullopt for missing id") {
    std::remove(kDbTmp.c_str());
    LocalStore db(kDbTmp);

    CHECK_FALSE(db.get_message("does-not-exist").has_value());

    std::remove(kDbTmp.c_str());
}

TEST_CASE("localstore list_messages excludes soft-deleted, newest first") {
    std::remove(kDbTmp.c_str());
    LocalStore db(kDbTmp);

    Message m1 = make_message("msg-1"); m1.sent_at_ms = 1000;
    Message m2 = make_message("msg-2"); m2.sent_at_ms = 3000;
    Message m3 = make_message("msg-3"); m3.sent_at_ms = 2000;
    db.save_message(m1);
    db.save_message(m2);
    db.save_message(m3);
    db.mark_deleted("msg-1");

    auto list = db.list_messages();
    REQUIRE(list.size() == 2);
    CHECK(list[0].message_id == "msg-2");   // newest first
    CHECK(list[1].message_id == "msg-3");

    std::remove(kDbTmp.c_str());
}

TEST_CASE("localstore get_message returns nullopt after mark_deleted") {
    std::remove(kDbTmp.c_str());
    LocalStore db(kDbTmp);

    db.save_message(make_message("msg-1"));
    db.mark_deleted("msg-1");

    CHECK_FALSE(db.get_message("msg-1").has_value());

    std::remove(kDbTmp.c_str());
}

TEST_CASE("localstore save and retrieve pin") {
    std::remove(kDbTmp.c_str());
    LocalStore db(kDbTmp);

    CryptoContext cx;
    KeyPair kp = cx.generate_keypair();

    User u;
    u.username    = "alice";
    u.user_id     = "alice-uuid";
    u.public_key  = kp.public_key;
    u.key_version = 2;
    db.save_pin(u);

    auto result = db.get_pin("alice");
    REQUIRE(result.has_value());
    CHECK(result->username    == u.username);
    CHECK(result->user_id     == u.user_id);
    CHECK(result->public_key  == u.public_key);
    CHECK(result->key_version == u.key_version);

    std::remove(kDbTmp.c_str());
}

TEST_CASE("localstore get_pin returns nullopt for unknown username") {
    std::remove(kDbTmp.c_str());
    LocalStore db(kDbTmp);

    CHECK_FALSE(db.get_pin("nobody").has_value());

    std::remove(kDbTmp.c_str());
}

TEST_CASE("localstore save_pin overwrites existing pin") {
    std::remove(kDbTmp.c_str());
    LocalStore db(kDbTmp);

    CryptoContext cx;
    User u;
    u.username    = "alice";
    u.user_id     = "alice-uuid";
    u.public_key  = cx.generate_keypair().public_key;
    u.key_version = 1;
    db.save_pin(u);

    u.public_key  = cx.generate_keypair().public_key;
    u.key_version = 2;
    db.save_pin(u);

    auto result = db.get_pin("alice");
    REQUIRE(result.has_value());
    CHECK(result->key_version == 2);
    CHECK(result->public_key  == u.public_key);

    std::remove(kDbTmp.c_str());
}
