#pragma once
#include "CryptoContext.hpp"   // PublicKey
#include <string>
#include <string_view>

struct User {
    std::string user_id;        // uuid
    std::string username;
    PublicKey   public_key{};   // x25519
    int         key_version = 1;

    // parse GET /keys/:username; throws if a field is missing or the key is the wrong size
    static User from_json(std::string_view json);
};
