#include "User.hpp"
#include "Base64.hpp"

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>

using json = nlohmann::json;

// Parse and validate a User from a JSON string returned by GET /api/keys/:username.
// Throws std::runtime_error on malformed JSON or missing fields.
User User::from_json(std::string_view json_str) {
    json j;
    try {
        j = json::parse(json_str);
    } catch (const json::parse_error& e) {
        throw std::runtime_error(std::string("User::from_json: invalid JSON: ") + e.what());
    }

    // Validate all required fields are present before accessing them -
    // gives a clear error message rather than a cryptic json::out_of_range.
    for (const char* field : {"username", "user_id", "public_key", "key_version"}) {
        if (!j.contains(field)) {
            throw std::runtime_error(
                std::string("User::from_json: missing required field '") + field + "'");
        }
    }

    User u;
    u.username    = j.at("username").get<std::string>();
    u.user_id     = j.at("user_id").get<std::string>();
    u.key_version = j.at("key_version").get<int>();

    // public_key arrives as a base64url-encoded X25519 public key (32 bytes).
    // Decode it and validate the length before copying into the fixed-size array.
    std::vector<unsigned char> raw = from_base64url(j.at("public_key").get<std::string>());
    if (raw.size() != u.public_key.size()) {
        throw std::runtime_error(
            "User::from_json: public key for '" + u.username + "' is " +
            std::to_string(raw.size()) + " bytes; expected " +
            std::to_string(u.public_key.size()) + " (X25519)");
    }
    // Copy decoded bytes into the std::array<unsigned char, 32> fixed buffer
    // used by the HPKE layer - avoids a heap allocation for a known-size key.
    std::copy(raw.begin(), raw.end(), u.public_key.begin());

    return u;
}
