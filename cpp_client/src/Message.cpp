// strptime / timegm are POSIX.1-2008; the macro must appear before any system header
#define _POSIX_C_SOURCE 200809L

#include "Message.hpp"
#include "Base64.hpp"

#include <nlohmann/json.hpp>

#include <ctime>
#include <stdexcept>
#include <string>

using json = nlohmann::json;

namespace {

// "2026-05-19T14:32:00Z" -> milliseconds since Unix epoch
long long iso8601_to_ms(const std::string& s) {
    std::tm tm{};
    const char* end = strptime(s.c_str(), "%Y-%m-%dT%H:%M:%SZ", &tm);
    if (!end) {
        throw std::runtime_error("Message: malformed timestamp '" + s + "'");
    }
    // timegm interprets tm as UTC (unlike mktime which uses local time)
    return static_cast<long long>(timegm(&tm)) * 1000LL;
}

}  // namespace

// ---------------------------------------------------------------------------
// Serialise for POST /messages
// ---------------------------------------------------------------------------
std::string Message::to_send_json() const {
    json j = {
        {"recipient_username", recipient_username},
        {"ciphertext",         to_base64url(ciphertext.data(), ciphertext.size())},
        {"encapsulated_key",   to_base64url(encapsulated_key.data(), encapsulated_key.size())},
        {"sent_at_ms",         sent_at_ms},
    };
    return j.dump();
}

// ---------------------------------------------------------------------------
// Deserialise a message object from GET /conversations/:id/messages
// ---------------------------------------------------------------------------
Message Message::from_json(std::string_view json_str) {
    json j;
    try {
        j = json::parse(json_str);
    } catch (const json::parse_error& e) {
        throw std::runtime_error(std::string("Message::from_json: invalid JSON: ") + e.what());
    }

    for (const char* field :
         {"message_id", "sender_id", "sender_username",
          "recipient_id", "recipient_username",
          "ciphertext", "encapsulated_key", "is_forwarded"}) {
        if (!j.contains(field)) {
            throw std::runtime_error(
                std::string("Message::from_json: missing required field '") + field + "'");
        }
    }

    Message m;
    m.message_id         = j.at("message_id").get<std::string>();
    m.sender_id          = j.at("sender_id").get<std::string>();
    m.sender_username    = j.at("sender_username").get<std::string>();
    m.recipient_id       = j.at("recipient_id").get<std::string>();
    m.recipient_username = j.at("recipient_username").get<std::string>();

    m.ciphertext       = from_base64url(j.at("ciphertext").get<std::string>());
    m.encapsulated_key = from_base64url(j.at("encapsulated_key").get<std::string>());

    m.is_forwarded = j.at("is_forwarded").get<bool>();

    // original_message_id is null when the message was not forwarded
    if (j.contains("original_message_id") && !j.at("original_message_id").is_null()) {
        m.original_message_id = j.at("original_message_id").get<std::string>();
    }

    // prefer the ms timestamp added in the sent_at_ms API update; fall back to parsing ISO 8601
    if (j.contains("sent_at_ms") && !j.at("sent_at_ms").is_null()) {
        m.sent_at_ms = j.at("sent_at_ms").get<long long>();
    } else if (j.contains("sent_at") && !j.at("sent_at").is_null()) {
        m.sent_at_ms = iso8601_to_ms(j.at("sent_at").get<std::string>());
    }

    return m;
}
