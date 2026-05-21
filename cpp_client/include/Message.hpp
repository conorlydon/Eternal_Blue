#pragma once
#include <string>
#include <string_view>
#include <vector>

struct Message {
    std::string message_id;
    std::string sender_id;
    std::string sender_username;
    std::string recipient_id;
    std::string recipient_username;

    std::vector<unsigned char> encapsulated_key;   // HPKE enc; "session_key" on the wire
    std::vector<unsigned char> ciphertext;          // base64url on the wire

    long long   sent_at_ms = 0;
    bool        is_forwarded = false;
    std::string original_message_id;                // empty if not forwarded

    // client-only, never sent
    std::string plaintext;
    bool        signature_verified = false;

    std::string to_send_json() const;               // body for POST /api/messages
    static Message from_json(std::string_view json);
};
