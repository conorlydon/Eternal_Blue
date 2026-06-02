#pragma once
#include "HttpClient.hpp"
#include "CryptoContext.hpp"
#include "Keystore.hpp"
#include "LocalStore.hpp"
#include "TrustStore.hpp"
#include <string>
#include <string_view>
#include <vector>

struct ConvSummary {
    std::string peer;
    long long   last_sent_at_ms = 0;
    int         count = 0;
};

// top-level orchestrator: owns the http client, crypto, keystore, sqlite store,
// trust policy, and the in-memory session (token in http_, unwrapped secret key
// in session_sk_).
class Client {
public:
    Client(std::string_view host, std::string_view port, std::string_view ca_bundle = "");
    ~Client();

    int health();
    int signup(std::string_view username, std::string_view password);
    int login(std::string_view username, std::string_view password);
    int logout();

    int send_message(std::string_view recipient_username, std::string_view plaintext);
    // pull + decrypt + persist new messages, then reconcile revocations.
    // announce=false silences all output (used by the chat-mode background poll).
    int sync(bool announce = true);
    int read_message(std::string_view message_id);
    int delete_message(std::string_view message_id);
    int revoke_message(std::string_view message_id);   // sender recalls a message for both sides
    int forward_message(std::string_view message_id, std::string_view recipient_username);

    // trust management (TOFU pins)
    int print_fingerprint(std::string_view username);   // sha-256 of the pinned key, for OOB compare
    int confirm_rotation(std::string_view username);    // explicitly re-pin to the server's current key

    // navigation (LocalStore-backed; no server round-trip)
    std::vector<ConvSummary> list_conversations();
    void                     print_conversations();
    std::vector<Message>     list_thread(const std::string& peer);
    // prints the thread with 1-based indices and returns it so the caller can
    // map an index back to a message_id (used by chat-mode /delete and /forward)
    std::vector<Message>     print_thread(const std::string& peer);
    // one rendered thread line ("<n>. [<who> <iso>] <body>"), no trailing
    // newline; shared by print_thread and the chat-mode incremental renderer
    std::string              format_thread_line(std::size_t index, const Message& m) const;

    bool logged_in() const { return logged_in_; }
    const std::string& current_username() const { return username_; }

private:
    // GET /api/keys/:username -> User::from_json -> TrustStore::lookup_or_pin.
    // throws KeyChangedError on pin mismatch.
    User lookup_user(const std::string& username);

    HttpClient    http_;
    CryptoContext crypto_;
    Keystore      keystore_;
    LocalStore    store_;
    TrustStore    trust_;

    bool        logged_in_ = false;
    std::string user_id_;
    std::string username_;
    SecretKey   session_sk_{};   // valid only while logged_in_; zeroed on logout/dtor
};
