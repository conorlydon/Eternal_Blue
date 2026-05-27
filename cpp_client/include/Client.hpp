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
    int sync();                                        // pull + decrypt + persist new messages
    int read_message(std::string_view message_id);
    int delete_message(std::string_view message_id);
    int forward_message(std::string_view message_id, std::string_view recipient_username);

    // navigation (LocalStore-backed; no server round-trip)
    std::vector<ConvSummary> list_conversations();
    void                     print_conversations();
    std::vector<Message>     list_thread(const std::string& peer);
    void                     print_thread(const std::string& peer);

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
