#pragma once
#include "HttpClient.hpp"
#include "CryptoContext.hpp"
#include "Keystore.hpp"
#include <string>
#include <string_view>

// top-level orchestrator: owns the http client, crypto, keystore, and the
// in-memory session (token lives in http_, unwrapped secret key in session_sk_).
class Client {
public:
    Client(std::string_view host, std::string_view port, std::string_view ca_bundle = "");
    ~Client();

    int health();
    int signup(std::string_view username, std::string_view password);
    int login(std::string_view username, std::string_view password);
    int logout();

    bool logged_in() const { return logged_in_; }
    const std::string& current_username() const { return username_; }

private:
    HttpClient    http_;
    CryptoContext crypto_;
    Keystore      keystore_;

    bool        logged_in_ = false;
    std::string user_id_;
    std::string username_;
    SecretKey   session_sk_{};   // valid only while logged_in_; zeroed on logout/dtor
};
