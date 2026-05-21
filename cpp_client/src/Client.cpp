#include "Client.hpp"
#include "Base64.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <cstdlib>
#include <iostream>
#include <string>

using json = nlohmann::json;

namespace {

std::string default_keystore_path() {
    const char* home = std::getenv("HOME");
    std::string base = home ? home : ".";
    return base + "/.eternal-messenger/keys.bin";
}

}  // namespace

Client::Client(std::string_view host, std::string_view port, std::string_view ca_bundle)
    : http_(host, port, ca_bundle),
      keystore_(default_keystore_path()) {}

Client::~Client() {
    sodium_memzero(session_sk_.data(), session_sk_.size());
}

int Client::health() {
    HttpResponse resp = http_.get("/health");
    std::cout << "status " << resp.status_code << "\n"
              << resp.body << "\n";
    return resp.status_code == 200 ? 0 : 1;
}

int Client::signup(std::string_view username, std::string_view password) {
    KeyPair    kp      = crypto_.generate_keypair();
    Salt       salt    = crypto_.random_salt();
    Kek        kek     = crypto_.derive_kek(password, salt);
    WrappedKey wrapped = crypto_.wrap_key(kp.secret_key, kek);
    sodium_memzero(kek.data(), kek.size());

    // persist the wrapped key locally BEFORE publishing (protocol §3) so a lost
    // response never leaves a published public key with no recoverable private key
    keystore_.save({salt, wrapped});

    json body = {
        {"username",   std::string(username)},
        {"password",   std::string(password)},
        {"public_key", to_base64url(kp.public_key.data(), kp.public_key.size())},
    };
    sodium_memzero(kp.secret_key.data(), kp.secret_key.size());

    HttpResponse resp = http_.post("/api/auth/register", body.dump());
    if (resp.status_code == 201) {
        std::cout << "registered " << username << "\n";
        return 0;
    }
    std::cerr << "signup failed (" << resp.status_code << "): " << resp.body << "\n";
    return 1;
}

int Client::login(std::string_view username, std::string_view password) {
    if (!keystore_.exists()) {
        std::cerr << "no local keystore — run signup on this machine first\n";
        return 1;
    }

    json body = {{"username", std::string(username)}, {"password", std::string(password)}};
    HttpResponse resp = http_.post("/api/auth/login", body.dump());
    if (resp.status_code != 200) {
        std::cerr << "login failed (" << resp.status_code << "): " << resp.body << "\n";
        return 1;
    }

    json j = json::parse(resp.body);
    http_.set_bearer_token(j.at("token").get<std::string>());
    user_id_ = j.at("user_id").get<std::string>();

    // unwrap the local secret key into the session
    KeystoreData ks  = keystore_.load();
    Kek          kek = crypto_.derive_kek(password, ks.salt);
    session_sk_ = crypto_.unwrap_key(ks.wrapped, kek);   // throws CryptoError on password mismatch
    sodium_memzero(kek.data(), kek.size());

    username_   = std::string(username);
    logged_in_  = true;
    std::cout << "logged in as " << username_
              << " (token expires " << j.value("expires_at", "?") << ")\n";
    return 0;
}

int Client::logout() {
    if (!logged_in_) {
        std::cerr << "not logged in\n";
        return 1;
    }
    sodium_memzero(session_sk_.data(), session_sk_.size());
    http_.set_bearer_token("");
    logged_in_ = false;
    user_id_.clear();
    std::string who = username_;
    username_.clear();
    std::cout << "logged out " << who << "\n";
    return 0;
}
