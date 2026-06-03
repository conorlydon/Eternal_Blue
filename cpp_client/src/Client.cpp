#include "Client.hpp"
#include "Base64.hpp"
#include "Message.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <sys/stat.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>

using json = nlohmann::json;

namespace {

std::string home_dir() {
    const char* h = std::getenv("HOME");
    return h ? std::string(h) : std::string(".");
}
// scope local storage by backend so switching --host doesn't merge pins / messages
std::string backend_subdir(std::string_view host, std::string_view port) {
    return std::string(host) + "_" + std::string(port);
}
void ensure_eb_dir(std::string_view host, std::string_view port) {
    ::mkdir((home_dir() + "/.eternal-messenger").c_str(), 0700);   // parent
    ::mkdir((home_dir() + "/.eternal-messenger/" + backend_subdir(host, port)).c_str(), 0700);
}
std::string default_keystore_path(std::string_view host, std::string_view port) {
    ensure_eb_dir(host, port);
    return home_dir() + "/.eternal-messenger/" + backend_subdir(host, port) + "/keys.bin";
}
std::string default_store_path(std::string_view host, std::string_view port) {
    ensure_eb_dir(host, port);
    return home_dir() + "/.eternal-messenger/" + backend_subdir(host, port) + "/store.db";
}

long long current_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string ms_to_iso(long long ms) {
    std::time_t t = static_cast<std::time_t>(ms / 1000);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

// canonical AAD : sender_id | recipient_id | sent_at_ms
std::string make_aad(const std::string& sender_id, const std::string& recipient_id, long long sent_at_ms) {
    return sender_id + "|" + recipient_id + "|" + std::to_string(sent_at_ms);
}

constexpr const char* kMsgInfo = "eternal-blue-msg-v1";

}  

Client::Client(std::string_view host, std::string_view port, std::string_view ca_bundle)
    : http_(host, port, ca_bundle),
      keystore_(default_keystore_path(host, port)),
      store_(default_store_path(host, port)),
      trust_(store_) {}

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

    // persist the wrapped key locally BEFORE publishing so a lost
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

    KeystoreData ks  = keystore_.load();
    Kek          kek = crypto_.derive_kek(password, ks.salt);
    session_sk_ = crypto_.unwrap_key(ks.wrapped, kek);
    sodium_memzero(kek.data(), kek.size());

    username_   = std::string(username);
    logged_in_  = true;
    std::cout << "logged in as " << username_
              << " (token expires " << j.value("expires_at", "?") << ")\n";
    return 0;
}

int Client::logout() {
    if (!logged_in_) { std::cerr << "not logged in\n"; return 1; }
    sodium_memzero(session_sk_.data(), session_sk_.size());
    http_.set_bearer_token("");
    logged_in_ = false;
    user_id_.clear();
    std::string who = username_;
    username_.clear();
    std::cout << "logged out " << who << "\n";
    return 0;
}

User Client::lookup_user(const std::string& username) {
    HttpResponse resp = http_.get("/api/keys/" + username);
    if (resp.status_code != 200) {
        throw std::runtime_error("lookup '" + username + "' failed (" +
                                 std::to_string(resp.status_code) + "): " + resp.body);
    }
    User u = User::from_json(resp.body);
    return trust_.lookup_or_pin(u);
}

int Client::print_fingerprint(std::string_view username) {
    auto pin = store_.get_pin(std::string(username));
    if (!pin) {
        std::cout << "no pinned key for " << username
                  << " yet — exchange a message first, then re-check\n";
        return 1;
    }
    std::cout << "pinned key fingerprint for " << username << ":\n  "
              << TrustStore::fingerprint(pin->public_key) << "\n"
              << "compare this out-of-band (call / in person) against " << username
              << "'s own copy\n";
    return 0;
}

int Client::confirm_rotation(std::string_view username) {
    std::string name(username);
    // fetch directly, bypassing lookup_user's TOFU check, which would just re-throw
    HttpResponse resp = http_.get("/api/keys/" + name);
    if (resp.status_code != 200) {
        std::cerr << "lookup '" << name << "' failed (" << resp.status_code << "): " << resp.body << "\n";
        return 1;
    }
    User fetched = User::from_json(resp.body);

    auto pin = store_.get_pin(name);
    if (!pin) {
        store_.save_pin(fetched);
        std::cout << "pinned " << name << " (no previous pin):\n  "
                  << TrustStore::fingerprint(fetched.public_key) << "\n";
        return 0;
    }
    if (pin->public_key == fetched.public_key) {
        std::cout << "no rotation needed — the pinned key already matches the server\n";
        return 0;
    }
    std::cout << "rotating pinned key for " << name << ":\n"
              << "  old: " << TrustStore::fingerprint(pin->public_key) << "\n"
              << "  new: " << TrustStore::fingerprint(fetched.public_key) << "\n"
              << "only proceed if you have verified the new fingerprint out-of-band.\n"
              << "overwrite the pin? [y/N]: " << std::flush;

    std::string answer;
    if (!std::getline(std::cin, answer) ||
        (answer != "y" && answer != "Y" && answer != "yes" && answer != "Yes")) {
        std::cout << "rotation cancelled — pin unchanged\n";
        return 1;
    }

    store_.save_pin(fetched);
    std::cout << "pin overwritten for " << name << "\n";
    return 0;
}

int Client::send_message(std::string_view recipient_username, std::string_view plaintext) {
    if (!logged_in_) { std::cerr << "not logged in\n"; return 1; }

    User recipient;
    try {
        recipient = lookup_user(std::string(recipient_username));
    } catch (const KeyChangedError& e) {
        std::cerr << "ABORT: " << e.what() << "\n"; return 1;
    } catch (const std::exception& e) {
        std::cerr << "lookup failed: " << e.what() << "\n"; return 1;
    }

    long long sent_at_ms = current_ms();
    std::string aad = make_aad(user_id_, recipient.user_id, sent_at_ms);

    std::vector<unsigned char> pt(plaintext.begin(), plaintext.end());
    Sealed sealed = crypto_.seal_auth(recipient.public_key, session_sk_, kMsgInfo, aad, pt);

    // build a complete Message — to_send_json only serializes the wire fields,
    // and the same struct is what we save locally after a successful post
    Message m;
    m.sender_id          = user_id_;
    m.sender_username    = username_;
    m.recipient_id       = recipient.user_id;
    m.recipient_username = recipient.username;
    m.encapsulated_key.assign(sealed.enc.begin(), sealed.enc.end());
    m.ciphertext         = sealed.ciphertext;          // keep a copy; need it for save_message
    m.sent_at_ms         = sent_at_ms;
    m.plaintext          = std::string(plaintext);
    m.signature_verified = true;

    HttpResponse resp = http_.post("/api/messages", m.to_send_json());
    if (resp.status_code != 201) {
        std::cerr << "send failed (" << resp.status_code << "): " << resp.body << "\n";
        return 1;
    }
    json j = json::parse(resp.body);
    m.message_id = j.value("message_id", "");
    store_.save_message(m);                              // outbox: visible in conversations + chat
    std::cout << "sent to " << recipient.username << " [" << m.message_id << "]\n";
    return 0;
}

int Client::sync(bool announce) {
    if (!logged_in_) { if (announce) std::cerr << "not logged in\n"; return 1; }

    HttpResponse resp = http_.get("/api/messages?box=inbox");
    if (resp.status_code != 200) {
        if (announce) std::cerr << "inbox failed (" << resp.status_code << "): " << resp.body << "\n";
        return 1;
    }

    json j = json::parse(resp.body);
    std::unordered_map<std::string, User> sender_cache;
    int saved = 0, skipped = 0;

    for (const auto& msg_j : j.at("messages")) {
        Message m;
        try {
            m = Message::from_json(msg_j.dump());
        } catch (const std::exception& e) {
            if (announce) std::cerr << "skip (bad json): " << e.what() << "\n";
            ++skipped; continue;
        }

        // lookup sender's pk (TOFU), cached per call
        User sender;
        auto it = sender_cache.find(m.sender_username);
        if (it != sender_cache.end()) {
            sender = it->second;
        } else {
            try {
                sender = lookup_user(m.sender_username);
                sender_cache.emplace(m.sender_username, sender);
            } catch (const std::exception& e) {
                if (announce) std::cerr << "skip " << m.message_id << " (sender lookup): " << e.what() << "\n";
                ++skipped; continue;
            }
        }

        if (m.encapsulated_key.size() != crypto_kx_PUBLICKEYBYTES) {
            if (announce) std::cerr << "skip " << m.message_id << " (bad enc size)\n";
            ++skipped; continue;
        }
        PublicKey enc{};
        std::copy(m.encapsulated_key.begin(), m.encapsulated_key.end(), enc.begin());

        std::string aad = make_aad(m.sender_id, m.recipient_id, m.sent_at_ms);
        try {
            auto pt = crypto_.open_auth(enc, session_sk_, sender.public_key,
                                        kMsgInfo, aad, m.ciphertext);
            m.plaintext = std::string(pt.begin(), pt.end());
            m.signature_verified = true;
        } catch (const std::exception& e) {
            if (announce) std::cerr << "skip " << m.message_id << " (open failed): " << e.what() << "\n";
            ++skipped; continue;
        }

        // save_message uses INSERT OR REPLACE, so check existence ourselves to count "new"
        if (store_.get_message(m.message_id).has_value()) {
            continue;   // already in the store from an earlier fetch — silent
        }
        store_.save_message(m);
        ++saved;
        if (announce)
            std::cout << "  [" << m.message_id << "] from " << m.sender_username
                      << " " << ms_to_iso(m.sent_at_ms) << "\n";
    }

    // reconcile revocations: a message we already cached may since have been
    // recalled by its sender. the server filters revoked messages out of the
    // inbox above, so we learn about them from this dedicated list and null the
    // local plaintext for any we still hold.
    int revoked = 0;
    HttpResponse rev = http_.get("/api/messages/revoked");
    if (rev.status_code == 200) {
        try {
            json rj = json::parse(rev.body);
            for (const auto& id_j : rj.at("revoked_ids")) {
                std::string id = id_j.get<std::string>();
                auto existing = store_.get_message(id);
                if (existing && !existing->revoked) {
                    store_.mark_revoked(id);
                    ++revoked;
                }
            }
        } catch (const std::exception& e) {
            if (announce) std::cerr << "revocation sync skipped: " << e.what() << "\n";
        }
    } else {
        if (announce) std::cerr << "revocation sync failed (" << rev.status_code << ")\n";
    }

    if (announce)
        std::cout << "inbox: " << saved << " new, " << revoked << " revoked, "
                  << skipped << " skipped\n";
    return 0;
}

int Client::read_message(std::string_view message_id) {
    if (!logged_in_) { std::cerr << "not logged in\n"; return 1; }
    auto m = store_.get_message(std::string(message_id));
    if (!m) { std::cerr << "no such message: " << message_id << "\n"; return 1; }
    std::cout << "from " << m->sender_username << " " << ms_to_iso(m->sent_at_ms);
    if (m->signature_verified) std::cout << " [signed]";
    std::cout << "\n" << m->plaintext << "\n";
    return 0;
}

int Client::delete_message(std::string_view message_id) {
    if (!logged_in_) { std::cerr << "not logged in\n"; return 1; }
    HttpResponse resp = http_.del("/api/messages/" + std::string(message_id));
    if (resp.status_code == 200) {
        store_.mark_deleted(std::string(message_id));
        std::cout << "deleted " << message_id << "\n";
        return 0;
    }
    std::cerr << "delete failed (" << resp.status_code << "): " << resp.body << "\n";
    return 1;
}

// sender-only recall. the server stops serving the ciphertext (and reports the
// id via /messages/revoked so the recipient nulls their copy on next sync); we
// null our own copy here too. revokes only this message — forwarded copies are
// independent messages and are left intact.
int Client::revoke_message(std::string_view message_id) {
    if (!logged_in_) { std::cerr << "not logged in\n"; return 1; }

    auto m = store_.get_message(std::string(message_id));
    if (!m) { std::cerr << "no such message: " << message_id << "\n"; return 1; }
    if (m->sender_username != username_) {
        std::cerr << "can only revoke messages you sent\n"; return 1;
    }

    HttpResponse resp = http_.del("/api/messages/" + std::string(message_id) + "/revoke");
    if (resp.status_code == 200) {
        store_.mark_revoked(std::string(message_id));
        std::cout << "revoked " << message_id << "\n";
        return 0;
    }
    std::cerr << "revoke failed (" << resp.status_code << "): " << resp.body << "\n";
    return 1;
}

int Client::forward_message(std::string_view message_id, std::string_view recipient_username) {
    if (!logged_in_) { std::cerr << "not logged in\n"; return 1; }

    auto m = store_.get_message(std::string(message_id));
    if (!m) { std::cerr << "no such message: " << message_id << "\n"; return 1; }
    if (m->plaintext.empty()) { std::cerr << "message has no decrypted plaintext\n"; return 1; }

    User recipient;
    try {
        recipient = lookup_user(std::string(recipient_username));
    } catch (const KeyChangedError& e) {
        std::cerr << "ABORT: " << e.what() << "\n"; return 1;
    } catch (const std::exception& e) {
        std::cerr << "lookup failed: " << e.what() << "\n"; return 1;
    }

    long long sent_at_ms = current_ms();
    std::string aad = make_aad(user_id_, recipient.user_id, sent_at_ms);

    std::vector<unsigned char> pt(m->plaintext.begin(), m->plaintext.end());
    Sealed sealed = crypto_.seal_auth(recipient.public_key, session_sk_, kMsgInfo, aad, pt);

    json body = {
        {"forward_to_username", recipient.username},
        {"ciphertext",          to_base64url(sealed.ciphertext.data(), sealed.ciphertext.size())},
        {"encapsulated_key",    to_base64url(sealed.enc.data(),        sealed.enc.size())},
        {"sent_at_ms",          sent_at_ms},
    };

    HttpResponse resp = http_.post("/api/messages/" + std::string(message_id) + "/forward", body.dump());
    if (resp.status_code == 201) {
        json j = json::parse(resp.body);
        std::cout << "forwarded to " << recipient.username
                  << " [" << j.value("message_id", "?") << "]\n";
        return 0;
    }
    std::cerr << "forward failed (" << resp.status_code << "): " << resp.body << "\n";
    return 1;
}

// group LocalStore messages by peer; flatten; sort by recency descending.
std::vector<ConvSummary> Client::list_conversations() {
    const std::string& me = username_;

    std::unordered_map<std::string, ConvSummary> by_peer;
    for (const auto& m : store_.list_messages()) {
        // only group messages where the current user is one party; ignore
        // anything else (e.g. third-party rows left over from a different identity)
        std::string peer;
        if      (m.sender_username    == me) peer = m.recipient_username;
        else if (m.recipient_username == me) peer = m.sender_username;
        else                                  continue;

        ConvSummary& s = by_peer[peer];
        if (s.peer.empty()) s.peer = peer;
        ++s.count;
        if (m.sent_at_ms > s.last_sent_at_ms) s.last_sent_at_ms = m.sent_at_ms;
    }

    std::vector<ConvSummary> convs;
    convs.reserve(by_peer.size());
    for (auto& kv : by_peer) convs.push_back(std::move(kv.second));

    std::sort(convs.begin(), convs.end(),
              [](const ConvSummary& a, const ConvSummary& b) {
                  return a.last_sent_at_ms > b.last_sent_at_ms;     // newest first
              });
    return convs;
}

void Client::print_conversations() {
    auto convs = list_conversations();
    if (convs.empty()) { std::cout << "(no conversations)\n"; return; }
    for (const auto& c : convs) {
        std::cout << "  " << c.peer
                  << "  last " << ms_to_iso(c.last_sent_at_ms)
                  << "  (" << c.count << (c.count == 1 ? " message" : " messages") << ")\n";
    }
}

// strict filter: messages BETWEEN me and peer (both sides represented), sorted chronologically.
std::vector<Message> Client::list_thread(const std::string& peer) {
    const std::string& me = username_;
    auto all = store_.list_messages();
    std::vector<Message> thread;
    thread.reserve(all.size());
    std::copy_if(all.begin(), all.end(), std::back_inserter(thread),
                 [&peer, &me](const Message& m) {
                     return (m.sender_username == me   && m.recipient_username == peer) ||
                            (m.sender_username == peer && m.recipient_username == me);
                 });
    std::sort(thread.begin(), thread.end(),
              [](const Message& a, const Message& b) {
                  return a.sent_at_ms < b.sent_at_ms;               // oldest first
              });
    return thread;
}

std::string Client::format_thread_line(std::size_t index, const Message& m) const {
    const bool from_me = (m.sender_username == username_);
    return std::to_string(index) + ". ["
         + (from_me ? std::string("you") : m.sender_username)
         + " " + ms_to_iso(m.sent_at_ms) + "] "
         + (m.revoked ? std::string("(message revoked)") : m.plaintext);
}

std::vector<Message> Client::print_thread(const std::string& peer) {
    auto thread = list_thread(peer);
    std::cout << "── chat with " << peer << " ──\n";
    if (thread.empty()) { std::cout << "(no messages yet)\n"; return thread; }
    for (std::size_t i = 0; i < thread.size(); ++i)
        std::cout << format_thread_line(i + 1, thread[i]) << "\n";
    return thread;
}
