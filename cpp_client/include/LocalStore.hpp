#pragma once
#include "Message.hpp"
#include "User.hpp"
#include <optional>
#include <string>
#include <vector>
#include <stdexcept>

struct sqlite3;   // forward-declared; full include in the .cpp

class LocalStoreError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// opens + creates tables on construction; owns the sqlite3 handle
class LocalStore {
public:
    explicit LocalStore(const std::string& path);
    ~LocalStore();
    LocalStore(const LocalStore&) = delete;
    LocalStore& operator=(const LocalStore&) = delete;

    void save_message(const Message& m);
    std::optional<Message> get_message(const std::string& message_id);
    std::vector<Message> list_messages();          // excludes soft-deleted, newest first
    void mark_deleted(const std::string& message_id);

    // tofu pins (back TrustStore)
    void save_pin(const User& user);
    std::optional<User> get_pin(const std::string& username);

private:
    sqlite3* db_ = nullptr;
};
