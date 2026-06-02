#include "LocalStore.hpp"
#include <sqlite3.h>
#include <cstring>

/*rc- sqlite return
 db- sqlite database connection
 op- label, see what line crashed*/
static void check_ok(int rc, sqlite3* db, const char* op) {
    if (rc != SQLITE_OK)
        throw LocalStoreError(std::string(op) + ": " + sqlite3_errmsg(db));
}

//sqlite constructor
LocalStore::LocalStore(const std::string& path) {
    //open db file
    int rc = sqlite3_open(path.c_str(), &db_);
    //error handling: may still partially open
    if (rc != SQLITE_OK) {
        std::string msg = db_ ? sqlite3_errmsg(db_) : "sqlite3_open failed";
        sqlite3_close(db_);
        db_ = nullptr;
        throw LocalStoreError("open: " + msg);
    }
    //table creations: schema: create table if doesnt exist ? do nothing
    //messages: stores every message client received
    //pinned_keys: stores first pub key of everyone youve messaged(TOFU pinning)
    const char* schema = R"(
        CREATE TABLE IF NOT EXISTS messages (
            message_id          TEXT    PRIMARY KEY,
            sender_id           TEXT    NOT NULL,
            sender_username     TEXT    NOT NULL,
            recipient_id        TEXT    NOT NULL,
            recipient_username  TEXT    NOT NULL,
            encapsulated_key    BLOB    NOT NULL,
            ciphertext          BLOB    NOT NULL,
            sent_at_ms          INTEGER NOT NULL,
            is_forwarded        INTEGER NOT NULL DEFAULT 0,
            original_message_id TEXT    NOT NULL DEFAULT '',
            plaintext           TEXT    NOT NULL DEFAULT '',
            signature_verified  INTEGER NOT NULL DEFAULT 0,
            deleted             INTEGER NOT NULL DEFAULT 0,
            revoked             INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS pinned_keys (
            username    TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            public_key  BLOB NOT NULL,
            key_version INTEGER NOT NULL DEFAULT 1
        );
    )";

    char* errmsg = nullptr;
    rc = sqlite3_exec(db_, schema, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::string msg = errmsg ? errmsg : "schema creation failed";
        sqlite3_free(errmsg);
        sqlite3_close(db_);
        db_ = nullptr;
        throw LocalStoreError("schema: " + msg);
    }

    // migrate stores created before the `revoked` column existed. sqlite has no
    // ADD COLUMN IF NOT EXISTS, so run it unconditionally and ignore the
    // "duplicate column name" error returned on stores that already have it.
    sqlite3_exec(db_, "ALTER TABLE messages ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0",
                 nullptr, nullptr, nullptr);
}
//destructor
//close db connection + release file lock
//db_ points to nothing so it crashes if anything uses it.
LocalStore::~LocalStore() {
    if (db_) { sqlite3_close(db_); db_ = nullptr; }
}

//takes row of db results, converts into message obj
static Message row_to_message(sqlite3_stmt* stmt) {
    Message m;
    m.message_id          = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    m.sender_id           = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    m.sender_username     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    m.recipient_id        = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    m.recipient_username  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));

    //read BLOBs(encryption keys+ciphertext)
    const auto* ek = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 5));
    int ek_size    = sqlite3_column_bytes(stmt, 5);
    m.encapsulated_key.assign(ek, ek + ek_size);

    const auto* ct = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 6));
    int ct_size    = sqlite3_column_bytes(stmt, 6);
    m.ciphertext.assign(ct, ct + ct_size);

    //read int columns
    m.sent_at_ms          = sqlite3_column_int64(stmt, 7);
    m.is_forwarded        = sqlite3_column_int(stmt, 8) != 0;
    m.original_message_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
    m.plaintext           = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
    m.signature_verified  = sqlite3_column_int(stmt, 11) != 0;
    m.revoked             = sqlite3_column_int(stmt, 12) != 0;
    return m;
}

void LocalStore::save_message(const Message& m) {
    // IGNORE not REPLACE so re-saving never resurrects a locally deleted/revoked row
    const char* sql = R"(
        INSERT OR IGNORE INTO messages
            (message_id, sender_id, sender_username, recipient_id, recipient_username,
             encapsulated_key, ciphertext, sent_at_ms, is_forwarded, original_message_id,
             plaintext, signature_verified, deleted)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)
    )";
    sqlite3_stmt* stmt = nullptr;
    //compile sql & fill in values
    check_ok(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr), db_, "save_message prepare");

    sqlite3_bind_text(stmt,  1, m.message_id.c_str(),          -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt,  2, m.sender_id.c_str(),           -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt,  3, m.sender_username.c_str(),     -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt,  4, m.recipient_id.c_str(),        -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt,  5, m.recipient_username.c_str(),  -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt,  6, m.encapsulated_key.data(), static_cast<int>(m.encapsulated_key.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt,  7, m.ciphertext.data(),       static_cast<int>(m.ciphertext.size()),       SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 8, m.sent_at_ms);
    sqlite3_bind_int(stmt,   9, m.is_forwarded ? 1 : 0);
    sqlite3_bind_text(stmt, 10, m.original_message_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 11, m.plaintext.c_str(),           -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt,  12, m.signature_verified ? 1 : 0);

    //execute+cleanup
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        throw LocalStoreError(std::string("save_message: ") + sqlite3_errmsg(db_));
}

//type: wrapper(might have a value, may not)
std::optional<Message> LocalStore::get_message(const std::string& message_id) {
    const char* sql = R"(
        SELECT message_id, sender_id, sender_username, recipient_id, recipient_username,
               encapsulated_key, ciphertext, sent_at_ms, is_forwarded, original_message_id,
               plaintext, signature_verified, revoked
        FROM messages WHERE message_id = ? AND deleted = 0
    )";
    sqlite3_stmt* stmt = nullptr;
    check_ok(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr), db_, "get_message prepare");
    sqlite3_bind_text(stmt, 1, message_id.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) { sqlite3_finalize(stmt); return std::nullopt; }
    if (rc != SQLITE_ROW)  { sqlite3_finalize(stmt); throw LocalStoreError(std::string("get_message: ") + sqlite3_errmsg(db_)); }

    Message m = row_to_message(stmt);
    sqlite3_finalize(stmt);
    return m;
}

//list all messages in db, as long as there is more
std::vector<Message> LocalStore::list_messages() {
    const char* sql = R"(
        SELECT message_id, sender_id, sender_username, recipient_id, recipient_username,
               encapsulated_key, ciphertext, sent_at_ms, is_forwarded, original_message_id,
               plaintext, signature_verified, revoked
        FROM messages WHERE deleted = 0 ORDER BY sent_at_ms DESC
    )";
    sqlite3_stmt* stmt = nullptr;
    check_ok(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr), db_, "list_messages prepare");

    std::vector<Message> result;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
        result.push_back(row_to_message(stmt));
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        throw LocalStoreError(std::string("list_messages: ") + sqlite3_errmsg(db_));
    return result;
}


void LocalStore::mark_deleted(const std::string& message_id) {
    const char* sql = "UPDATE messages SET deleted = 1 WHERE message_id = ?";
    sqlite3_stmt* stmt = nullptr;
    check_ok(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr), db_, "mark_deleted prepare");
    sqlite3_bind_text(stmt, 1, message_id.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        throw LocalStoreError(std::string("mark_deleted: ") + sqlite3_errmsg(db_));
}

// null the plaintext and flag the row revoked. the message stays in the thread
// (not deleted) so it can render as a tombstone rather than silently vanish.
void LocalStore::mark_revoked(const std::string& message_id) {
    const char* sql = "UPDATE messages SET plaintext = '', revoked = 1 WHERE message_id = ?";
    sqlite3_stmt* stmt = nullptr;
    check_ok(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr), db_, "mark_revoked prepare");
    sqlite3_bind_text(stmt, 1, message_id.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        throw LocalStoreError(std::string("mark_revoked: ") + sqlite3_errmsg(db_));
}

void LocalStore::save_pin(const User& user) {
    const char* sql = R"(
        INSERT OR REPLACE INTO pinned_keys (username, user_id, public_key, key_version)
        VALUES (?,?,?,?)
    )";
    sqlite3_stmt* stmt = nullptr;
    check_ok(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr), db_, "save_pin prepare");
    sqlite3_bind_text(stmt, 1, user.username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user.user_id.c_str(),  -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, user.public_key.data(), static_cast<int>(user.public_key.size()), SQLITE_STATIC);
    sqlite3_bind_int(stmt,  4, user.key_version);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        throw LocalStoreError(std::string("save_pin: ") + sqlite3_errmsg(db_));
}

std::optional<User> LocalStore::get_pin(const std::string& username) {
    const char* sql = "SELECT username, user_id, public_key, key_version FROM pinned_keys WHERE username = ?";
    sqlite3_stmt* stmt = nullptr;
    check_ok(sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr), db_, "get_pin prepare");
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) { sqlite3_finalize(stmt); return std::nullopt; }
    if (rc != SQLITE_ROW)  { sqlite3_finalize(stmt); throw LocalStoreError(std::string("get_pin: ") + sqlite3_errmsg(db_)); }

    User u;
    u.username    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    u.user_id     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    const void* pk_blob = sqlite3_column_blob(stmt, 2);
    int pk_size         = sqlite3_column_bytes(stmt, 2);
    if (pk_size != static_cast<int>(u.public_key.size())) {
        sqlite3_finalize(stmt);
        throw LocalStoreError("get_pin: stored public key has wrong size");
    }
    std::memcpy(u.public_key.data(), pk_blob, static_cast<size_t>(pk_size));
    u.key_version = sqlite3_column_int(stmt, 3);

    sqlite3_finalize(stmt);
    return u;
}
