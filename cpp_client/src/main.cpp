#include "Client.hpp"

#include <sodium.h>
#include <poll.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::vector<std::string> split(const std::string& line) {
    std::vector<std::string> out;
    std::istringstream iss(line);
    for (std::string w; iss >> w;) out.push_back(w);
    return out;
}

// read a line from stdin with terminal echo disabled
std::string prompt_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    termios old{};
    tcgetattr(STDIN_FILENO, &old);
    termios no_echo = old;
    no_echo.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &no_echo);

    std::string pw;
    std::getline(std::cin, pw);

    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    std::cout << "\n";
    return pw;
}

// puts the terminal in a raw-ish mode for the chat line editor: character-at-a-
// time, no driver echo (we echo ourselves so a background redraw can't clobber
// the in-progress line), but signals stay on so Ctrl-C still works. restores the
// previous settings on destruction — on every exit path out of the chat loop.
class RawMode {
public:
    RawMode() {
        tcgetattr(STDIN_FILENO, &old_);
        termios raw = old_;
        raw.c_lflag &= ~static_cast<tcflag_t>(ICANON | ECHO);
        raw.c_cc[VMIN]  = 1;
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    }
    ~RawMode() { tcsetattr(STDIN_FILENO, TCSANOW, &old_); }
    RawMode(const RawMode&) = delete;
    RawMode& operator=(const RawMode&) = delete;
private:
    termios old_{};
};

void print_help() {
    std::cout <<
        "commands:\n"
        "  signup <username>          create an account on this machine\n"
        "  login <username>           authenticate and unlock the local key\n"
        "  logout                          end the session, wipe the key\n"
        "  sync                            fetch + decrypt new incoming messages (alias: inbox)\n"
        "  conversations                   list peers grouped by last activity (alias: convos)\n"
        "  chat <username>                 open a conversation (message actions live here)\n"
        "  send <username> <text...>       one-shot send without entering chat mode\n"
        "  health                          check server reachability\n"
        "  help                            this message\n"
        "  quit                            exit\n"
        "\n"
        "inside chat mode (auto-refreshes every few seconds):\n"
        "  <any text>                      send to the current peer\n"
        "  /sync                           pull new messages now (verbose)\n"
        "  /list                           reprint the thread\n"
        "  /delete <#>                     delete the Nth message (your view only)\n"
        "  /revoke <#>                     recall the Nth message you sent, for both sides\n"
        "  /forward <#> <user>             forward the Nth message to another user\n"
        "  /back  or  /quit                return to the top-level prompt\n";
}

// resolve a 1-based index string against the most recently printed thread.
// returns the message_id, or empty on parse/range failure (with stderr message).
std::string resolve_index(const std::vector<Message>& thread, const std::string& tok) {
    int n = 0;
    try { n = std::stoi(tok); }
    catch (...) { std::cerr << "expected a number, got: " << tok << "\n"; return ""; }
    if (n < 1 || static_cast<size_t>(n) > thread.size()) {
        std::cerr << "index " << n << " out of range (thread has "
                  << thread.size() << " messages)\n";
        return "";
    }
    return thread[n - 1].message_id;
}

// how long the chat loop waits for input before polling the server in the
// background. fresh TLS round-trips per tick, so don't set this too low.
constexpr int kSyncIntervalMs = 5000;

// worth-reprinting test: a message added/removed, or a revocation toggled.
// both vectors come from list_thread (same oldest-first ordering).
bool thread_changed(const std::vector<Message>& a, const std::vector<Message>& b) {
    if (a.size() != b.size()) return true;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i].message_id != b[i].message_id) return true;
        if (a[i].revoked    != b[i].revoked)    return true;
    }
    return false;
}

void run_chat(Client& client, const std::string& peer) {
    RawMode raw;   // restored on every return path below

    std::string input;              // line being composed — we own it, so a
                                    // background redraw can't clobber it
    bool pending_refresh = false;   // a change arrived while you were typing

    auto prompt_prefix = [&]() {
        return peer + (pending_refresh ? std::string(" (new)") : std::string()) + "| ";
    };
    auto redraw_prompt = [&]() {
        std::cout << "\r\033[K" << prompt_prefix() << input << std::flush;   // \r + erase-to-eol
    };

    client.sync(false);                                        // quiet refresh on entry
    std::vector<Message> displayed = client.print_thread(peer);

    auto full_reprint = [&]() {
        std::cout << "\r\033[K";
        displayed = client.print_thread(peer);
        pending_refresh = false;
        redraw_prompt();
    };

    redraw_prompt();

    auto handle_line = [&](const std::string& line) -> bool {   // false => leave chat
        std::vector<std::string> args = split(line);
        if (args.empty()) return true;
        const std::string& sub = args[0];
        if (sub[0] == '/') {
            if (sub == "/back" || sub == "/quit" || sub == "/exit") return false;
            else if (sub == "/sync") client.sync(true);
            else if (sub == "/list") { /* full_reprint below shows it */ }
            else if (sub == "/delete") {
                if (args.size() < 2) { std::cerr << "usage: /delete <#>\n"; return true; }
                std::string id = resolve_index(displayed, args[1]);
                if (!id.empty()) client.delete_message(id);
            }
            else if (sub == "/revoke") {
                if (args.size() < 2) { std::cerr << "usage: /revoke <#>\n"; return true; }
                std::string id = resolve_index(displayed, args[1]);
                if (!id.empty()) client.revoke_message(id);
            }
            else if (sub == "/forward") {
                if (args.size() < 3) { std::cerr << "usage: /forward <#> <username>\n"; return true; }
                std::string id = resolve_index(displayed, args[1]);
                if (!id.empty()) client.forward_message(id, args[2]);
            }
            else std::cerr << "unknown chat command: " << sub
                           << " (try /back, /sync, /list, /delete, /revoke, /forward)\n";
        } else {
            client.send_message(peer, line);
        }
        return true;
    };

    char buf[128];
    while (true) {
        struct pollfd pfd{ STDIN_FILENO, POLLIN, 0 };
        int r = poll(&pfd, 1, kSyncIntervalMs);
        if (r < 0) { if (errno == EINTR) continue; break; }

        if (r == 0) {
            // idle tick: pull from the server, then reflect any change
            try {
                client.sync(false);
                auto fresh = client.list_thread(peer);
                if (thread_changed(displayed, fresh)) {
                    if (input.empty()) full_reprint();          // safe to redraw now
                    else { pending_refresh = true; redraw_prompt(); }  // defer, just hint
                }
            } catch (const std::exception& e) {
                std::cout << "\r\033[K"; std::cerr << "sync error: " << e.what() << "\n"; redraw_prompt();
            }
            continue;
        }

        ssize_t n = ::read(STDIN_FILENO, buf, sizeof buf);
        if (n <= 0) { std::cout << "\n"; break; }                // EOF on stdin
        for (ssize_t i = 0; i < n; ++i) {
            unsigned char c = static_cast<unsigned char>(buf[i]);
            if (c == '\n' || c == '\r') {
                std::cout << "\n";
                std::string line = input;
                input.clear();
                if (line.empty()) {
                    if (pending_refresh) full_reprint();         // surface deferred changes
                    else                 redraw_prompt();
                } else {
                    bool cont = true;
                    try { cont = handle_line(line); }
                    catch (const std::exception& e) { std::cerr << "error: " << e.what() << "\n"; }
                    if (!cont) return;
                    full_reprint();                              // resync the displayed thread
                }
            }
            else if (c == 0x7f || c == 0x08) {                   // backspace / delete
                if (!input.empty()) { input.pop_back(); std::cout << "\b \b" << std::flush; }
                else if (pending_refresh) full_reprint();        // empty line + deferred change
            }
            else if (c == 0x1b) {                                // swallow an escape / arrow sequence
                if (i + 1 < n && (buf[i + 1] == '[' || buf[i + 1] == 'O')) {
                    i += 2;
                    while (i < n && !(static_cast<unsigned char>(buf[i]) >= 0x40 &&
                                      static_cast<unsigned char>(buf[i]) <= 0x7e)) ++i;
                }
            }
            else if (c == 0x04) {                                // Ctrl-D on an empty line leaves chat
                if (input.empty()) { std::cout << "\n"; return; }
            }
            else if (c >= 0x20 && c < 0x7f) {                    // printable
                input.push_back(static_cast<char>(c));
                std::cout << static_cast<char>(c) << std::flush;
            }
            // other control bytes ignored
        }
    }
}

void run_repl(Client& client) {
    std::cout << "eternal-blue — type 'help' or 'quit'\n";
    std::string line;
    while (true) {
        std::cout << (client.logged_in() ? client.current_username() : "") << "> " << std::flush;
        if (!std::getline(std::cin, line)) { std::cout << "\n"; break; }   // EOF

        std::vector<std::string> args = split(line);
        if (args.empty()) continue;
        const std::string& cmd = args[0];

        try {
            if (cmd == "quit" || cmd == "exit") break;
            else if (cmd == "help")   print_help();
            else if (cmd == "health") client.health();
            else if (cmd == "logout") client.logout();
            else if (cmd == "signup" || cmd == "login") {
                if (args.size() < 2) { std::cerr << "usage: " << cmd << " <username>\n"; continue; }
                std::string pw = prompt_password("password: ");
                if (cmd == "signup") client.signup(args[1], pw);
                else                 client.login(args[1], pw);
                sodium_memzero(pw.data(), pw.size());
            }
            else if (cmd == "send") {
                if (args.size() < 3) { std::cerr << "usage: send <username> <text...>\n"; continue; }
                std::string text;
                for (size_t i = 2; i < args.size(); ++i) {
                    if (i > 2) text += ' ';
                    text += args[i];
                }
                client.send_message(args[1], text);
            }
            else if (cmd == "sync" || cmd == "inbox") client.sync();
            else if (cmd == "conversations" || cmd == "convos") {
                if (!client.logged_in()) { std::cerr << "not logged in\n"; continue; }
                client.print_conversations();
            }
            else if (cmd == "chat") {
                if (!client.logged_in()) { std::cerr << "not logged in\n"; continue; }
                if (args.size() < 2) { std::cerr << "usage: chat <username>\n"; continue; }
                run_chat(client, args[1]);
            }
            else std::cerr << "unknown command: " << cmd
                           << " (try 'help'; message actions live inside 'chat <user>')\n";
        } catch (const std::exception& e) {
            std::cerr << "error: " << e.what() << "\n";
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    std::string host = "localhost";
    std::string port = "8991";
    std::string ca_bundle;
    std::string command;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--host" && i + 1 < argc)            host = argv[++i];
        else if (arg == "--port" && i + 1 < argc)       port = argv[++i];
        else if (arg == "--ca-bundle" && i + 1 < argc)  ca_bundle = argv[++i];
        else if (command.empty())                       command = arg;
        else { std::cerr << "unexpected argument: " << arg << "\n"; return 2; }
    }

    try {
        Client client(host, port, ca_bundle);
        if (command.empty()) { run_repl(client); return 0; }
        if (command == "health") return client.health();   // one-shot convenience
        std::cerr << "unknown one-shot command: " << command
                  << " (run with no command for the interactive shell)\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
