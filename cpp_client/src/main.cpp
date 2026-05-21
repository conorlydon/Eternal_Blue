#include "Client.hpp"

#include <sodium.h>
#include <termios.h>
#include <unistd.h>

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

void print_help() {
    std::cout <<
        "commands:\n"
        "  signup <username>   create an account on this machine\n"
        "  login <username>    authenticate and unlock the local key\n"
        "  logout              end the session, wipe the key\n"
        "  health              check server reachability\n"
        "  help                this message\n"
        "  quit                exit\n";
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
            else std::cerr << "unknown command: " << cmd << " (try 'help')\n";
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
