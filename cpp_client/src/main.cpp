#include "Client.hpp"

#include <iostream>
#include <string>
#include <string_view>

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

    if (command.empty()) {
        std::cerr << "usage: eternal-blue <command> [--host H] [--port P] [--ca-bundle PATH]\n";
        return 2;
    }

    try {
        Client client(host, port, ca_bundle);
        if (command == "health") return client.health();
        std::cerr << "unknown command: " << command << "\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
