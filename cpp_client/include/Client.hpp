#pragma once
#include "HttpClient.hpp"
#include <string_view>

// top-level orchestrator: owns the http client, dispatches commands
class Client {
public:
    Client(std::string_view host, std::string_view port, std::string_view ca_bundle = "");

    int health();

private:
    HttpClient http_;
};
