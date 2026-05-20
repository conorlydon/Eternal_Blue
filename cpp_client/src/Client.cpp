#include "Client.hpp"

#include <iostream>

Client::Client(std::string_view host, std::string_view port, std::string_view ca_bundle)
    : http_(host, port, ca_bundle) {}

int Client::health() {
    HttpResponse resp = http_.get("/health");
    std::cout << "status " << resp.status_code << "\n"
              << resp.body << "\n";
    return resp.status_code == 200 ? 0 : 1;
}
