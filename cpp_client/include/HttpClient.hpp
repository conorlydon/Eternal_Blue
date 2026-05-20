#pragma once
#include <string>
#include <string_view>
#include <stdexcept>

// http-layer failures; transport failures throw TlsError so callers can tell them apart
class HttpError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct HttpResponse {
    int status_code = 0;
    std::string body;
};

// parse a raw http/1.1 response into status + body; throws HttpError if malformed
HttpResponse parse_http_response(std::string_view raw);

// model A: holds config only, opens a fresh TlsConnection per request (Connection: close)
class HttpClient {
public:
    HttpClient(std::string_view host,
               std::string_view port,
               std::string_view ca_bundle = "");

    HttpResponse get(std::string_view path);
    HttpResponse post(std::string_view path, std::string_view body);

    // empty token = no Authorization header
    void set_bearer_token(std::string_view token);

private:
    HttpResponse request(std::string_view method,
                         std::string_view path,
                         std::string_view body);

    std::string host_;
    std::string port_;
    std::string ca_bundle_;
    std::string token_;
};
