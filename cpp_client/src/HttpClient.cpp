#include "HttpClient.hpp"
#include "TlsConnection.hpp"

#include <sstream>

HttpClient::HttpClient(std::string_view host,
                       std::string_view port,
                       std::string_view ca_bundle)
    : host_(host), port_(port), ca_bundle_(ca_bundle) {}

void HttpClient::set_bearer_token(std::string_view token) {
    token_ = token;
}

HttpResponse HttpClient::get(std::string_view path) {
    return request("GET", path, "");
}

HttpResponse HttpClient::post(std::string_view path, std::string_view body) {
    return request("POST", path, body);
}

HttpResponse HttpClient::request(std::string_view method,
                                 std::string_view path,
                                 std::string_view body) {
    TlsConnection conn(host_, port_, ca_bundle_);

    std::ostringstream req;
    req << method << " " << path << " HTTP/1.1\r\n"
        << "Host: " << host_ << "\r\n"
        << "User-Agent: eternal-blue/0.1\r\n"
        << "Accept: application/json\r\n"
        << "Connection: close\r\n";
    if (!token_.empty())
        req << "Authorization: Bearer " << token_ << "\r\n";
    if (!body.empty())
        req << "Content-Type: application/json\r\n"
            << "Content-Length: " << body.size() << "\r\n";
    req << "\r\n" << body;

    conn.write(req.str());
    std::string raw = conn.read_all();

    // split headers from body on the blank line
    auto sep = raw.find("\r\n\r\n");
    if (sep == std::string::npos)
        throw HttpError("malformed response: no header/body separator");

    // status line: "HTTP/1.1 <code> <reason>"
    auto sp1 = raw.find(' ');
    auto sp2 = raw.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos)
        throw HttpError("malformed status line");

    HttpResponse resp;
    resp.status_code = std::stoi(raw.substr(sp1 + 1, sp2 - sp1 - 1));
    resp.body = raw.substr(sep + 4);
    return resp;
}
