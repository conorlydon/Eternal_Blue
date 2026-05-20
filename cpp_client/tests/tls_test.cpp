#include <doctest/doctest.h>
#include "HttpClient.hpp"

TEST_CASE("parse_http_response extracts status and body") {
    std::string raw =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "\r\n"
        "{\"status\":\"ok\"}";
    HttpResponse r = parse_http_response(raw);
    CHECK(r.status_code == 200);
    CHECK(r.body == "{\"status\":\"ok\"}");
}

TEST_CASE("parse_http_response reads a non-200 status") {
    HttpResponse r = parse_http_response("HTTP/1.1 404 Not Found\r\n\r\nnope");
    CHECK(r.status_code == 404);
    CHECK(r.body == "nope");
}

TEST_CASE("parse_http_response throws on missing separator") {
    CHECK_THROWS_AS(parse_http_response("HTTP/1.1 200 OK\r\n"), HttpError);
}
