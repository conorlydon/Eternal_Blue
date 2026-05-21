#pragma once
#include <string>
#include <string_view>
#include <vector>

// base64url, no padding — wire encoding for binary fields
std::string to_base64url(const unsigned char* data, size_t len);
std::vector<unsigned char> from_base64url(std::string_view text);   // throws on malformed input
