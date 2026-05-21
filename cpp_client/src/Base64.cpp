#include "Base64.hpp"

#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace {
constexpr int kVariant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
}

std::string to_base64url(const unsigned char* data, size_t len) {
    const size_t cap = sodium_base64_ENCODED_LEN(len, kVariant);   // includes '\0' slot
    std::string out(cap, '\0');
    sodium_bin2base64(out.data(), cap, data, len, kVariant);
    out.resize(std::strlen(out.c_str()));   // trim the trailing '\0' slot
    return out;
}

std::vector<unsigned char> from_base64url(std::string_view text) {
    std::vector<unsigned char> out(text.size());   // decoded is always <= input
    size_t out_len = 0;
    if (sodium_base642bin(out.data(), out.size(),
                          text.data(), text.size(),
                          nullptr, &out_len, nullptr, kVariant) != 0)
        throw std::runtime_error("from_base64url: invalid base64url input");
    out.resize(out_len);
    return out;
}
