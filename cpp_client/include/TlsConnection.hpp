#pragma once
#include <string>
#include <string_view>
#include <openssl/ssl.h>
#include <stdexcept>

class TlsError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
        
};


class TlsConnection {
    public:
        TlsConnection(std::string_view host, std::string_view port, std::string_view ca_bundle = "");
        ~TlsConnection();

        TlsConnection(const TlsConnection&) = delete;
        TlsConnection& operator=(const TlsConnection&) = delete;
        TlsConnection(TlsConnection&&) = delete;
        TlsConnection& operator=(TlsConnection&&) = delete;

        void write(std::string_view data);
        std::string read_all();

    private:
        int fd_ = -1;
        SSL_CTX* ctx_ = nullptr;
        SSL* ssl_ = nullptr;
        void cleanup() noexcept;
};
