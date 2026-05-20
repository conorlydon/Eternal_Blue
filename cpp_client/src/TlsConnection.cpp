
#include "TlsConnection.hpp"

// System + OpenSSL headers the implementation needs (the header itself doesn't).
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <string>

namespace {

// Helper: drain OpenSSL's thread-local error queue and fold it into a single
// human-readable string, so the TlsError thrown carries the real reason.

    std::string ssl_error_string(const std::string& prefix){
        std::string out = prefix;
        unsigned long e;
        while ((e = ERR_get_error()) != 0) {
            char buf[256];
            ERR_error_string_n(e, buf, sizeof buf);
            out += "; openssl: ";
            out += buf;
        }
        return out;
    }


}  

void TlsConnection::cleanup() noexcept {
        if (ssl_)        { SSL_shutdown(ssl_); SSL_free(ssl_); ssl_ = nullptr; }
        if (fd_ != -1)   { close(fd_); fd_ = -1; }
        if (ctx_)        { SSL_CTX_free(ctx_); ctx_ = nullptr; }
}
// ---------------------------------------------------------------------------
// Constructor: connect + handshake + verify. Blocks until the connection is
// fully established and verified, or throws TlsError
// ---------------------------------------------------------------------------
TlsConnection::TlsConnection(std::string_view host,
                             std::string_view port,
                             std::string_view ca_bundle) {

    try{
        // resolve + connect to host:port and store the connected fd in fd_.
        struct addrinfo hints{};
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo* result = nullptr;
        int gai = getaddrinfo(std::string(host).c_str(), std::string(port).c_str(), &hints, &result);
        if (gai != 0)        throw TlsError(std::string("getaddrinfo: ") + gai_strerror(gai));
        int fd = -1;
        for (auto* rp = result; rp != nullptr; rp = rp->ai_next){
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0) continue;
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
            close(fd);
            fd = -1;
        }
        freeaddrinfo(result);
        if (fd == -1) throw TlsError("Failed to connect to " + std::string(host) + ":" + std::string(port));
        fd_ = fd;


        // SSL_CTX setup: new ctx, set min proto to TLS 1.2, load system CAs, optionally
        ctx_ = SSL_CTX_new(TLS_client_method());
        if (!ctx_) throw TlsError("SSL_CTX_new failed");
        if (SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION) != 1)
            throw TlsError("SSL_CTX_set_min_proto_version failed");
        if (SSL_CTX_set_default_verify_paths(ctx_) != 1)
            throw TlsError("SSL_CTX_set_default_verify_paths failed");
        if (!ca_bundle.empty()) {
            if (SSL_CTX_load_verify_locations(ctx_, std::string(ca_bundle).c_str(), nullptr) != 1)
                throw TlsError("SSL_CTX_load_verify_locations failed");
        }
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
        

        // SSL object, bind socket, SNI + hostname verify setup.
        ssl_ = SSL_new(ctx_);
        if (!ssl_) throw TlsError("SSL_new failed");
        if (SSL_set_fd(ssl_, fd_) != 1)
            throw TlsError("SSL_set_fd failed");
        if (SSL_set_tlsext_host_name(ssl_, std::string(host).c_str()) != 1)
            throw TlsError("SSL_set_tlsext_host_name failed");
        X509_VERIFY_PARAM* param = SSL_get0_param(ssl_);
        if (X509_VERIFY_PARAM_set1_host(param, std::string(host).c_str(), host.size()) != 1)
            throw TlsError("X509_VERIFY_PARAM_set1_host failed");

        
        // drive the handshake to completion. If it fails, or if verification fails, throw.
        if (SSL_connect(ssl_) != 1)
            throw TlsError(ssl_error_string("SSL_connect failed"));
        long vr = SSL_get_verify_result(ssl_);
        if (vr != X509_V_OK)
            throw TlsError(std::string("SSL_get_verify_result: ") +
                           X509_verify_cert_error_string(vr));
        
    }
    catch(...){
        cleanup();
        throw;  // rethrow the original exception after cleanup
    }
}


TlsConnection::~TlsConnection() {
    cleanup();
}

// loop on SSL_write until all data is written. On error, throw TlsError with the OpenSSL error string (ref ssl_error_string helper)
void TlsConnection::write(std::string_view data) {
    
    size_t total = 0;
    while (total < data.size()){
        int n = SSL_write(ssl_, data.data() + total, static_cast<int>(data.size() - total));
        if (n <= 0) {
            int err = SSL_get_error(ssl_, n);
            throw TlsError(ssl_error_string("SSL_write failed: code " + std::to_string(err)));
        }
        total += static_cast<size_t>(n);
    }
}

// read until the server cleanly closes the connection, accumulating the data into a string and returrning it.
std::string TlsConnection::read_all() {
    
    std::string out;
    char buf[4096];
    for (;;) {
        int n = SSL_read(ssl_, buf, sizeof buf);
        if (n > 0) {
            out.append(buf, static_cast<size_t>(n));
            continue;
        }
        int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_ZERO_RETURN) break;          // clean close_notify
        if (err == SSL_ERROR_SYSCALL && n == 0) break;    // TCP EOF without close_notify
        if (err == SSL_ERROR_WANT_READ ||
            err == SSL_ERROR_WANT_WRITE) continue;
        throw TlsError(ssl_error_string("SSL_read failed: code " + std::to_string(err)));
    }
    return out;
}
