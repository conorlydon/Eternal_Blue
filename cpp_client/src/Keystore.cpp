#include "Keystore.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <utility>
#include <vector>

namespace {

constexpr unsigned char kMagic[4] = {'E', 'B', 'K', 'S'};
constexpr unsigned char kVersion  = 1;

// magic + version + salt + nonce + ciphertext
constexpr size_t kFileSize =
    4 + 1 + crypto_pwhash_SALTBYTES
    + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    + (crypto_kx_SECRETKEYBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES);

}  // namespace

Keystore::Keystore(std::string path) : path_(std::move(path)) {}

bool Keystore::exists() const {
    struct stat st;
    return ::stat(path_.c_str(), &st) == 0;
}

void Keystore::save(const KeystoreData& data) {
    std::vector<unsigned char> buf;
    buf.reserve(kFileSize);
    buf.insert(buf.end(), kMagic, kMagic + 4);
    buf.push_back(kVersion);
    buf.insert(buf.end(), data.salt.begin(), data.salt.end());
    buf.insert(buf.end(), data.wrapped.nonce.begin(), data.wrapped.nonce.end());
    buf.insert(buf.end(), data.wrapped.ciphertext.begin(), data.wrapped.ciphertext.end());

    // make sure the parent dir exists (0700 — private)
    auto slash = path_.find_last_of('/');
    if (slash != std::string::npos && slash != 0)
        ::mkdir(path_.substr(0, slash).c_str(), 0700);   // ignore EEXIST

    int fd = ::open(path_.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0)
        throw KeystoreError("cannot open keystore for writing: " + path_);

    size_t off = 0;
    while (off < buf.size()) {
        ssize_t n = ::write(fd, buf.data() + off, buf.size() - off);
        if (n < 0) { ::close(fd); throw KeystoreError("write to keystore failed"); }
        off += static_cast<size_t>(n);
    }
    ::close(fd);
}

KeystoreData Keystore::load() {
    int fd = ::open(path_.c_str(), O_RDONLY);
    if (fd < 0)
        throw KeystoreError("keystore not found: " + path_);

    std::array<unsigned char, kFileSize> buf{};
    size_t off = 0;
    while (off < buf.size()) {
        ssize_t n = ::read(fd, buf.data() + off, buf.size() - off);
        if (n < 0) { ::close(fd); throw KeystoreError("read from keystore failed"); }
        if (n == 0) break;   // EOF
        off += static_cast<size_t>(n);
    }
    ::close(fd);

    if (off != kFileSize)               throw KeystoreError("keystore wrong size (corrupt?)");
    if (std::memcmp(buf.data(), kMagic, 4) != 0) throw KeystoreError("bad keystore magic");
    if (buf[4] != kVersion)             throw KeystoreError("unsupported keystore version");

    KeystoreData data{};
    size_t p = 5;
    std::memcpy(data.salt.data(),              buf.data() + p, data.salt.size());
    p += data.salt.size();
    std::memcpy(data.wrapped.nonce.data(),     buf.data() + p, data.wrapped.nonce.size());
    p += data.wrapped.nonce.size();
    std::memcpy(data.wrapped.ciphertext.data(), buf.data() + p, data.wrapped.ciphertext.size());
    return data;
}
