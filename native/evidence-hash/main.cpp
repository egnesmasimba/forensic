// Stream a SHA-256 for comparison with Attachment.sha256. Evidence is opened read-only.
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif
#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

class Digest {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
public:
    ~Digest() { if (hash) BCryptDestroyHash(hash); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); }
    bool init() { return BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 && BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0; }
    bool update(const char *data, size_t size) { return BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char *>(data)), static_cast<ULONG>(size), 0) >= 0; }
    bool finish(unsigned char *out) { return BCryptFinishHash(hash, out, 32, 0) >= 0; }
#else
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
public:
    bool init() { return ctx && EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) == 1; }
    bool update(const char *data, size_t size) { return EVP_DigestUpdate(ctx.get(), data, size) == 1; }
    bool finish(unsigned char *out) { unsigned int length = 0; return EVP_DigestFinal_ex(ctx.get(), out, &length) == 1 && length == 32; }
#endif
};

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) {
        std::cerr << "usage: evidence-hash FILE [EXPECTED_SHA256]\n"; return 2;
    }
    std::string expected = argc == 3 ? argv[2] : "";
    if (argc == 3) {
        if (expected.size() != 64 || expected.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
            std::cerr << "expected digest must be 64 hexadecimal characters\n"; return 2;
        }
        for (char &c : expected) if (c >= 'A' && c <= 'F') c += 'a' - 'A';
    }
    std::ifstream file(argv[1], std::ios::binary);
    if (!file) { std::cerr << "cannot read evidence file\n"; return 1; }
    Digest hash;
    if (!hash.init()) return 1;
    std::array<char, 65536> block{};
    while (file) {
        file.read(block.data(), block.size());
        if (!hash.update(block.data(), static_cast<size_t>(file.gcount()))) return 1;
    }
    if (!file.eof() || file.bad()) { std::cerr << "evidence read failed\n"; return 1; }
    unsigned char digest[32];
    if (!hash.finish(digest)) return 1;
    std::ostringstream hex;
    for (unsigned int i=0; i<32; ++i) hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(digest[i]);
    std::cout << hex.str() << '\n';
    if (argc == 3 && hex.str() != expected) { std::cerr << "digest mismatch\n"; return 1; }
    return 0;
}
