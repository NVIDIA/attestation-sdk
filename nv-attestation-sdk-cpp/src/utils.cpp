#include "nv_attestation/utils.h"
#include "nv_attestation/log.h"
#include "nv_attestation/nv_types.h"
#include "nv_attestation/error.h"

#include <openssl/evp.h>

namespace nvattestation {

Error evp_md_for_hash_algorithm(HashAlgorithm alg, const EVP_MD*& out_md) {
    switch (alg) {
        case HashAlgorithm::Sha256: out_md = EVP_sha256(); return Error::Ok;
        case HashAlgorithm::Sha384: out_md = EVP_sha384(); return Error::Ok;
        case HashAlgorithm::Sha512: out_md = EVP_sha512(); return Error::Ok;
    }
    out_md = nullptr;
    return Error::BadArgument;
}

const char* to_algorithm_name(HashAlgorithm alg) {
    switch (alg) {
        case HashAlgorithm::Sha256: return "sha-256";
        case HashAlgorithm::Sha384: return "sha-384";
        case HashAlgorithm::Sha512: return "sha-512";
    }
    return "sha-256";
}

namespace {
// IANA Named Information hash algorithm registry IDs.
constexpr int32_t kNiHashSha256 = 1;
constexpr int32_t kNiHashSha384 = 7;
constexpr int32_t kNiHashSha512 = 8;
// Digest lengths in bytes.
constexpr std::size_t kSha256DigestBytes = 32;
constexpr std::size_t kSha384DigestBytes = 48;
constexpr std::size_t kSha512DigestBytes = 64;
} // namespace

int32_t to_ni_algorithm_id(HashAlgorithm alg) {
    switch (alg) {
        case HashAlgorithm::Sha256: return kNiHashSha256;
        case HashAlgorithm::Sha384: return kNiHashSha384;
        case HashAlgorithm::Sha512: return kNiHashSha512;
    }
    return kNiHashSha256;
}

Error hash_algorithm_from_ni_id(int32_t ni_id, HashAlgorithm& out_alg) {
    if (ni_id == kNiHashSha256) { out_alg = HashAlgorithm::Sha256; return Error::Ok; }
    if (ni_id == kNiHashSha384) { out_alg = HashAlgorithm::Sha384; return Error::Ok; }
    if (ni_id == kNiHashSha512) { out_alg = HashAlgorithm::Sha512; return Error::Ok; }
    return Error::BadArgument;
}

Error hash_algorithm_from_name(const std::string& name, HashAlgorithm& out_alg) {
    for (HashAlgorithm alg : {HashAlgorithm::Sha256, HashAlgorithm::Sha384,
                              HashAlgorithm::Sha512}) {
        if (name == to_algorithm_name(alg)) {
            out_alg = alg;
            return Error::Ok;
        }
    }
    return Error::BadArgument;
}

Error hash_algorithm_from_digest_size(std::size_t size, HashAlgorithm& out_alg) {
    switch (size) {
        case kSha256DigestBytes: out_alg = HashAlgorithm::Sha256; return Error::Ok;
        case kSha384DigestBytes: out_alg = HashAlgorithm::Sha384; return Error::Ok;
        case kSha512DigestBytes: out_alg = HashAlgorithm::Sha512; return Error::Ok;
        default: return Error::BadArgument;
    }
}

Error compute_digest(const std::vector<uint8_t>& data,
                     HashAlgorithm alg,
                     std::vector<uint8_t>& out_bytes) {
    const EVP_MD* md = nullptr;
    Error error = evp_md_for_hash_algorithm(alg, md);
    if (error != Error::Ok) {
        return error;
    }
    nv_unique_ptr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
    if (!ctx) {
        LOG_ERROR("EVP_MD_CTX_new failed: " << get_openssl_error());
        return Error::InternalError;
    }
    if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
        LOG_ERROR("EVP_DigestInit_ex failed: " << get_openssl_error());
        return Error::InternalError;
    }
    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) {
        LOG_ERROR("EVP_DigestUpdate failed: " << get_openssl_error());
        return Error::InternalError;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len{0};
    if (EVP_DigestFinal_ex(ctx.get(), digest, &digest_len) != 1) {
        LOG_ERROR("EVP_DigestFinal_ex failed: " << get_openssl_error());
        return Error::InternalError;
    }
    out_bytes.assign(digest, digest + digest_len);
    return Error::Ok;
}

Error compute_sha256_hex(const std::string& data, std::string& out_hex) {
    std::vector<uint8_t> input(data.begin(), data.end());
    std::vector<uint8_t> digest_bytes;
    Error err = compute_digest(input, HashAlgorithm::Sha256, digest_bytes);
    if (err != Error::Ok) {
        return err;
    }
    out_hex = to_hex_string(digest_bytes);
    return Error::Ok;
}

Error require_https_and_normalize(const std::string& url, std::string& out_normalized) {
    std::string normalized = url;
    while (!normalized.empty() && normalized.back() == '/') {
        normalized.pop_back();
    }
    if (!starts_with(normalized, "https://")) {
        LOG_ERROR("URL must use https: " << url);
        return Error::BadArgument;
    }
    out_normalized = normalized;
    return Error::Ok;
}

} // namespace nvattestation
