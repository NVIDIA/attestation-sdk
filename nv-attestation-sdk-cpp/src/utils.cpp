#include "nv_attestation/utils.h"
#include "nv_attestation/log.h"
#include "nv_attestation/nv_types.h"
#include "nv_attestation/error.h"

#include <openssl/evp.h>

namespace nvattestation {
Error compute_sha256_hex(const std::string& data, std::string& out_hex) {
    nv_unique_ptr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
    if (!ctx) {
        LOG_ERROR("EVP_MD_CTX_new failed: " << get_openssl_error());
        return Error::InternalError;
    }
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        LOG_ERROR("EVP_DigestInit_ex failed: " << get_openssl_error());
        return Error::InternalError;
    }
    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) {
        LOG_ERROR("EVP_DigestUpdate failed: " << get_openssl_error());
        return Error::InternalError;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest, &digest_len) != 1) {
        LOG_ERROR("EVP_DigestFinal_ex failed: " << get_openssl_error());
        return Error::InternalError;
    }
    std::vector<uint8_t> digest_vec(digest, digest + digest_len);
    out_hex = to_hex_string(digest_vec);
    return Error::Ok;
}

} // namespace nvattestation