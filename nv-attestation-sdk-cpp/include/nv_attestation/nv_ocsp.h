/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <vector>
#include <string>
#include <memory>
#include <utility>
#include <time.h>
#include <openssl/bio.h>
#include <openssl/conf.h>

#include "nv_types.h"
#include "nv_attestation/error.h"
#include "nv_attestation/verify.h"
#include "nv_attestation/nv_http.h"
#include "nv_attestation/nv_cache.h"

namespace nvattestation {


struct NvOcspResponse {
    time_t thisupd;
    time_t nextupd;
    // Set only when status is revoked; 0 otherwise.
    time_t revtime = 0;
    // When the responder signed this response (OCSP producedAt); distinct
    // from thisupd, which is when the status itself was last known correct.
    time_t producedat = 0;
    int reason;
    int status;
    bool nonce_matches;
    bool response_valid;
    // No request was made (AIA responder lookup on, cert carries no AIA
    // responder). The other fields are unset and must be ignored.
    bool skipped = false;
};

enum class OcspCertIdHashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
};

struct OcspClientOptions {
    OcspCertIdHashAlgorithm cert_id_hash_algorithm =
        OcspCertIdHashAlgorithm::Sha256;
};

Error ocsp_cert_id_hash_algorithm_from_name(
    const std::string& name,
    OcspCertIdHashAlgorithm& out_algorithm
);

/**
 * @brief Interface for an OCSP HTTP client.
 * This allows for mocking the HTTP transfer part of OCSP requests during testing.
 */
class IOcspHttpClient {
protected:
    IOcspHttpClient() = default;
public:
    virtual ~IOcspHttpClient() = default;


    /**
     * @brief Performs the HTTP transfer for an OCSP request with retry logic and response processing.
     *
     * @param req_bio The BIO containing the serialized OCSP request.
     * @param out_ocsp_resp Output parameter for the successfully parsed OCSP response.
     * @return Error code indicating the result of the operation.
     */
    virtual Error get_ocsp_response(
        const nv_unique_ptr<X509>& subject_cert,
        const nv_unique_ptr<X509>& issuer_cert,
        const nv_unique_ptr<stack_st_X509>& intermediates,
        const nv_unique_ptr<X509_STORE>& trust_store,
        NvOcspResponse& out_ocsp_response
    ) = 0;


};

/**
 * @brief NvHttpClient-based implementation of IOcspHttpClient.
 * This implementation uses NvHttpClient for OCSP requests with direct request/response parsing.
 */
class NvHttpOcspClient : public IOcspHttpClient {
public:
    NvHttpOcspClient() = default;
    static constexpr const char* DEFAULT_BASE_URL = "https://ocsp.ndis.nvidia.com";
    static constexpr time_t DEFAULT_NEXT_UPDATE_TTL_SECONDS = 3600;

    Error get_ocsp_response(
        const nv_unique_ptr<X509>& subject_cert,
        const nv_unique_ptr<X509>& issuer_cert,
        const nv_unique_ptr<stack_st_X509>& intermediates,
        const nv_unique_ptr<X509_STORE>& trust_store,
        NvOcspResponse& out_ocsp_response
    ) override;

    static Error create(
        NvHttpOcspClient& out_client,
        const std::string& base_url,
        const std::string& service_key,
        const HttpOptions& http_options
    );

    static Error create(
        NvHttpOcspClient& out_client,
        const std::string& base_url,
        const std::string& service_key,
        const HttpOptions& http_options,
        const OcspClientOptions& options
    );

    /**
     * @brief Creates an NvHttpOcspClient instance.
     *
     * @param out_client Output parameter for the created client
     * @param ocsp_url The OCSP server URL
     * @param http_options HTTP options for the client
     * @return Error::Ok on success, error code on failure
     */
    static Error init_from_env(
        NvHttpOcspClient& out_client,
        const char * base_url,
        const std::string& service_key,
        const HttpOptions& http_options
    );

    static Error init_from_env(
        NvHttpOcspClient& out_client,
        const char * base_url,
        const std::string& service_key,
        const HttpOptions& http_options,
        const OcspClientOptions& options
    );

    OcspCertIdHashAlgorithm cert_id_hash_algorithm() const {
        return m_options.cert_id_hash_algorithm;
    }

    // When enabled, the responder URL is taken from each subject cert's
    // Authority Information Access extension instead of the configured base
    // URL; a cert with no AIA responder is skipped (no request) rather than
    // falling back to the base URL. Default disabled (legacy behavior: always
    // use the base URL).
    void set_use_cert_aia_responder(bool enabled) {
        m_use_cert_aia_responder = enabled;
    }

    // Append a prefix-substitution rule applied to the responder URL before
    // the request (e.g. upgrade http:// to https://, or redirect to an
    // alternate responder, such as Trust Outpost). Rules are tried in
    // insertion order; first match wins.
    // Only applicable when m_use_cert_aia_reponder is true.
    Error add_url_rewrite(std::string pattern, std::string replacement);

    // First OCSP responder URL in the cert's AIA extension, or "" if none.
    static std::string first_ocsp_responder_url(X509* cert);

    // Determine the effective OCSP responder URL for subject_cert, honoring
    // set_use_cert_aia_responder() and configured URL rewrites. Returns the
    // base URL when AIA lookup is disabled; when it is enabled, returns the
    // cert's (rewritten) AIA responder URL, or "" if the cert has none.
    std::string select_request_url(X509* subject_cert) const;

    // Apply prefix-substitution rules to url; first match wins.
    static std::string apply_url_rewrites(
        const std::vector<std::pair<std::string, std::string>>& rules,
        const std::string& url);

private:
    HttpOptions m_http_options;
    std::string m_ocsp_default_url;
    NvHttpClient m_http_client;
    OcspClientOptions m_options;
    bool m_use_cert_aia_responder = false;
    std::vector<std::pair<std::string, std::string>> m_url_rewrites;

    static Error create_cert_id(
        OcspCertIdHashAlgorithm algorithm,
        X509* subject_cert,
        X509* issuer_cert,
        nv_unique_ptr<OCSP_CERTID>& out_id
    );

    Error build_request(
        X509* subject_cert,
        X509* issuer_cert,
        nv_unique_ptr<OCSP_REQUEST>& out_request,
        nv_unique_ptr<OCSP_CERTID>& out_response_lookup_id
    ) const;

    static Error get_ocsp_response_from_raw(
        const std::string& ocsp_response_raw,
        nv_unique_ptr<OCSP_BASICRESP>& out_ocsp_response
    );

    static Error validate_ocsp_response(
        nv_unique_ptr<OCSP_REQUEST>& ocsp_req,
        nv_unique_ptr<OCSP_BASICRESP>& basic_resp,
        const nv_unique_ptr<stack_st_X509>& intermediates,
        const nv_unique_ptr<X509_STORE>& trust_store
    );

    static Error get_ocsp_status(
        nv_unique_ptr<OCSP_BASICRESP>& basic_resp,
        nv_unique_ptr<OCSP_CERTID>& id,
        NvOcspResponse& out_ocsp_response
    );

    // Grants the get_ocsp_status unit tests direct access, so timestamp
    // parsing can be exercised without a live/mocked OCSP HTTP round trip.
    friend class NvHttpOcspClientStatusTest_GoodStatusAllFieldsPresent_Test;
    friend class NvHttpOcspClientStatusTest_RevokedStatusIncludesRevocationTime_Test;
    friend class NvHttpOcspClientStatusTest_MissingNextUpdateUsesDefaultTtl_Test;
    friend class NvHttpOcspClientHashTest_ConfiguredAlgorithmsBuildExpectedCertIds_Test;
    friend class NvHttpOcspCacheClient;

};

class NvHttpOcspCacheClient: public IOcspHttpClient {
public:
    NvHttpOcspCacheClient() = default;

    Error get_ocsp_response(
        const nv_unique_ptr<X509>& subject_cert,
        const nv_unique_ptr<X509>& issuer_cert,
        const nv_unique_ptr<stack_st_X509>& intermediates,
        const nv_unique_ptr<X509_STORE>& trust_store,
        NvOcspResponse& out_ocsp_response
    ) override;

    static Error create(
        std::shared_ptr<IOcspHttpClient>& inner_client,
        uint64_t max_size_bytes,
        time_t ttl_seconds,
        std::shared_ptr<IOcspHttpClient>& out_client
    );

    private:
    friend class NvHttpOcspCacheClientTest_CacheKeyUsesFixedSha256_Test;

    std::shared_ptr<IOcspHttpClient> m_inner_client;
    std::shared_ptr<INvCache> m_cache;

    /*
        approx size of one cache entry = key length + size of NvOcspResponse
        size of NvOcspResponse = approx 20 bytes
    */
    static constexpr const uint64_t NV_OCSP_RESPONSE_SIZE_BYTES = 20;

    static Error get_cache_key(
        const nv_unique_ptr<X509>& subject_cert,
        const nv_unique_ptr<X509>& issuer_cert,
        std::string& out_cache_key
    );

};
}
