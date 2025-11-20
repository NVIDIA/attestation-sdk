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
    int reason;
    int status;
    bool nonce_matches;
};

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

private:
    HttpOptions m_http_options;
    std::string m_ocsp_url;
    NvHttpClient m_http_client;


    static Error get_ocsp_response_from_raw(
        const std::string& ocsp_response_raw,
        nv_unique_ptr<OCSP_BASICRESP>& out_ocsp_response
    );

    static Error validate_ocsp_response(
        nv_unique_ptr<OCSP_REQUEST>& ocsp_req,
        nv_unique_ptr<OCSP_BASICRESP>& basic_resp,
        const nv_unique_ptr<stack_st_X509>& intermediates,
        const nv_unique_ptr<X509_STORE>& trust_store,
        bool& nonce_matches
    );

    static Error get_nv_ocsp_response(
        nv_unique_ptr<OCSP_BASICRESP>& basic_resp,
        nv_unique_ptr<OCSP_CERTID>& id,
        NvOcspResponse& out_ocsp_response
    );
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