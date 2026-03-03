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

#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/nv_cache.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/log.h"
#include "nv_attestation/error.h"
#include "internal/debug.hpp"


namespace nvattestation {

Error NvHttpOcspClient::get_ocsp_response_from_raw(
    const std::string& ocsp_response_raw,
    nv_unique_ptr<OCSP_BASICRESP>& out_ocsp_resp
) {
    // Create a memory BIO from the response data
    nv_unique_ptr<BIO> resp_bio(BIO_new_mem_buf(ocsp_response_raw.data(), static_cast<int>(ocsp_response_raw.size())));
    if (!resp_bio) {
        LOG_ERROR("Failed to create BIO from OCSP response data: " << get_openssl_error());
        return Error::InternalError;
    }

    // Parse the response using OpenSSL
    nv_unique_ptr<OCSP_RESPONSE> ocsp_resp(d2i_OCSP_RESPONSE_bio(resp_bio.get(), nullptr));
    if (!ocsp_resp) {
        LOG_ERROR("Failed to parse OCSP response: " << get_openssl_error());
        return Error::OcspInvalidResponse;
    }

    // Check response status BEFORE moving the pointer
    int response_status_val = OCSP_response_status(ocsp_resp.get());
    switch (response_status_val) {
        case OCSP_RESPONSE_STATUS_SUCCESSFUL:
        {
            // Extract the basic response
            nv_unique_ptr<OCSP_BASICRESP> basic_resp(OCSP_response_get1_basic(ocsp_resp.get()));
            if (!basic_resp) {
                LOG_ERROR("Could not extract basic response from OCSP response: " << get_openssl_error());
                return Error::OcspInvalidResponse;
            }
            out_ocsp_resp = std::move(basic_resp);
            LOG_DEBUG("OCSP request successful");
            return Error::Ok;
        }
        case OCSP_RESPONSE_STATUS_INTERNALERROR:
        case OCSP_RESPONSE_STATUS_TRYLATER:
            LOG_ERROR("OCSP responder returned server error (status: " << response_status_val
                      << " - " << OCSP_response_status_str(response_status_val) << ").");
            return Error::OcspServerError;
        case OCSP_RESPONSE_STATUS_MALFORMEDREQUEST:
        case OCSP_RESPONSE_STATUS_SIGREQUIRED:
        case OCSP_RESPONSE_STATUS_UNAUTHORIZED:
        {
            std::string status_str = OCSP_response_status_str(response_status_val);
            LOG_ERROR("OCSP request failed due to client-side issue. Status: "
                      << response_status_val << " (" << status_str << ")");
            return Error::OcspInvalidRequest;
        }
        default:
        {
            std::string status_str = OCSP_response_status_str(response_status_val);
            LOG_ERROR("OCSP responder indicated a non-retryable error. Status: "
                      << response_status_val << " (" << status_str << ")");
            return Error::OcspInvalidResponse;
        }
    }
    return Error::Ok;
}

Error NvHttpOcspClient::get_ocsp_response(
    const nv_unique_ptr<X509>& subject_cert,
    const nv_unique_ptr<X509>& issuer_cert,
    const nv_unique_ptr<stack_st_X509>& intermediates,
    const nv_unique_ptr<X509_STORE>& trust_store,
    NvOcspResponse& out_ocsp_response
) {
    nv_unique_ptr<OCSP_REQUEST> ocsp_req(OCSP_REQUEST_new());
    if (OCSP_request_add1_nonce(ocsp_req.get(), nullptr, -1) != 1) {
        LOG_ERROR("Unable to add nonce to ocsp request");
        return Error::InternalError;
    }
    // Create the original Cert ID
    nv_unique_ptr<OCSP_CERTID> id_orig (OCSP_cert_to_id(EVP_sha1(), subject_cert.get(), issuer_cert.get()));
    if (!id_orig) {
            LOG_ERROR("Unable to create OCSP_CERTID: " << get_openssl_error());
            return Error::InternalError;
    }
    // Duplicate the Cert ID for the request
    // We duplicate the ID because OCSP_request_add0_id takes ownership of the ID
    // The original ID is used by the caller to get ocsp status of the cert
    // from the ocsp response
    OCSP_CERTID *id_for_req = OCSP_CERTID_dup(id_orig.get());
    if (id_for_req == nullptr) {
        LOG_ERROR("Unable to duplicate OCSP_CERTID: " << get_openssl_error());
        return Error::InternalError;
    }

    // Add the duplicated ID to the request (OCSP_request_add0_id takes ownership of id_for_req)
    if (OCSP_request_add0_id(ocsp_req.get(), id_for_req) == nullptr) {
            // If adding fails, we need to free the duplicated ID manually
            OCSP_CERTID_free(id_for_req);
            LOG_ERROR("Unable to add subject to ocsp request");
            return Error::InternalError;
    }

    // Serialize the OCSP request to a memory BIO
    nv_unique_ptr<BIO> req_bio(BIO_new(BIO_s_mem()));
    if (!req_bio) {
        LOG_ERROR("Unable to create memory BIO for OCSP request: " << get_openssl_error());
        return Error::InternalError;
    }
    if (!i2d_OCSP_REQUEST_bio(req_bio.get(), ocsp_req.get())) {
        LOG_ERROR("Unable to serialize OCSP request to BIO: " << get_openssl_error());
        return Error::InternalError;
    }
    // Get serialized OCSP request data from the BIO
    const unsigned char *req_data_ptr = nullptr;
    long req_data_len_l = BIO_get_mem_data(req_bio.get(), &req_data_ptr);
    if (req_data_len_l <= 0 || req_data_ptr == nullptr) {
        LOG_ERROR("Unable to get serialized OCSP request data from BIO (length=" << req_data_len_l << "): " << get_openssl_error());
        return Error::InternalError;
    }
    int req_data_len = static_cast<int>(req_data_len_l);
    if (req_data_len < 0) { // Downcast and check for overflow
        LOG_ERROR("Serialized OCSP request length is too large: encountered integer overflow " << req_data_len_l);
        return Error::InternalError;
    }

    // Create the request payload as a string
    std::string request_payload(reinterpret_cast<const char*>(req_data_ptr), req_data_len);

    // Create HTTP request
    NvRequest request(
        m_ocsp_url,
        NvHttpMethod::HTTP_METHOD_POST,
        {{"Content-Type", "application/ocsp-request"},
        {"Accept", "application/ocsp-response"},
        {"User-Agent", "nv-attestation-sdk/" NVAT_VERSION_STRING}},
        request_payload
    );

    // Perform HTTP request
    long http_status = 0;
    std::string response_body;
    Error error = m_http_client.do_request_as_string(request, http_status, response_body);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to perform OCSP check with url: " << m_ocsp_url);
        return error;
    }

    // Check HTTP status
    if (http_status != HTTP_STATUS_OK) {
        LOG_ERROR("OCSP server returned HTTP status: " << http_status);
        if (http_status == HTTP_STATUS_FORBIDDEN || http_status == HTTP_STATUS_UNAUTHORIZED) {
            return Error::OcspForbidden;
        }
        return Error::OcspServerError;
    }

    // Parse the response into OCSP_RESPONSE
    if (response_body.empty()) {
        LOG_ERROR("Empty OCSP response received");
        return Error::OcspInvalidResponse;
    }

    nv_unique_ptr<OCSP_BASICRESP> openssl_ocsp_resp;
    error = get_ocsp_response_from_raw(response_body, openssl_ocsp_resp);
    if (error != Error::Ok) {
        return error;
    }

    error = validate_ocsp_response(
        ocsp_req,
        openssl_ocsp_resp,
        intermediates,
        trust_store
    );
    if (error == Error::Ok) {
        out_ocsp_response.response_valid = true;
    } else if (error == Error::OcspInvalidResponse) {
        out_ocsp_response.response_valid = false;
    } else {
        return error;
    }

    // see here for information about return values of the check nonce function:  https://docs.openssl.org/1.1.1/man3/OCSP_check_nonce.html
    int result = OCSP_check_nonce(ocsp_req.get(), openssl_ocsp_resp.get());
    LOG_DEBUG("OCSP_check_nonce returned: " << result);
    out_ocsp_response.nonce_matches = result == 1;

    return get_ocsp_status(openssl_ocsp_resp, id_orig, out_ocsp_response);
}

Error NvHttpOcspClient::validate_ocsp_response(
    nv_unique_ptr<OCSP_REQUEST>& ocsp_req,
    nv_unique_ptr<OCSP_BASICRESP>& basic_resp,
    const nv_unique_ptr<stack_st_X509>& intermediates,
    const nv_unique_ptr<X509_STORE>& trust_store
) {


    // --- BEGIN DEBUG PRINTS ---
    if (get_logger()->should_log(LogLevel::DEBUG, __FILE__, __FUNCTION__, __LINE__)) {
        // Print Signer (Responder) Cert Info
        X509* signer_cert = nullptr;
        // Note: Using sk_X509_num(NULL) returns -1, which is fine for sk_X509_value which checks >= 0
        if (OCSP_resp_get0_signer(basic_resp.get(), &signer_cert, nullptr) != 0 && signer_cert != nullptr) {
            LOG_TRACE("Responder Cert Info: " << get_cert_subject_issuer_str(signer_cert));
        } else {
            LOG_TRACE("Could not retrieve responder certificate from OCSP response.");
        }
        LOG_TRACE("Intermediate Certs Provided for OCSP_basic_verify (" << sk_X509_num(intermediates.get()) << "):");
        for (int i = 0; i < sk_X509_num(intermediates.get()); ++i) {
            X509 *inter_cert = sk_X509_value(intermediates.get(), i);
            if (inter_cert != nullptr) {
                LOG_DEBUG("  Intermediate Cert [" << i << "]: " << get_cert_subject_issuer_str(inter_cert));
            }
        }
        // Print Trust Store Certs Info
        LOG_TRACE("Trust Store Certs:");
        STACK_OF(X509_OBJECT) *store_objs = X509_STORE_get0_objects(trust_store.get());
        for (int i = 0; i < sk_X509_OBJECT_num(store_objs); ++i) {
            X509_OBJECT *obj = sk_X509_OBJECT_value(store_objs, i);
            if (X509_OBJECT_get_type(obj) == X509_LU_X509) {
                X509 *trust_cert = X509_OBJECT_get0_X509(obj);
                if (trust_cert != nullptr) {
                    LOG_TRACE("  Trust Anchor [" << i << "]: " << get_cert_subject_issuer_str(trust_cert));
                }
            }
        }
        LOG_TRACE("--- End OCSP Verification Debug Info ---");
    }
    // --- END DEBUG PRINTS ---

    // Verify the OCSP response signature and trust
    int verification_status = OCSP_basic_verify(basic_resp.get(), intermediates.get(), trust_store.get(), 0);

    if(verification_status != 1) {
        if (verification_status == 0) {
            // verification_status == 0 means verification failure (e.g., signature mismatch, untrusted signer)
            std::string err_msg = "OCSP response verification failed. OpenSSL errors: " + get_openssl_error();
            LOG_ERROR(err_msg);
            return Error::OcspInvalidResponse;
        }
        // verification_status < 0 means some other error occurred during verification (e.g., memory allocation)
        LOG_ERROR("OCSP basic verification encountered an internal error with status: "
                << verification_status << ". OpenSSL errors: " << get_openssl_error());
        return Error::InternalError;
    }

    LOG_DEBUG("OCSP basic verification successful");


    return Error::Ok;
}

Error NvHttpOcspClient::get_ocsp_status(
    nv_unique_ptr<OCSP_BASICRESP>& basic_resp,
    nv_unique_ptr<OCSP_CERTID>& id,
    NvOcspResponse& out_ocsp_response
) {
        /**
         * do not free these thisupd and nextupd pointers as they are internal pointers of OCSP_BASICRESP
         * and will be freed when OCSP_BASICRESP is freed
        */
        ASN1_GENERALIZEDTIME *thisupd = nullptr;
        ASN1_GENERALIZEDTIME *nextupd = nullptr;
        int reason = -1;
        int status = -1;
        // Use the original Cert ID (managed by id_orig) to find the status
        int result = OCSP_resp_find_status(basic_resp.get(), id.get(), &status, &reason,
                              nullptr, &thisupd, &nextupd);
        if(result != 1) {
            LOG_DEBUG("OCSP basic response is not present for subject index ");
            return Error::OcspInvalidResponse;
        }

        // note: timegm only works on linux.
        struct tm this_update_tm{};
        if (ASN1_TIME_to_tm((const ASN1_TIME *)thisupd, &this_update_tm) != 1) {
            LOG_ERROR("Unable to convert ASN1_TIME to tm: " << get_openssl_error());
            return Error::InternalError;
        }

        time_t this_update_time = timegm(&this_update_tm);
        LOG_DEBUG("ASN1_TIME_to_tm successful for this update time: " << this_update_time);
        out_ocsp_response.thisupd = this_update_time;

        LOG_DEBUG("Generating expiration time claim");
        if (nextupd == nullptr) {
            LOG_DEBUG("nextUpdate is absent in OCSP response, using default TTL");
            out_ocsp_response.nextupd = this_update_time + NvHttpOcspClient::DEFAULT_NEXT_UPDATE_TTL_SECONDS;
            LOG_DEBUG("Using default nextUpdate time: " << out_ocsp_response.nextupd);
        } else {
            struct tm next_update_tm{};
            if (ASN1_TIME_to_tm((const ASN1_TIME *)nextupd, &next_update_tm) != 1) {
                LOG_ERROR("Unable to convert ASN1_TIME to tm: " << get_openssl_error());
                return Error::InternalError;
            }

            time_t next_update_time = timegm(&next_update_tm);
            LOG_DEBUG("ASN1_TIME_to_tm successful for next update time: " << next_update_time);
            out_ocsp_response.nextupd = next_update_time;
        }

        out_ocsp_response.status = status;
        out_ocsp_response.reason = reason;

        return Error::Ok;
}

Error NvHttpOcspClient::create(
    NvHttpOcspClient& out_client,
    const std::string& base_url,
    const std::string& service_key,
    const HttpOptions& http_options) {
    out_client.m_http_options = http_options;
    out_client.m_ocsp_url = base_url;
    Error error = NvHttpClient::create(out_client.m_http_client, service_key, http_options);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to create HTTP client for OCSP request");
        return error;
    }
    return Error::Ok;
}

Error NvHttpOcspClient::init_from_env(
    NvHttpOcspClient& out_client,
    const char* base_url,
    const std::string& service_key,
    const HttpOptions& http_options) {
    std::string base_uri_str;
    if (base_url == nullptr || *base_url == '\0') {
        base_uri_str = get_env_or_default("NVAT_OCSP_BASE_URL", DEFAULT_BASE_URL);
    } else {
        base_uri_str = std::string(base_url);
    }

    return create(out_client, base_uri_str, service_key, http_options);
}

Error NvHttpOcspCacheClient::create(
    std::shared_ptr<IOcspHttpClient>& inner_client,
    uint64_t max_size_bytes,
    time_t ttl_seconds,
    std::shared_ptr<IOcspHttpClient>& out_client
) {
    std::shared_ptr<NvHttpOcspCacheClient> cache_client = std::make_shared<NvHttpOcspCacheClient>();
    cache_client->m_inner_client = std::move(inner_client);
    cache_client->m_cache = std::make_shared<NvCache>(std::make_shared<NvCacheOptions>(max_size_bytes, ttl_seconds));
    out_client = std::move(cache_client);
    return Error::Ok;
}

Error NvHttpOcspCacheClient::get_ocsp_response(
    const nv_unique_ptr<X509>& subject_cert,
    const nv_unique_ptr<X509>& issuer_cert,
    const nv_unique_ptr<stack_st_X509>& intermediates,
    const nv_unique_ptr<X509_STORE>& trust_store,
    NvOcspResponse& out_ocsp_response
) {
    std::string key;
    Error error = get_cache_key(subject_cert, issuer_cert, key);
    if (error != Error::Ok) {
        return error;
    }
    LOG_TRACE("Getting cached OCSP response for key: " << key);
    std::shared_ptr<void> ocsp_resp_cache_ptr;
    std::shared_ptr<NvOcspResponse> ocsp_resp_cache;
    error = m_cache->get(key, ocsp_resp_cache_ptr);
    if (error != Error::Ok && error != Error::CacheObjectNotFound) {
        return error;
    }
    bool should_refresh = false;
    if (error == Error::CacheObjectNotFound) {
        LOG_TRACE("OCSP response not found in cache, refreshing");
        should_refresh = true;
    } else {
        ocsp_resp_cache = std::static_pointer_cast<NvOcspResponse>(ocsp_resp_cache_ptr);
        if (ocsp_resp_cache->nextupd < time(nullptr)) {
            LOG_TRACE("OCSP next update time is in the past, refreshing");
            should_refresh = true;
        }
    }

    if (should_refresh) {
        LOG_TRACE("Refreshing OCSP response");
        error = m_inner_client->get_ocsp_response(subject_cert, issuer_cert, intermediates, trust_store, out_ocsp_response);
        if (error != Error::Ok) {
            return error;
        }
        error = m_cache->put(key, std::make_shared<NvOcspResponse>(out_ocsp_response), NvHttpOcspCacheClient::NV_OCSP_RESPONSE_SIZE_BYTES+key.size());
        if (error != Error::Ok) {
            return error;
        }
        return Error::Ok;
    }
    LOG_TRACE("OCSP response found in cache, returning");
    out_ocsp_response = *ocsp_resp_cache;
    return Error::Ok;
}

Error NvHttpOcspCacheClient::get_cache_key(
    const nv_unique_ptr<X509>& subject_cert,
    const nv_unique_ptr<X509>& issuer_cert,
    std::string& out_cache_key
) {
    nv_unique_ptr<OCSP_CERTID> id(OCSP_cert_to_id(EVP_sha1(), subject_cert.get(), issuer_cert.get()));
    if (!id) {
        LOG_ERROR("Unable to create OCSP_CERTID: " << get_openssl_error());
        return Error::InternalError;
    }
    unsigned char *cert_id_data = nullptr;
    int der_len = i2d_OCSP_CERTID(id.get(), &cert_id_data);
    if (der_len <= 0) {
        LOG_ERROR("Unable to serialize OCSP_CERTID to DER: " << get_openssl_error());
        return Error::InternalError;
    }
    out_cache_key = std::string(reinterpret_cast<const char*>(cert_id_data), der_len);
    OPENSSL_free(cert_id_data);
    return Error::Ok;
}
}
