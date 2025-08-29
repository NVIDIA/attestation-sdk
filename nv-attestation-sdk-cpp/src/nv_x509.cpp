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

#include <cstring>
#include <curl/urlapi.h>
#include <iostream>
#include <fstream>
#include <string>
#include <time.h>
#include <limits>
#include <memory>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>

#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/stack.h>
#include <openssl/ocsp.h>
#include <openssl/asn1.h>
#include <openssl/http.h>
#include <openssl/conf.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>

#include "nv_attestation/nv_http.h"
#include "nvat.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/nv_types.h"
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"
#include "internal/debug.hpp"
#include "internal/certs.h"

//todo: use specific error codes here instead of Error::InternalError

namespace nvattestation {

constexpr int MILLIS_PER_SECOND = 1000;

std::string X509CertChain::to_string(FWIDType fwid_type) {
    switch (fwid_type) {
        case FWIDType::FWID_2_23_133_5_4_1:
            return "2.23.133.5.4.1";
        case FWIDType::FWID_2_23_133_5_4_1_1:
            return "2.23.133.5.4.1.1";
    }
    return "";
}

Error NvHttpOcspClient::transfer_ocsp_request( // NOLINT(readability-function-cognitive-complexity)
    BIO* req_bio,
    nv_unique_ptr<OCSP_RESPONSE>& out_ocsp_resp
) {
    // Get serialized OCSP request data from the BIO
    const unsigned char *req_data_ptr = nullptr;
    long req_data_len_l = BIO_get_mem_data(req_bio, &req_data_ptr);
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
        return error;
    }

    // Check HTTP status
    if (http_status != HTTP_STATUS_OK) {
        LOG_ERROR("OCSP server returned HTTP status: " << http_status);
        return Error::OcspServerError;
    }

    // Parse the response into OCSP_RESPONSE
    if (response_body.empty()) {
        LOG_ERROR("Empty OCSP response received");
        return Error::OcspInvalidResponse;
    }

    // Create a memory BIO from the response data
    nv_unique_ptr<BIO> resp_bio(BIO_new_mem_buf(response_body.data(), static_cast<int>(response_body.size())));
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

    // Check response status
    int response_status_val = OCSP_response_status(ocsp_resp.get());
    switch (response_status_val) {
        case OCSP_RESPONSE_STATUS_SUCCESSFUL:
            out_ocsp_resp = std::move(ocsp_resp);
            LOG_DEBUG("OCSP request successful");
            return Error::Ok;
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
}

Error NvHttpOcspClient::create(
    NvHttpOcspClient& out_client,
    const std::string& base_url,
    HttpOptions http_options) {
    out_client.m_http_options = http_options;
    out_client.m_ocsp_url = base_url;
    Error error = NvHttpClient::create(out_client.m_http_client, http_options);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to create HTTP client for OCSP request");
        return error;
    }
    return Error::Ok;
}
    
Error NvHttpOcspClient::init_from_env(
    NvHttpOcspClient& out_client,
    const char* base_url,
    HttpOptions http_options) {
    std::string base_uri_str;
    if (base_url == nullptr || *base_url == '\0') {
        base_uri_str = get_env_or_default("NVAT_OCSP_BASE_URL", DEFAULT_BASE_URL);
    } else {
        base_uri_str = std::string(base_url);
    }
    
    return create(out_client, base_uri_str, http_options);
}

// Function to create an X509 object from a certificate file path
nv_unique_ptr<X509> x509_from_cert_path(const std::string &path) {
    std::ifstream cert_file_stream(path);
    if (!cert_file_stream.is_open()) {
        LOG_PUSH_ERROR(Error::InternalError, "Error: unable to open certificate file: " << path);
        return nullptr;
    }
    std::string cert_file_string((std::istreambuf_iterator<char>(cert_file_stream)), std::istreambuf_iterator<char>());
    nv_unique_ptr<X509> cert(x509_from_cert_string(cert_file_string));
    if (!cert) {
        LOG_PUSH_ERROR(Error::InternalError, "Error: unable to create X509 from certificate file content: " << path);
        // Error already logged in x509_from_cert_string
        return nullptr;
    }
    return cert;
}

// Function to create an X509_STORE from a trust anchor certificate
nv_unique_ptr<X509_STORE> create_trust_store(X509* trust_anchor_cert) {
    if (trust_anchor_cert == nullptr) {
         LOG_PUSH_ERROR(Error::InternalError, "Error: provided trust anchor certificate is null.");
         return nullptr;
    }
    nv_unique_ptr<X509_STORE> store(X509_STORE_new());
    if(store == nullptr) {
        LOG_PUSH_ERROR(Error::InternalError, "Error: unable to create X509_STORE: " << get_openssl_error());
        return nullptr;
    }

    // add trust anchor to store and check for errors
    if(X509_STORE_add_cert(store.get(), trust_anchor_cert) != 1) {
        LOG_PUSH_ERROR(Error::InternalError, "Error: unable to add trust anchor to store: " << get_openssl_error());
        return nullptr;
    }
    return store;
}

nv_unique_ptr<X509> x509_from_cert_string(const std::string &cert_string) {

    nv_unique_ptr<BIO> bio(BIO_new_mem_buf(cert_string.c_str(), (int)cert_string.size()));
    if(bio == nullptr) {
        LOG_PUSH_ERROR(Error::InternalError, "Could not load cert into BIO: " << get_openssl_error());
        return nullptr;
    }
    
    nv_unique_ptr<X509> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if(cert == nullptr) {
        // print openssl errors
        ERR_print_errors_fp(stderr);
        LOG_PUSH_ERROR(Error::InternalError, "Could not read cert from BIO: " << get_openssl_error());
        return nullptr;
    }
    
    return cert;
}

X509CertChain::X509CertChain(CertificateChainType type, nv_unique_ptr<X509_STORE> trust_store) {
    m_certs = std::vector<nv_unique_ptr<X509>>();
    m_type = type;
    m_trust_store = std::move(trust_store);
}

// Public static factory method
Error X509CertChain::create(
    CertificateChainType type, 
    const std::string& root_cert_str,
    X509CertChain& out_cert_chain) {

    nv_unique_ptr<X509_STORE> trust_store = nullptr;

    nv_unique_ptr<X509> root_cert = x509_from_cert_string(root_cert_str);
    if (!root_cert) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to create X509 from root_cert");
        return Error::InternalError;
    }

    trust_store = create_trust_store(root_cert.get());
    if (!trust_store) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to create trust store in X509CertChain::create.");
        return Error::InternalError;
    }
    
    out_cert_chain = X509CertChain(type, std::move(trust_store));
    return Error::Ok;
}

Error X509CertChain::set_root_cert(nv_unique_ptr<X509> root_cert) {
    if (!root_cert) {
        LOG_PUSH_ERROR(Error::InternalError, "Provided root certificate is null in X509CertChain::set_root_cert, trust store not updated.");
        return Error::InternalError;
    }

    nv_unique_ptr<X509_STORE> new_trust_store = create_trust_store(root_cert.get());
    if (!new_trust_store) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to create new trust store in X509CertChain::set_root_cert.");
        return Error::InternalError;
    }

    m_trust_store = std::move(new_trust_store);
    LOG_DEBUG("Successfully updated trust store in X509CertChain.");
    return Error::Ok;
}

Error X509CertChain::push_back(const std::string &cert_string) {
    nv_unique_ptr<X509> cert(x509_from_cert_string(cert_string));
    if(cert == nullptr) {
        LOG_PUSH_ERROR(Error::InternalError, "Error: unable to create X509 from cert string: " << get_openssl_error());
        return Error::InternalError;
    }
    m_certs.push_back(std::move(cert));
    return Error::Ok;
}

Error X509CertChain::verify_signature(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& signature,
    const EVP_MD* md) {

    if (m_certs.empty() || !m_certs[0]) {
        LOG_PUSH_ERROR(Error::InternalError, "Leaf certificate is null or chain is empty.");
        return Error::InternalError;
    }

    if (md == nullptr) {
        LOG_PUSH_ERROR(Error::InternalError, "Hash function is null.");
        return Error::InternalError;
    }

    nv_unique_ptr<EVP_PKEY> pkey(X509_get_pubkey(m_certs[0].get()));
    if (!pkey) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to get public key from certificate: " << get_openssl_error());
        return Error::InternalError;
    }

    nv_unique_ptr<EVP_MD_CTX> md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to create EVP_MD_CTX: " << get_openssl_error());
        return Error::InternalError;
    }

    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, md, nullptr, pkey.get()) != 1) {
        LOG_PUSH_ERROR(Error::InternalError, "EVP_DigestVerifyInit failed: " << get_openssl_error());
        return Error::InternalError;
    }

    // Provide the data to be hashed and verified.
    if (EVP_DigestVerifyUpdate(md_ctx.get(), data.data(), data.size()) != 1) {
        LOG_PUSH_ERROR(Error::InternalError, "EVP_DigestVerifyUpdate failed: " << get_openssl_error());
        return Error::InternalError;
    }

    // Verify the signature.
    // EVP_DigestVerifyFinal returns 1 for success (signature valid),
    // 0 for failure (signature invalid), and a negative value for other errors.
    int verify_result = EVP_DigestVerifyFinal(md_ctx.get(), signature.data(), signature.size());

    if (verify_result == 1) {
        // Signature is valid
        return Error::Ok;
    }
    if (verify_result == 0) {
        // Signature is invalid
        LOG_DEBUG("Signature verification failed: Invalid signature."); 
        return Error::InternalError;
    } 
    // An error occurred during finalization
    LOG_PUSH_ERROR(Error::InternalError, "EVP_DigestVerifyFinal failed with error: " << get_openssl_error());
    return Error::InternalError;
}

Error X509CertChain::verify_signature_pkcs11(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& pkcs11_signature,
    const EVP_MD* md) {

    if (pkcs11_signature.size() % 2 != 0) {
        LOG_PUSH_ERROR(Error::InternalError, "PKCS#11 signature length must be even (R and S components of equal length).");
        return Error::InternalError;
    }

    size_t component_len = pkcs11_signature.size() / 2;

    nv_unique_ptr<BIGNUM> r_bignum(BN_new());
    nv_unique_ptr<BIGNUM> s_bignum(BN_new());
    if (!r_bignum || !s_bignum) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to allocate BIGNUM for R or S: " << get_openssl_error());
        return Error::InternalError;
    }

    if (BN_bin2bn(pkcs11_signature.data(), static_cast<int>(component_len), r_bignum.get()) == nullptr) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to convert R component to BIGNUM: " << get_openssl_error());
        return Error::InternalError;
    }
    if (BN_bin2bn(pkcs11_signature.data() + component_len, static_cast<int>(component_len), s_bignum.get()) == nullptr) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to convert S component to BIGNUM: " << get_openssl_error());
        return Error::InternalError;
    }

    nv_unique_ptr<ECDSA_SIG> ecdsa_sig(ECDSA_SIG_new());
    if (!ecdsa_sig) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to allocate ECDSA_SIG: " << get_openssl_error());
        return Error::InternalError;
    }

    // ECDSA_SIG_set0 takes ownership of r and s if successful.
    // We need to release our nv_unique_ptr ownership if the call is successful.
    if (ECDSA_SIG_set0(ecdsa_sig.get(), r_bignum.get(), s_bignum.get()) != 1) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to set R and S in ECDSA_SIG: " << get_openssl_error());
        // r_bignum and s_bignum are still managed by their nv_unique_ptr and will be freed.
        return Error::InternalError;
    }
    // Release ownership as ECDSA_SIG_set0 now owns r and s BIGNUMs
    (void)r_bignum.release(); 
    (void)s_bignum.release(); 


    int der_len = i2d_ECDSA_SIG(ecdsa_sig.get(), nullptr);
    if (der_len <= 0) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to get DER encoding length for ECDSA_SIG: " << get_openssl_error());
        return Error::InternalError;
    }

    std::vector<uint8_t> der_signature(der_len);
    unsigned char *ptr = der_signature.data();
    if (i2d_ECDSA_SIG(ecdsa_sig.get(), &ptr) <= 0) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to DER encode ECDSA_SIG: " << get_openssl_error());
        return Error::InternalError;
    }

    // Call the original verify_signature method with the DER encoded signature
    Error error = verify_signature(data, der_signature, md);
    return error;
}

Error X509CertChain::verify() const {
    // ref: https://docs.openssl.org/3.0/man1/openssl-verification-options/#certification-path-building
    // verification involves setting up the untrusted certs, the trust anchor, and then calling X509_verify_cert
    // with the target cert to be verified. the function will build a chain of certs from the target cert
    // using the untrusted certs, till it finds a cert that is the trust anchor.
    // todo: move all initializations to the init function. make sure that same thing is not being 
    // initialized multiple times (xmlsec also initializes these openssl functions)
    // also, openssl init might not be needed for newer versions of openssl
    // OpenSSL_add_all_algorithms();
    // ERR_load_crypto_strings();
    if (m_certs.empty()) {
        LOG_PUSH_ERROR(Error::InternalError, "No certs in chain");
        return Error::InternalError;
    }

    // Use the member trust store
    if (m_trust_store == nullptr) {
        LOG_PUSH_ERROR(Error::InternalError, "Trust store is not initialized. Cannot verify certificate chain.");
        return Error::InternalError;
    }
    
    nv_unique_ptr<X509_STORE_CTX> ctx(X509_STORE_CTX_new());
    if(ctx == nullptr) {
        LOG_PUSH_ERROR(Error::InternalError, "Error: unable to create X509_STORE_CTX" << get_openssl_error());
        return Error::InternalError;
    }

    // create stack of untrusted certs from m_certs, excluding the first one (that will be the target cert)
    // initialize stack of (x509)
    nv_unique_ptr<STACK_OF(X509)> untrusted_certs(sk_X509_new_null());
    if(untrusted_certs == nullptr) {
        LOG_PUSH_ERROR(Error::InternalError, "Error: unable to create STACK_OF(X509): " << get_openssl_error());
        return Error::InternalError;
    }

    for (size_t i = 1; i < m_certs.size(); i++) {
        if(sk_X509_push(untrusted_certs.get(), m_certs[i].get()) <= 0) {
            LOG_PUSH_ERROR(Error::InternalError, "Error: unable to push cert to stack: " << get_openssl_error());
            return Error::InternalError;
        }
    }
    
    
    if(X509_STORE_CTX_init(ctx.get(), m_trust_store.get(), m_certs[0].get(), untrusted_certs.get()) != 1) {
        LOG_PUSH_ERROR(Error::InternalError, "Error: X509_STORE_CTX_init failed: " << get_openssl_error());
        return Error::InternalError;
    }
    
    
    int ret = X509_verify_cert(ctx.get());
    if(ret != 1) {
        int err = X509_STORE_CTX_get_error(ctx.get());
        LOG_PUSH_ERROR(Error::InternalError, "Certificate chain verification failed: " 
                << X509_verify_cert_error_string(err));
        return Error::InternalError;
    } 
    
    return Error::Ok;
}

Error X509CertChain::calculate_min_expiration_time(time_t& out_min_expiration_time, std::string* iso8601_time_out) const {
    if (m_certs.empty()) {
        LOG_PUSH_ERROR(Error::InternalError, "No certificates in chain to calculate expiration time");
        return Error::InternalError;
    }
    
    time_t min_expiration_time = std::numeric_limits<time_t>::max();
    bool valid_expiration_found = false;
    
    for (const auto& cert : m_certs) {
        if (cert == nullptr) {
            LOG_PUSH_ERROR(Error::InternalError, "Null certificate in chain");
            return Error::InternalError;
        }
        
        // Get the "not after" time from the certificate
        const ASN1_TIME* not_after = X509_get0_notAfter(cert.get());
        if (not_after == nullptr) {
            LOG_PUSH_ERROR(Error::InternalError, "Could not get expiration time from certificate");
            return Error::InternalError;
        }
        
        struct tm tm_expiration;
        if (ASN1_TIME_to_tm(not_after, &tm_expiration) != 1) {
            LOG_PUSH_ERROR(Error::InternalError, "Failed to convert ASN1_TIME to tm: " << get_openssl_error());
            return Error::InternalError;
        }
        
        time_t cert_expiration = timegm(&tm_expiration);
        if (cert_expiration < min_expiration_time) {
            min_expiration_time = cert_expiration;
            valid_expiration_found = true;
        }
    }
    
    if (!valid_expiration_found) {
        LOG_PUSH_ERROR(Error::InternalError, "Could not determine valid expiration time for the certificate chain");
        return Error::InternalError;
    }
    
    // If requested, convert min_expiration_time to ISO8601 format and return via the output parameter
    if (iso8601_time_out != nullptr) {
        struct tm tm_iso;
        gmtime_r(&min_expiration_time, &tm_iso);
        
        constexpr size_t BUF_SIZE = 25; // YYYY-MM-DDThh:mm:ssZ (20 chars) + null terminator + buffer
        char iso8601_time[BUF_SIZE];
        strftime(iso8601_time, sizeof(iso8601_time), "%Y-%m-%dT%H:%M:%SZ", &tm_iso);
        
        *iso8601_time_out = iso8601_time;
    }
    
    out_min_expiration_time = min_expiration_time;
    return Error::Ok;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
Error X509CertChain::generate_cert_chain_claims(const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, CertChainClaims& out_cert_chain_claims) const {
    time_t min_expiration_time = 0;
    std::string min_expiration_time_str;
    Error error = calculate_min_expiration_time(min_expiration_time, &min_expiration_time_str);
    if (error != Error::Ok) {
        return error;
    }
    
    out_cert_chain_claims.expiration_date = min_expiration_time_str; 
    out_cert_chain_claims.status = CertChainStatus::VALID; 

    error = verify();
    if (error != Error::Ok) {
        return Error::CertChainVerificationFailure;
    }

    OCSPClaims ocsp_claims;
    error = generate_ocsp_claims(ocsp_verify_options, ocsp_client, ocsp_claims);
    if (error != Error::Ok) {
        return error;
    }
    out_cert_chain_claims.ocsp_claims = ocsp_claims;
    
    // generate cert chain status claim
    out_cert_chain_claims.status = CertChainStatus::INVALID;
    if (min_expiration_time < time(nullptr)) {
        out_cert_chain_claims.status = CertChainStatus::EXPIRED;
    } else {
        out_cert_chain_claims.status = CertChainStatus::VALID;
    }

    return Error::Ok;
}


Error X509CertChain::generate_ocsp_claims(const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, OCSPClaims& out_ocsp_claims) const { // NOLINT(readability-function-cognitive-complexity)
    LOG_DEBUG("Generating OCSP claims");

    // Use the member trust store
    if (!m_trust_store) {
        LOG_PUSH_ERROR(Error::InternalError, "Trust store is not initialized. Cannot generate OCSP claims.");
        return Error::InternalError;
    }

    out_ocsp_claims = OCSPClaims();

    int start_indx = 0;
    if (m_type == CertificateChainType::GPU_DEVICE_IDENTITY || m_type == CertificateChainType::NVSWITCH_DEVICE_IDENTITY) {
        start_indx = 1;
    }

    // Stack for intermediate certificates for OCSP_basic_verify, built incrementally.
    nv_unique_ptr<STACK_OF(X509)> ocsp_verify_intermediates(sk_X509_new_null());
    if(!ocsp_verify_intermediates) {
        LOG_PUSH_ERROR(Error::InternalError, "unable to create STACK_OF(X509) for ocsp_verify_intermediates: " << get_openssl_error());
        return Error::InternalError;
    }

    // Loop from the certificate just before the root, down to the start_indx.
    // The subject_idx refers to the certificate being checked for revocation.
    // The issuer_idx refers to the issuer of subject_idx's certificate.
    for(int subject_idx = (int)m_certs.size() - 2; subject_idx >= start_indx; --subject_idx) {
        LOG_DEBUG("Processing cert : " << get_cert_subject_issuer_str(m_certs[subject_idx].get()));
        int issuer_idx = subject_idx + 1;

        // The intermediate_certs stack for OCSP_basic_verify is ocsp_verify_intermediates,
        // which is built incrementally across iterations.

        nv_unique_ptr<OCSP_REQUEST> ocsp_req(OCSP_REQUEST_new());
        // Create the original Cert ID
        nv_unique_ptr<OCSP_CERTID> id_orig (OCSP_cert_to_id(EVP_sha1(), m_certs[subject_idx].get(), m_certs[issuer_idx].get()));
        if (!id_orig) {
             LOG_PUSH_ERROR(Error::InternalError, "Unable to create OCSP_CERTID: " << get_openssl_error());
             return Error::InternalError;
        }

        // Duplicate the Cert ID for the request
        OCSP_CERTID *id_for_req = OCSP_CERTID_dup(id_orig.get());
        if (id_for_req == nullptr) {
            LOG_PUSH_ERROR(Error::InternalError, "Unable to duplicate OCSP_CERTID: " << get_openssl_error());
            return Error::InternalError;
        }

        // Add the duplicated ID to the request (OCSP_request_add0_id takes ownership of id_for_req)
        if (OCSP_request_add0_id(ocsp_req.get(), id_for_req) == nullptr) {
             // If adding fails, we need to free the duplicated ID manually
             OCSP_CERTID_free(id_for_req);
             LOG_PUSH_ERROR(Error::InternalError, "Unable to add subject to ocsp request");
             return Error::InternalError;
        }
        // Original id_orig remains managed by nv_unique_ptr. We need it later for OCSP_resp_find_status

        if (OCSP_request_add1_nonce(ocsp_req.get(), nullptr, -1) != 1) {
            LOG_PUSH_ERROR(Error::InternalError, "Unable to add nonce to ocsp request");
            return Error::InternalError;
        }

        // Serialize the OCSP request to a memory BIO
        nv_unique_ptr<BIO> req_bio(BIO_new(BIO_s_mem()));
        if (!req_bio) {
            LOG_PUSH_ERROR(Error::InternalError, "Unable to create memory BIO for OCSP request: " << get_openssl_error());
            return Error::InternalError;
        }
        if (!i2d_OCSP_REQUEST_bio(req_bio.get(), ocsp_req.get())) {
            LOG_PUSH_ERROR(Error::InternalError, "Unable to serialize OCSP request to BIO: " << get_openssl_error());
            return Error::InternalError;
        }

        // Use the IOcspHttpClient interface
        nv_unique_ptr<OCSP_RESPONSE> ocsp_resp;
        Error error = ocsp_client.transfer_ocsp_request(
            req_bio.get(),
            ocsp_resp
        );

        if (error != Error::Ok) {
            return error;
        }

        // Extract the basic response
        nv_unique_ptr<OCSP_BASICRESP> basic_resp(OCSP_response_get1_basic(ocsp_resp.get()));
        if (!basic_resp) {
            LOG_PUSH_ERROR(Error::OcspInvalidResponse, "could not extract basic response from OCSP response: " << get_openssl_error());
            return Error::OcspInvalidResponse;
        }

        // --- BEGIN DEBUG PRINTS ---
        if (get_logger()->should_log(LogLevel::DEBUG, __FILE__, __FUNCTION__, __LINE__)) {
            LOG_DEBUG("--- OCSP Verification Debug Info (Subject Index: " << subject_idx << ") ---");
            // Print Signer (Responder) Cert Info
            X509* signer_cert = nullptr;
            // Note: Using sk_X509_num(NULL) returns -1, which is fine for sk_X509_value which checks >= 0
            if (OCSP_resp_get0_signer(basic_resp.get(), &signer_cert, nullptr) != 0 && signer_cert != nullptr) {
                LOG_DEBUG("Responder Cert Info: " << get_cert_subject_issuer_str(signer_cert));
            } else {
                LOG_DEBUG("Could not retrieve responder certificate from OCSP response.");
            }
            LOG_DEBUG("Intermediate Certs Provided for OCSP_basic_verify (" << sk_X509_num(ocsp_verify_intermediates.get()) << "):");
            for (int i = 0; i < sk_X509_num(ocsp_verify_intermediates.get()); ++i) {
                X509 *inter_cert = sk_X509_value(ocsp_verify_intermediates.get(), i);
                if (inter_cert != nullptr) {
                    LOG_DEBUG("  Intermediate Cert [" << i << "]: " << get_cert_subject_issuer_str(inter_cert));
                }
            }
            // Print Trust Store Certs Info
            LOG_DEBUG("Trust Store Certs:");
            STACK_OF(X509_OBJECT) *store_objs = X509_STORE_get0_objects(m_trust_store.get());
            for (int i = 0; i < sk_X509_OBJECT_num(store_objs); ++i) {
                X509_OBJECT *obj = sk_X509_OBJECT_value(store_objs, i);
                if (X509_OBJECT_get_type(obj) == X509_LU_X509) {
                    X509 *trust_cert = X509_OBJECT_get0_X509(obj);
                    if (trust_cert != nullptr) {
                        LOG_DEBUG("  Trust Anchor [" << i << "]: " << get_cert_subject_issuer_str(trust_cert));
                    }
                }
            }
            LOG_DEBUG("--- End OCSP Verification Debug Info ---");
        }
        // --- END DEBUG PRINTS ---

        // Verify the OCSP response signature and trust
        int verification_status = OCSP_basic_verify(basic_resp.get(), ocsp_verify_intermediates.get(), m_trust_store.get(), 0);

        if(verification_status != 1) {
            if (verification_status == 0) {
                // verification_status == 0 means verification failure (e.g., signature mismatch, untrusted signer)
                std::string err_msg = "OCSP response verification failed. OpenSSL errors: " + get_openssl_error();
                LOG_PUSH_ERROR(Error::OcspInvalidResponse, err_msg);
                return Error::OcspInvalidResponse;
            } 
            // verification_status < 0 means some other error occurred during verification (e.g., memory allocation)
            LOG_PUSH_ERROR(Error::InternalError, "OCSP basic verification encountered an internal error with status: "
                    << verification_status << ". OpenSSL errors: " << get_openssl_error());
            return Error::InternalError;
        }

        LOG_DEBUG("OCSP basic verification successful for subject index " << subject_idx);

        // generate nonce claim
        int result = OCSP_check_nonce(ocsp_req.get(), basic_resp.get());
        LOG_DEBUG("OCSP_check_nonce returned: " << result << " for subject index " << subject_idx);
        /** 
         * OCSP_check_nonce() returns the result of the nonce comparison between req and resp. 
         * The return value indicates the result of the comparison. If nonces are present and equal 1 is returned. 
         * If the nonces are absent 2 is returned. If a nonce is present in the response only 3 is returned.
         * If nonces are present and unequal 0 is returned. If the nonce is present in the request only then -1 is returned.
         * https://docs.openssl.org/1.1.1/man3/OCSP_check_nonce.html
         */
        out_ocsp_claims.nonce_matches = result == 1;

        if (ocsp_verify_options.get_nonce_enabled() && !out_ocsp_claims.nonce_matches) {
            LOG_PUSH_ERROR(Error::OcspInvalidResponse, "OCSP nonce mismatch for subject index " << subject_idx);
            return Error::OcspInvalidResponse;
        }

        /** 
         * do not free these thisupd and nextupd pointers as they are internal pointers of OCSP_BASICRESP
         * and will be freed when OCSP_BASICRESP is freed
        */
        ASN1_GENERALIZEDTIME *thisupd = nullptr;
        ASN1_GENERALIZEDTIME *nextupd = nullptr;
        int reason = -1; 
        int status = -1;
        // Use the original Cert ID (managed by id_orig) to find the status
        result = OCSP_resp_find_status(basic_resp.get(), id_orig.get(), &status, &reason,
                              nullptr, &thisupd, &nextupd);
        if(result != 1) {
            LOG_PUSH_ERROR(Error::OcspInvalidResponse, "OCSP basic response is not present for subject index " << subject_idx);
            return Error::InternalError;
        }

        // generate status claim
        switch(status) {
            case V_OCSP_CERTSTATUS_REVOKED:
                out_ocsp_claims.status = OCSPStatus::REVOKED;
                out_ocsp_claims.revocation_reason = std::make_shared<std::string>(OCSP_crl_reason_str(reason));
                LOG_DEBUG("Certificate is revoked");
                if (ocsp_verify_options.get_allow_cert_hold() && reason == OCSP_REVOKED_STATUS_CERTIFICATEHOLD) {
                    out_ocsp_claims.status = OCSPStatus::GOOD;
                    break;
                }
                return Error::OcspStatusNotGood; // If any cert is revoked, return immediately
                break;
            case V_OCSP_CERTSTATUS_GOOD:
                out_ocsp_claims.status = OCSPStatus::GOOD; // This will be overwritten by next good cert, or a final revoked/unknown
                break;
            case V_OCSP_CERTSTATUS_UNKNOWN:
                out_ocsp_claims.status = OCSPStatus::UNKOWN;
                LOG_ERROR("Certificate status is unknown");
                return Error::OcspStatusNotGood; // If any cert status is unknown, return immediately
            default:
                LOG_ERROR("OCSP certificate status in ocsp response is not valid");
                return Error::OcspInvalidResponse;
        }


        LOG_DEBUG("Generating expiration time claim");
        // generate expiration time claim
        struct tm tm{};
        if (ASN1_TIME_to_tm((const ASN1_TIME *)nextupd, &tm) != 1) {
            LOG_PUSH_ERROR(Error::InternalError, "unable to convert ASN1_TIME to tm: " << get_openssl_error());
            return Error::InternalError;
        }
        
         /**
         * ocsp_check_validity is not needed here as we will not check the time
         * validity of the cert.
         * the expiration time will be a separate claim and the user can choose to use it 
         * however they wish (for e.g they may wish to have a 48h expiration time instead of 
         * the default 24h)
         */
        // note: timegm only works on linux.
        time_t current_expiration_time = timegm(&tm);
        LOG_DEBUG("ASN1_TIME_to_tm successful for subject index " << subject_idx << " expiration time: " << current_expiration_time);
        // The OCSP response expiration time is for this specific response.
        // We should take the minimum expiration time of all OCSP responses in the chain.
        if (out_ocsp_claims.ocsp_resp_expiration_time == 0 || current_expiration_time < out_ocsp_claims.ocsp_resp_expiration_time) {
            out_ocsp_claims.ocsp_resp_expiration_time = current_expiration_time;
        }
        
        // Prepare intermediates for the next iteration (which will process subject_idx-1).
        // The current m_certs[subject_idx] becomes an intermediate for the next subject.
        // sk_X509_insert does not increment ref count, which is fine as m_certs owns X509.
        if (sk_X509_insert(ocsp_verify_intermediates.get(), m_certs[subject_idx].get(), 0) <= 0) {
            LOG_PUSH_ERROR(Error::InternalError, "Failed to prepend certificate to intermediate stack for OCSP: " << get_openssl_error());
            return Error::InternalError;
        }
    }
    // After the loop, if all certs were 'good', claims->status will be "good".
    // If the loop didn't run (e.g. m_certs.size() < 2 or adjusted start_indx is too high),
    // claims will be in its initial state ("unknown", expiration 0).
    // This might need adjustment if no certs are processed - what should be returned?
    // Current behavior: if loop doesn't run, returns initial "unknown" claims. This seems acceptable.
    return Error::Ok;
}
size_t X509CertChain::size() const {
    return m_certs.size();
}

Error X509CertChain::create_from_cert_chain_str(
    CertificateChainType type,
    const std::string& root_cert_str,
    const std::string& cert_chain,
    X509CertChain& out_cert_chain
    )
{
    if (cert_chain.empty()) {
        LOG_PUSH_ERROR(Error::InternalError, "Input PEM chain string is empty");
        return Error::InternalError;
    }
    


    Error error = X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, root_cert_str, out_cert_chain);
    if (error != Error::Ok) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to create X509CertChain");
        return error;
    }

    // Split PEM chain into individual certificates and add them to m_certificate_chains
    const std::string delimiter = "-----END CERTIFICATE-----";
    size_t start = 0;
    while (true) {
        size_t end = cert_chain.find(delimiter, start);
        if (end == std::string::npos) {
            break;
        }
        size_t cert_end = end + delimiter.length();
        std::string cert_str = cert_chain.substr(start, cert_end - start);

        Error error = out_cert_chain.push_back(cert_str);
        if (error != Error::Ok) {
            LOG_PUSH_ERROR(Error::InternalError, "Failed to add parsed GPU certificate to chain");
            return Error::InternalError;
        }

        start = cert_end;
        while (start < cert_chain.size() && (cert_chain[start] == '\n' || cert_chain[start] == '\r')) {
            ++start;
        }
    }
    if (out_cert_chain.size() == 0) {
            LOG_PUSH_ERROR(Error::InternalError, "No certificate chain available after parsing");
            return Error::InternalError;
    }
    return Error::Ok;
}

Error X509CertChain::get_fwid(size_t cert_index, FWIDType fwid_type, std::vector<uint8_t>& out_fwid) const {
    std::string fwid_oid = to_string(fwid_type);
    if (cert_index >= m_certs.size()) {
        LOG_ERROR("Certificate index out of bounds.");
        return Error::CertNotFound;
    }

    const X509* cert = m_certs[cert_index].get();
    if (cert == nullptr) {
        LOG_ERROR("Certificate at specified index is null.");
        return Error::CertNotFound;
    }

    nv_unique_ptr<ASN1_OBJECT> obj(OBJ_txt2obj(fwid_oid.c_str(), 0));
    if (!obj) {
        LOG_ERROR("Could not convert FWID OID string to ASN1_OBJECT: " << fwid_oid);
        return Error::CertFwidNotFound;
    }

    int loc = X509_get_ext_by_OBJ(cert, obj.get(), -1);
    if (loc < 0) {
        LOG_ERROR("FWID extension with OID " << fwid_oid << " not found in certificate at index " << cert_index);
        return Error::CertFwidNotFound;
    }

    X509_EXTENSION* ext = X509_get_ext(cert, loc);
    if (ext == nullptr) {
        // This should ideally not happen if loc >= 0
        LOG_ERROR("Could not retrieve extension by location even though found by OBJ. OpenSSL error: " << get_openssl_error());
        return Error::InternalError;
    }

    ASN1_OCTET_STRING* octet_str = X509_EXTENSION_get_data(ext);
    if (octet_str == nullptr) {
        LOG_ERROR("Could not get data from FWID extension. OpenSSL error: " << get_openssl_error());
        return Error::InternalError;
    }

    const unsigned char* data = ASN1_STRING_get0_data(octet_str);
    size_t length = ASN1_STRING_length(octet_str);

    if (data == nullptr || length <= 0) {
        LOG_ERROR("FWID extension data is empty or invalid.");
        return Error::InternalError;
    }

    if (length < X509CertChain::m_fwid_hash_length) {
        LOG_ERROR("FWID extension data is too short for SHA384 hash (need atleast " << X509CertChain::m_fwid_hash_length << " bytes, got " << length << " bytes).");
        return Error::InternalError;
    }

    if (fwid_type == FWIDType::FWID_2_23_133_5_4_1) {
        if (X509CertChain::m_fwid_hash_length > length) {
            LOG_ERROR("FWID extension data is too short for SHA384 hash (need atleast " << X509CertChain::m_fwid_hash_length << " bytes, got " << length << " bytes).");
            return Error::InternalError;
        }
        out_fwid.assign(data + length - X509CertChain::m_fwid_hash_length, data + length);
    } else if (fwid_type == FWIDType::FWID_2_23_133_5_4_1_1) {
        return get_fwid_2_23_133_5_4_1_1(data, length, out_fwid);
    }
    return Error::Ok;
}

Error X509CertChain::get_fwid_2_23_133_5_4_1_1(const unsigned char* extension_data, unsigned int length, std::vector<uint8_t>& out_fwid) {
    nv_unique_ptr<ASN1_SEQUENCE_ANY> seq(d2i_ASN1_SEQUENCE_ANY(nullptr, &extension_data, length));
    if (!seq) {
        LOG_ERROR("Failed to parse ASN1_SEQUENCE_ANY from extension data.");
        return Error::InternalError;
    }
    // fwid list is the 7th element in the sequence according to the spec
    // https://trustedcomputinggroup.org/wp-content/uploads/TCG_DICE_Attestation_Architecture_r22_02dec2020.pdf
    // NOLINTNEXTLINE(readability-magic-numbers)
    if (sk_ASN1_TYPE_num(seq.get()) <= 6) {
        LOG_ERROR("expected at least 7 elements in the FWID 2.23.133.5.4.1.1 extension");
        return Error::InternalError;
    }

    ASN1_TYPE* fwid_list_asn = sk_ASN1_TYPE_value(seq.get(), 6);

    if(fwid_list_asn == nullptr || fwid_list_asn->value.sequence == nullptr) {
        LOG_ERROR("expected a list of fwid elements");
        return Error::InternalError;
    }

    const unsigned char* fwid_list_data = ASN1_STRING_get0_data(fwid_list_asn->value.sequence);
    int fwid_list_length = ASN1_STRING_length(fwid_list_asn->value.sequence);
    LOG_DEBUG("fwid_list_data: " << to_hex_string(std::vector<uint8_t>(fwid_list_data, fwid_list_data + fwid_list_length)));
    std::vector<uint8_t> fwid_list_data_vec(fwid_list_data, fwid_list_data + fwid_list_length);
    /*
    the fwid list structure: 

    echo "3081b180064e5649444941810d4742313030204130312047535082023031830101840100850100a67e303d06096086480165030402020430d090cab1b6e6ffddca83d1781e25b3f040fa1f3c7608230cb5f41b1c1b99f5f748349e59d0ef8eb830c9bc79ccf77502303d06096086480165030402020430000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000870500800000018801c0890100" | xxd -r -p | openssl asn1parse -inform DER -i
    0:d=0  hl=3 l= 177 cons: SEQUENCE          
    3:d=1  hl=2 l=   6 prim:  cont [ 0 ]        
   11:d=1  hl=2 l=  13 prim:  cont [ 1 ]        
   26:d=1  hl=2 l=   2 prim:  cont [ 2 ]        
   30:d=1  hl=2 l=   1 prim:  cont [ 3 ]        
   33:d=1  hl=2 l=   1 prim:  cont [ 4 ]        
   36:d=1  hl=2 l=   1 prim:  cont [ 5 ]        
   39:d=1  hl=2 l= 126 cons:  cont [ 6 ]   <- this is the fwid list    
   41:d=2  hl=2 l=  61 cons:   SEQUENCE          
   43:d=3  hl=2 l=   9 prim:    OBJECT            :sha384
   54:d=3  hl=2 l=  48 prim:    OCTET STRING      [HEX DUMP]:D090CAB1B6E6FFDDCA83D1781E25B3F040FA1F3C7608230CB5F41B1C1B99F5F748349E59D0EF8EB830C9BC79CCF77502
  104:d=2  hl=2 l=  61 cons:   SEQUENCE          
  106:d=3  hl=2 l=   9 prim:    OBJECT            :sha384
  117:d=3  hl=2 l=  48 prim:    OCTET STRING      [HEX DUMP]:000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
  167:d=1  hl=2 l=   5 prim:  cont [ 7 ]        
  174:d=1  hl=2 l=   1 prim:  cont [ 8 ]        
  177:d=1  hl=2 l=   1 prim:  cont [ 9 ]
    */

    int offset = 2; // skip the context-specific tag and length bytes

    std::vector<std::vector<uint8_t>> fwid_list;
    while (offset < fwid_list_length) {
        offset += 2; // skip the sequence tag and length bytes

        offset += 1; // skip hash algorithm tag
        if(!can_read_buffer(fwid_list_data_vec, offset, 1, "hash algorithm length")) {
            return Error::InternalError;
        }
        int hash_alg_len = fwid_list_data_vec[offset];
        offset += 1;  // for hash algo length
        offset += hash_alg_len; // skip reading the hash algorithm

        offset += 1; // skip fwid tag
        if(!can_read_buffer(fwid_list_data_vec, offset, 1, "fwid length")) {
            return Error::InternalError;
        }
        int fwid_len = fwid_list_data_vec[offset];
        offset += 1;

        if(!can_read_buffer(fwid_list_data_vec, offset, fwid_len, "fwid")) {
            return Error::InternalError;
        }
        std::vector<uint8_t> fwid_vec(fwid_list_data_vec.begin() + offset, fwid_list_data_vec.begin() + offset + fwid_len);
        offset += fwid_len;

        fwid_list.push_back(fwid_vec);
    }

    if (offset != fwid_list_length) {
        LOG_ERROR("fwid list data is not fully parsed");
        return Error::InternalError;
    }

    if (fwid_list.empty()) {
        LOG_ERROR("fwid list is empty");
        return Error::InternalError;
    }

    out_fwid = fwid_list[0]; // use only the first fwid
    return Error::Ok;
}

Error X509CertChain::get_hwmodel(std::string& out_hwmodel) const {

    if (m_certs.size() < 2) {
        LOG_ERROR("Certificate index 1 is out of bounds. Chain size: " << m_certs.size());
        return Error::CertNotFound;
    }

    const X509* cert = m_certs[1].get();
    if (cert == nullptr) {
        LOG_ERROR("Certificate at index 1 is null.");
        return Error::CertNotFound;
    }

    // Get the subject name from the certificate
    X509_NAME* subject_name = X509_get_subject_name(cert);
    if (subject_name == nullptr) {
        LOG_ERROR("Failed to get subject name from certificate at index 1: " << get_openssl_error());
        return Error::InternalError;
    }

    int lastpos = -1;
    int cn_index = X509_NAME_get_index_by_NID(subject_name, NID_commonName, lastpos);
    if (cn_index < 0) {
        LOG_ERROR("Common name (CN) not found in certificate at index 1");
        return Error::InternalError;
    }

    X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(subject_name, cn_index);
    if (cn_entry == nullptr) {
        LOG_ERROR("Failed to get common name entry from certificate at index 1: " << get_openssl_error());
        return Error::InternalError;
    }

    ASN1_STRING* cn_asn1_string = X509_NAME_ENTRY_get_data(cn_entry);
    if (cn_asn1_string == nullptr) {
        LOG_ERROR("Failed to get ASN1_STRING from common name entry: " << get_openssl_error());
        return Error::InternalError;
    }

    const unsigned char* cn_data = ASN1_STRING_get0_data(cn_asn1_string);
    int cn_length = ASN1_STRING_length(cn_asn1_string);
    
    if (cn_data == nullptr || cn_length <= 0) {
        LOG_ERROR("Common name data is empty or invalid");
        return Error::InternalError;
    }

    // Store the common name in the output parameter
    out_hwmodel = std::string(reinterpret_cast<const char*>(cn_data), cn_length);
    
    return Error::Ok;
}

Error X509CertChain::get_ueid(std::string& out_ueid) const {
    if (m_certs.empty()) {
        LOG_ERROR("Certificate index 0 is out of bounds. Chain size: " << m_certs.size());
        return Error::CertNotFound;
    }

    const X509* cert = m_certs[0].get();
    if (cert == nullptr) {
        LOG_ERROR("Certificate at index 0 is null.");
        return Error::CertNotFound;
    }

    // Get the serial number from the certificate
    const ASN1_INTEGER* serial_asn1 = X509_get0_serialNumber(cert);
    if (serial_asn1 == nullptr) {
        LOG_ERROR("Failed to get serial number from certificate at index 0: " << get_openssl_error());
        return Error::InternalError;
    }

    // Convert ASN1_INTEGER to BIGNUM
    nv_unique_ptr<BIGNUM> serial_bn(ASN1_INTEGER_to_BN(serial_asn1, nullptr));
    if (!serial_bn) {
        LOG_ERROR("Failed to convert ASN1_INTEGER to BIGNUM: " << get_openssl_error());
        return Error::InternalError;
    }

    // Convert BIGNUM to decimal string
    char* dec_str = BN_bn2dec(serial_bn.get());
    if (dec_str == nullptr) {
        LOG_ERROR("Failed to convert BIGNUM to decimal string: " << get_openssl_error());
        return Error::InternalError;
    }

    // Store the serial number as decimal string in the output parameter
    out_ueid = std::string(dec_str);
    
    // Free the allocated string from OpenSSL
    OPENSSL_free(dec_str);
    
    return Error::Ok;
}


// << operator for OCSPClaims
std::ostream& operator<<(std::ostream& os, const OCSPClaims& claims) {
    os << "--- OCSP Claims ---" << std::endl;
    os << "OCSP Status: " << to_string(claims.status) << std::endl;
    os << "Revocation Reason: " << (claims.revocation_reason ? *claims.revocation_reason : "None") << std::endl;
    os << "Nonce Matches: " << (claims.nonce_matches ? "true" : "false") << std::endl;
    os << "OCSP Response Expiration (timestamp): " << claims.ocsp_resp_expiration_time << std::endl;
    
    std::string formatted_time;
    Error time_error = format_time(claims.ocsp_resp_expiration_time, formatted_time);
    if (time_error != Error::Ok) {
        formatted_time = "Format error";
    }
    os << "OCSP Response Expiration (readable): " << formatted_time << std::endl;
    return os;
}

// << operator for CertChainClaims
std::ostream& operator<<(std::ostream& os, const CertChainClaims& claims) {
    os << "--- Certificate Chain Claims ---" << std::endl;
    os << "Expiration Date: " << claims.expiration_date << std::endl;
    os << "Cert Chain Status: " << to_string(claims.status) << std::endl;
    os << std::endl;
    os << claims.ocsp_claims;
    return os;
}

}