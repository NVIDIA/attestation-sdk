/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <algorithm>
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
#include "nv_attestation/dice_tcb_info.h"
#include "nv_attestation/nv_types.h"
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/nv_ocsp.h"
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



// Function to create an X509 object from a certificate file path
nv_unique_ptr<X509> x509_from_cert_path(const std::string &path) {
    std::ifstream cert_file_stream(path);
    if (!cert_file_stream.is_open()) {
        LOG_ERROR("Error: unable to open certificate file: " << path);
        return nullptr;
    }
    std::string cert_file_string((std::istreambuf_iterator<char>(cert_file_stream)), std::istreambuf_iterator<char>());
    nv_unique_ptr<X509> cert(x509_from_cert_string(cert_file_string));
    if (!cert) {
        LOG_ERROR("Error: unable to create X509 from certificate file content: " << path);
        // Error already logged in x509_from_cert_string
        return nullptr;
    }
    return cert;
}

// Function to create an X509_STORE from a trust anchor certificate
nv_unique_ptr<X509_STORE> create_trust_store(X509* trust_anchor_cert) {
    if (trust_anchor_cert == nullptr) {
         LOG_ERROR("Error: provided trust anchor certificate is null.");
         return nullptr;
    }
    nv_unique_ptr<X509_STORE> store(X509_STORE_new());
    if(store == nullptr) {
        LOG_ERROR("Error: unable to create X509_STORE: " << get_openssl_error());
        return nullptr;
    }

    // add trust anchor to store and check for errors
    if(X509_STORE_add_cert(store.get(), trust_anchor_cert) != 1) {
        LOG_ERROR("Error: unable to add trust anchor to store: " << get_openssl_error());
        return nullptr;
    }
    return store;
}

nv_unique_ptr<X509_STORE> create_trust_store(const std::vector<X509*>& trust_anchor_certs) {
    if (trust_anchor_certs.empty()) {
        LOG_ERROR("Error: no trust anchor certificates provided.");
        return nullptr;
    }
    nv_unique_ptr<X509_STORE> store(X509_STORE_new());
    if (store == nullptr) {
        LOG_ERROR("Error: unable to create X509_STORE: " << get_openssl_error());
        return nullptr;
    }
    for (X509* anchor : trust_anchor_certs) {
        if (anchor == nullptr) {
            LOG_ERROR("Error: null trust anchor certificate.");
            return nullptr;
        }
        if (X509_STORE_add_cert(store.get(), anchor) != 1) {
            LOG_ERROR("Error: unable to add trust anchor to store: " << get_openssl_error());
            return nullptr;
        }
    }
    return store;
}

nv_unique_ptr<X509> x509_from_cert_string(const std::string &cert_string) {

    nv_unique_ptr<BIO> bio(BIO_new_mem_buf(cert_string.c_str(), (int)cert_string.size()));
    if(bio == nullptr) {
        LOG_ERROR("Could not load cert into BIO: " << get_openssl_error());
        return nullptr;
    }
    
    nv_unique_ptr<X509> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if(cert == nullptr) {
        // print openssl errors
        ERR_print_errors_fp(stderr);
        LOG_ERROR("Could not read cert from BIO: " << get_openssl_error());
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
        LOG_ERROR("Failed to create X509 from root_cert");
        return Error::InternalError;
    }

    trust_store = create_trust_store(root_cert.get());
    if (!trust_store) {
        LOG_ERROR("Failed to create trust store in X509CertChain::create.");
        return Error::InternalError;
    }
    
    out_cert_chain = X509CertChain(type, std::move(trust_store));
    return Error::Ok;
}

Error X509CertChain::set_root_cert(nv_unique_ptr<X509> root_cert) {
    if (!root_cert) {
        LOG_ERROR("Provided root certificate is null in X509CertChain::set_root_cert, trust store not updated.");
        return Error::InternalError;
    }

    nv_unique_ptr<X509_STORE> new_trust_store = create_trust_store(root_cert.get());
    if (!new_trust_store) {
        LOG_ERROR("Failed to create new trust store in X509CertChain::set_root_cert.");
        return Error::InternalError;
    }

    m_trust_store = std::move(new_trust_store);
    LOG_DEBUG("Successfully updated trust store in X509CertChain.");
    return Error::Ok;
}

Error X509CertChain::push_back(const std::string &cert_string) {
    nv_unique_ptr<X509> cert(x509_from_cert_string(cert_string));
    if(cert == nullptr) {
        LOG_ERROR("Error: unable to create X509 from cert string: " << get_openssl_error());
        return Error::InternalError;
    }
    m_certs.push_back(std::move(cert));
    return Error::Ok;
}

Error X509CertChain::get_leaf_public_key(nv_unique_ptr<EVP_PKEY>& out_pkey) const {
    if (m_certs.empty() || !m_certs[0]) {
        LOG_ERROR("Leaf certificate is null or chain is empty.");
        return Error::InternalError;
    }

    nv_unique_ptr<EVP_PKEY> pkey(X509_get_pubkey(m_certs[0].get()));
    if (!pkey) {
        LOG_ERROR("Failed to get public key from certificate: " << get_openssl_error());
        return Error::InternalError;
    }

    out_pkey = std::move(pkey);
    return Error::Ok;
}

Error X509CertChain::verify_signature(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& signature,
    const EVP_MD* md) {

    if (md == nullptr) {
        LOG_ERROR("Hash function is null.");
        return Error::InternalError;
    }

    nv_unique_ptr<EVP_PKEY> pkey;
    Error key_err = get_leaf_public_key(pkey);
    if (key_err != Error::Ok) {
        return key_err;
    }

    nv_unique_ptr<EVP_MD_CTX> md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        LOG_ERROR("Failed to create EVP_MD_CTX: " << get_openssl_error());
        return Error::InternalError;
    }

    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, md, nullptr, pkey.get()) != 1) {
        LOG_ERROR("EVP_DigestVerifyInit failed: " << get_openssl_error());
        return Error::InternalError;
    }

    // Provide the data to be hashed and verified.
    if (EVP_DigestVerifyUpdate(md_ctx.get(), data.data(), data.size()) != 1) {
        LOG_ERROR("EVP_DigestVerifyUpdate failed: " << get_openssl_error());
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
    LOG_ERROR("EVP_DigestVerifyFinal failed with error: " << get_openssl_error());
    return Error::InternalError;
}

Error X509CertChain::verify_signature_pkcs11(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& pkcs11_signature,
    const EVP_MD* md) {

    if (pkcs11_signature.size() % 2 != 0) {
        LOG_ERROR("PKCS#11 signature length must be even (R and S components of equal length).");
        return Error::InternalError;
    }

    size_t component_len = pkcs11_signature.size() / 2;

    nv_unique_ptr<BIGNUM> r_bignum(BN_new());
    nv_unique_ptr<BIGNUM> s_bignum(BN_new());
    if (!r_bignum || !s_bignum) {
        LOG_ERROR("Failed to allocate BIGNUM for R or S: " << get_openssl_error());
        return Error::InternalError;
    }

    if (BN_bin2bn(pkcs11_signature.data(), static_cast<int>(component_len), r_bignum.get()) == nullptr) {
        LOG_ERROR("Failed to convert R component to BIGNUM: " << get_openssl_error());
        return Error::InternalError;
    }
    if (BN_bin2bn(pkcs11_signature.data() + component_len, static_cast<int>(component_len), s_bignum.get()) == nullptr) {
        LOG_ERROR("Failed to convert S component to BIGNUM: " << get_openssl_error());
        return Error::InternalError;
    }

    nv_unique_ptr<ECDSA_SIG> ecdsa_sig(ECDSA_SIG_new());
    if (!ecdsa_sig) {
        LOG_ERROR("Failed to allocate ECDSA_SIG: " << get_openssl_error());
        return Error::InternalError;
    }

    // ECDSA_SIG_set0 takes ownership of r and s if successful.
    // We need to release our nv_unique_ptr ownership if the call is successful.
    if (ECDSA_SIG_set0(ecdsa_sig.get(), r_bignum.get(), s_bignum.get()) != 1) {
        LOG_ERROR("Failed to set R and S in ECDSA_SIG: " << get_openssl_error());
        // r_bignum and s_bignum are still managed by their nv_unique_ptr and will be freed.
        return Error::InternalError;
    }
    // Release ownership as ECDSA_SIG_set0 now owns r and s BIGNUMs
    (void)r_bignum.release(); 
    (void)s_bignum.release(); 


    int der_len = i2d_ECDSA_SIG(ecdsa_sig.get(), nullptr);
    if (der_len <= 0) {
        LOG_ERROR("Failed to get DER encoding length for ECDSA_SIG: " << get_openssl_error());
        return Error::InternalError;
    }

    std::vector<uint8_t> der_signature(der_len);
    unsigned char *ptr = der_signature.data();
    if (i2d_ECDSA_SIG(ecdsa_sig.get(), &ptr) <= 0) {
        LOG_ERROR("Failed to DER encode ECDSA_SIG: " << get_openssl_error());
        return Error::InternalError;
    }

    // Call the original verify_signature method with the DER encoded signature
    Error error = verify_signature(data, der_signature, md);
    return error;
}

Error X509CertChain::verify(bool allow_partial_chain) const {
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
        LOG_ERROR("No certs in chain");
        return Error::InternalError;
    }

    // Use the member trust store
    if (m_trust_store == nullptr) {
        LOG_ERROR("Trust store is not initialized. Cannot verify certificate chain.");
        return Error::InternalError;
    }
    
    nv_unique_ptr<X509_STORE_CTX> ctx(X509_STORE_CTX_new());
    if(ctx == nullptr) {
        LOG_ERROR("Error: unable to create X509_STORE_CTX" << get_openssl_error());
        return Error::InternalError;
    }

    // create stack of untrusted certs from m_certs, excluding the first one (that will be the target cert)
    // initialize stack of (x509)
    nv_unique_ptr<STACK_OF(X509)> untrusted_certs(sk_X509_new_null());
    if(untrusted_certs == nullptr) {
        LOG_ERROR("Error: unable to create STACK_OF(X509): " << get_openssl_error());
        return Error::InternalError;
    }

    for (size_t i = 1; i < m_certs.size(); i++) {
        if(sk_X509_push(untrusted_certs.get(), m_certs[i].get()) <= 0) {
            LOG_ERROR("Error: unable to push cert to stack: " << get_openssl_error());
            return Error::InternalError;
        }
    }
    
    
    if(X509_STORE_CTX_init(ctx.get(), m_trust_store.get(), m_certs[0].get(), untrusted_certs.get()) != 1) {
        LOG_ERROR("Error: X509_STORE_CTX_init failed: " << get_openssl_error());
        return Error::InternalError;
    }
    
    // Skip certificate expiration checks; optionally accept non-self-signed trust anchors
    X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx.get());
    if (param == nullptr) {
        LOG_ERROR("Error: X509_STORE_CTX_get0_param returned null: " << get_openssl_error());
        return Error::InternalError;
    }
    unsigned long flags = X509_V_FLAG_NO_CHECK_TIME;
    if (allow_partial_chain) {
        flags |= X509_V_FLAG_PARTIAL_CHAIN;
    }
    if (X509_VERIFY_PARAM_set_flags(param, flags) != 1) {
        LOG_ERROR("Error: X509_VERIFY_PARAM_set_flags failed: " << get_openssl_error());
        return Error::InternalError;
    }
    
    int ret = X509_verify_cert(ctx.get());
    if(ret != 1) {
        int err = X509_STORE_CTX_get_error(ctx.get());
        LOG_ERROR("Certificate chain verification failed: " 
                << X509_verify_cert_error_string(err));
        return Error::CertChainVerificationFailure;
    } 
    
    return Error::Ok;
}

Error X509CertChain::calculate_min_expiration_time(time_t& out_min_expiration_time, std::string* iso8601_time_out) const {
    if (m_certs.empty()) {
        LOG_ERROR("No certificates in chain to calculate expiration time");
        return Error::InternalError;
    }
    
    time_t min_expiration_time = std::numeric_limits<time_t>::max();
    bool valid_expiration_found = false;
    
    for (const auto& cert : m_certs) {
        if (cert == nullptr) {
            LOG_ERROR("Null certificate in chain");
            return Error::InternalError;
        }
        
        // Get the "not after" time from the certificate
        const ASN1_TIME* not_after = X509_get0_notAfter(cert.get());
        if (not_after == nullptr) {
            LOG_ERROR("Could not get expiration time from certificate");
            return Error::InternalError;
        }
        
        struct tm tm_expiration;
        if (ASN1_TIME_to_tm(not_after, &tm_expiration) != 1) {
            LOG_ERROR("Failed to convert ASN1_TIME to tm: " << get_openssl_error());
            return Error::InternalError;
        }
        
        time_t cert_expiration = timegm(&tm_expiration);
        if (cert_expiration < min_expiration_time) {
            min_expiration_time = cert_expiration;
            valid_expiration_found = true;
        }
    }
    
    if (!valid_expiration_found) {
        LOG_ERROR("Could not determine valid expiration time for the certificate chain");
        return Error::InternalError;
    }
    
    if (iso8601_time_out != nullptr) {
        Error fmt_err = format_time(min_expiration_time, *iso8601_time_out);
        if (fmt_err != Error::Ok) {
            return fmt_err;
        }
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
    out_cert_chain_claims.status = CertChainStatus::INVALID;

    // generate cert chain status claim
    if (min_expiration_time < time(nullptr)) {
        LOG_WARN("certificate chain has expired");
        out_cert_chain_claims.status = CertChainStatus::EXPIRED;
    } else {
        out_cert_chain_claims.status = CertChainStatus::VALID;
    }

    error = verify();
    if (error != Error::Ok) {
        return error;
    }

    OCSPClaims ocsp_claims;
    error = generate_ocsp_claims(ocsp_verify_options, ocsp_client, ocsp_claims);
    if (error != Error::Ok) {
        return error;
    }
    out_cert_chain_claims.ocsp_claims = ocsp_claims;
    

    return Error::Ok;
}


Error X509CertChain::collect_ocsp_responses(const OcspVerifyOptions& options, IOcspHttpClient& client,
                                             std::vector<std::pair<size_t, NvOcspResponse>>& out) const {
    if (!m_trust_store) {
        LOG_ERROR("Trust store is not initialized. Cannot collect OCSP responses.");
        return Error::InternalError;
    }

    int start_indx = 0;
    if (m_type == CertificateChainType::GPU_DEVICE_IDENTITY || m_type == CertificateChainType::NVSWITCH_DEVICE_IDENTITY) {
        start_indx = 1;
    }

    // Certs outside [start_indx, m_certs.size()-2] have no issuer in this
    // chain to check them against (the root, and — for chain types that
    // exclude it — the leaf). Emit a synthetic skipped response for each,
    // so callers record them as NOT_CHECKED through the same path as a
    // cert with no AIA responder, instead of leaving them silently absent.
    for (size_t idx = 0; idx < m_certs.size(); ++idx) {
        if (static_cast<int>(idx) >= start_indx &&
            static_cast<int>(idx) <= static_cast<int>(m_certs.size()) - 2) {
            continue;
        }
        NvOcspResponse not_applicable{};
        not_applicable.skipped = true;
        out.emplace_back(idx, not_applicable);
    }

    nv_unique_ptr<STACK_OF(X509)> ocsp_verify_intermediates(sk_X509_new_null());
    if (!ocsp_verify_intermediates) {
        LOG_ERROR("unable to create STACK_OF(X509) for ocsp_verify_intermediates: " << get_openssl_error());
        return Error::InternalError;
    }

    for (int subject_idx = (int)m_certs.size() - 2; subject_idx >= start_indx; --subject_idx) {
        LOG_DEBUG("Processing cert: subject_idx" << subject_idx << ". " << get_cert_subject_issuer_str(m_certs[subject_idx].get()));
        int issuer_idx = subject_idx + 1;

        NvOcspResponse ocsp_resp;
        Error error = client.get_ocsp_response(m_certs[subject_idx], m_certs[issuer_idx], ocsp_verify_intermediates, m_trust_store, ocsp_resp);
        if (error != Error::Ok) {
            return error;
        }

        out.emplace_back(static_cast<size_t>(subject_idx), ocsp_resp);

        if (sk_X509_insert(ocsp_verify_intermediates.get(), m_certs[subject_idx].get(), 0) <= 0) {
            LOG_ERROR("Failed to prepend certificate to intermediate stack for OCSP: " << get_openssl_error());
            return Error::InternalError;
        }
    }
    return Error::Ok;
}

Error X509CertChain::generate_ocsp_claims(const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, OCSPClaims& out_ocsp_claims) const { // NOLINT(readability-function-cognitive-complexity)
    LOG_DEBUG("Generating OCSP claims");

    out_ocsp_claims = OCSPClaims(OCSPStatus::UNDEFINED);
    bool claims_initialized = false;

    std::vector<std::pair<size_t, NvOcspResponse>> responses;
    Error error = collect_ocsp_responses(ocsp_verify_options, ocsp_client, responses);
    if (error != Error::Ok) {
        return error;
    }

    for (const auto& entry : responses) {
        const size_t subject_idx = entry.first;
        const NvOcspResponse& ocsp_resp = entry.second;
        if (ocsp_resp.skipped) {
            continue;
        }

        if (!ocsp_resp.response_valid) {
            LOG_WARN("OCSP response is invalid for cert: " << get_cert_subject_issuer_str(m_certs[subject_idx].get()));
        }
        if (!claims_initialized) {
            out_ocsp_claims.ocsp_response_valid = ocsp_resp.response_valid;
        } else {
            out_ocsp_claims.ocsp_response_valid = out_ocsp_claims.ocsp_response_valid && ocsp_resp.response_valid;
        }

        if (!claims_initialized) {
            out_ocsp_claims.nonce_matches = ocsp_resp.nonce_matches;
        } else {
            out_ocsp_claims.nonce_matches = out_ocsp_claims.nonce_matches && ocsp_resp.nonce_matches;
        }
        if (!ocsp_resp.nonce_matches) {
            LOG_WARN("OCSP nonce mismatch for cert: " << subject_idx << ": " << get_cert_subject_issuer_str(m_certs[subject_idx].get()));
        }

        LOG_DEBUG("OCSP status for cert: " << get_cert_subject_issuer_str(m_certs[subject_idx].get()) << " is: " << OCSP_cert_status_str(ocsp_resp.status));
        OCSPStatus mapped_status = OCSPStatus::UNDEFINED;
        switch (ocsp_resp.status) {
            case V_OCSP_CERTSTATUS_REVOKED:
                mapped_status = OCSPStatus::REVOKED;
                break;
            case V_OCSP_CERTSTATUS_GOOD:
                mapped_status = OCSPStatus::GOOD;
                break;
            case V_OCSP_CERTSTATUS_UNKNOWN:
                mapped_status = OCSPStatus::UNKOWN;
                break;
            default:
                mapped_status = OCSPStatus::UNDEFINED;
                break;
        }

        if (!claims_initialized) {
            out_ocsp_claims.status = mapped_status;
        } else {
            if (out_ocsp_claims.status == OCSPStatus::GOOD) {
                if (mapped_status == OCSPStatus::REVOKED) {
                    out_ocsp_claims.revocation_reason = std::make_shared<std::string>(OCSP_crl_reason_str(ocsp_resp.reason));
                }
                out_ocsp_claims.status = mapped_status;
            }
        }

        LOG_DEBUG("Generating expiration time claim");
        if (out_ocsp_claims.ocsp_resp_expiration_time == 0 || ocsp_resp.nextupd < out_ocsp_claims.ocsp_resp_expiration_time) {
            out_ocsp_claims.ocsp_resp_expiration_time = ocsp_resp.nextupd;
        }

        claims_initialized = true;
    }
    return Error::Ok;
}

bool all_certs_trusted(const std::vector<PerCertStatus>& chain) {
    // No ocsp data or NOT_CHECKED means not applicable. A genuinely failed
    // query must be marked ERROR by the caller, not left null.
    for (size_t i = 0; i < chain.size(); ++i) {
        const auto& cert = chain[i];
        if (cert.expired) {
            return false;
        }
        if (!cert.ocsp || cert.ocsp->crl_status == OCSPStatus::NOT_CHECKED) {
            continue;
        }
        if (cert.ocsp->crl_status != OCSPStatus::GOOD ||
            !cert.ocsp->nonce_matches || !cert.ocsp->response_valid) {
            return false;
        }
    }
    return true;
}

std::shared_ptr<PerCertStatus::OcspInfo> X509CertChain::build_ocsp_info(const NvOcspResponse& resp, time_t now) {
    auto info = std::make_shared<PerCertStatus::OcspInfo>();
    info->response_valid = resp.response_valid;
    info->nonce_matches = resp.nonce_matches;
    info->response_expired = (resp.nextupd > 0 && resp.nextupd < now);
    if (resp.nextupd > 0) {
        if (format_time(resp.nextupd, info->response_expiration_date) != Error::Ok) {
            LOG_WARN("Failed to format OCSP nextupd timestamp");
            info->response_expired = false;
        }
    }
    if (resp.producedat > 0) {
        if (format_time(resp.producedat, info->response_produced_at) != Error::Ok) {
            LOG_WARN("Failed to format OCSP producedat timestamp");
        }
    }

    switch (resp.status) {
        case V_OCSP_CERTSTATUS_GOOD:
            info->crl_status = OCSPStatus::GOOD;
            break;
        case V_OCSP_CERTSTATUS_REVOKED:
            info->crl_status = OCSPStatus::REVOKED;
            info->revocation_reason = std::make_shared<std::string>(OCSP_crl_reason_str(resp.reason));
            if (resp.revtime > 0 &&
                format_time(resp.revtime, info->response_revoked_at) != Error::Ok) {
                LOG_WARN("Failed to format OCSP revtime timestamp");
            }
            break;
        case V_OCSP_CERTSTATUS_UNKNOWN:
            info->crl_status = OCSPStatus::UNKOWN;
            break;
        default:
            info->crl_status = OCSPStatus::UNDEFINED;
            break;
    }
    return info;
}

Error X509CertChain::generate_per_cert_status(const OcspVerifyOptions& ocsp_options, IOcspHttpClient* ocsp_client,
                                               std::vector<PerCertStatus>& out_statuses) const {
    if (m_certs.empty()) {
        LOG_ERROR("No certificates in chain");
        return Error::InternalError;
    }

    time_t now = time(nullptr);
    out_statuses.resize(m_certs.size());

    for (size_t i = 0; i < m_certs.size(); ++i) {
        if (!m_certs[i]) {
            LOG_ERROR("Null certificate at index " << i);
            return Error::InternalError;
        }

        const ASN1_TIME* not_after = X509_get0_notAfter(m_certs[i].get());
        if (not_after == nullptr) {
            LOG_ERROR("Could not get expiration time from certificate at index " << i);
            return Error::InternalError;
        }

        struct tm tm_exp;
        if (ASN1_TIME_to_tm(not_after, &tm_exp) != 1) {
            LOG_ERROR("Failed to convert ASN1_TIME to tm: " << get_openssl_error());
            return Error::InternalError;
        }

        time_t cert_expiration = timegm(&tm_exp);
        if (format_time(cert_expiration, out_statuses[i].expiration_date) != Error::Ok) {
            LOG_ERROR("Failed to format cert expiration time at index " << i);
            return Error::InternalError;
        }
        out_statuses[i].expired = (cert_expiration < now);
        out_statuses[i].cert_check_status = out_statuses[i].expired ? CertChainStatus::EXPIRED : CertChainStatus::VALID;
    }

    // Output is root-first (L1 = root, Ln = leaf).
    std::reverse(out_statuses.begin(), out_statuses.end());

    if (ocsp_client == nullptr) {
        return Error::Ok;
    }

    std::vector<std::pair<size_t, NvOcspResponse>> responses;
    Error error = collect_ocsp_responses(ocsp_options, *ocsp_client, responses);

    for (const auto& entry : responses) {
        const size_t idx = entry.first;
        const NvOcspResponse& resp = entry.second;
        if (resp.skipped) {
            // Not applicable (e.g. cert has no AIA responder URL) — record
            // as NOT_CHECKED rather than leaving ocsp null, so
            // all_certs_trusted can tell this apart from a cert whose OCSP
            // query actually failed.
            auto skipped_info = std::make_shared<PerCertStatus::OcspInfo>();
            skipped_info->crl_status = OCSPStatus::NOT_CHECKED;
            out_statuses[m_certs.size() - 1 - idx].ocsp = std::move(skipped_info);
            continue;
        }

        auto info = build_ocsp_info(resp, now);
        if (resp.status == V_OCSP_CERTSTATUS_REVOKED) {
            out_statuses[m_certs.size() - 1 - idx].cert_check_status = CertChainStatus::REVOKED;
        }
        out_statuses[m_certs.size() - 1 - idx].ocsp = std::move(info);
    }

    if (error != Error::Ok) {
        // Query aborted partway (e.g. network error); mark every unreached
        // cert ERROR instead of leaving it null, so null means only "not
        // applicable" elsewhere.
        for (size_t i = 0; i < out_statuses.size(); ++i) {
            if (out_statuses[i].ocsp) {
                continue;
            }
            auto error_info = std::make_shared<PerCertStatus::OcspInfo>();
            error_info->crl_status = OCSPStatus::ERROR;
            out_statuses[i].ocsp = std::move(error_info);
        }
        return error;
    }

    return Error::Ok;
}
size_t X509CertChain::size() const {
    return m_certs.size();
}

Error X509CertChain::append_pem_chain(const std::string& cert_chain) {
    // Split PEM chain into individual certificates and add them to m_certs
    const std::string delimiter = "-----END CERTIFICATE-----";
    size_t start = 0;
    while (true) {
        size_t end = cert_chain.find(delimiter, start);
        if (end == std::string::npos) {
            break;
        }
        size_t cert_end = end + delimiter.length();
        std::string cert_str = cert_chain.substr(start, cert_end - start);

        Error error = push_back(cert_str);
        if (error != Error::Ok) {
            LOG_ERROR("Failed to add parsed certificate to chain");
            return Error::InternalError;
        }

        start = cert_end;
        while (start < cert_chain.size() && (cert_chain[start] == '\n' || cert_chain[start] == '\r')) {
            ++start;
        }
    }
    if (size() == 0) {
            LOG_ERROR("No certificate chain available after parsing");
            return Error::InternalError;
    }
    return Error::Ok;
}

Error X509CertChain::create_from_cert_chain_str(
    CertificateChainType type,
    const std::string& root_cert_str,
    const std::string& cert_chain,
    X509CertChain& out_cert_chain
    )
{
    if (cert_chain.empty()) {
        LOG_ERROR("Input PEM chain string is empty");
        return Error::InternalError;
    }

    Error error = X509CertChain::create(type, root_cert_str, out_cert_chain);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to create X509CertChain");
        return error;
    }
    return out_cert_chain.append_pem_chain(cert_chain);
}

Error X509CertChain::create_from_cert_chain_str(
    CertificateChainType type,
    nv_unique_ptr<X509_STORE> trust_store,
    const std::string& cert_chain,
    X509CertChain& out_cert_chain
    )
{
    if (cert_chain.empty()) {
        LOG_ERROR("Input PEM chain string is empty");
        return Error::InternalError;
    }
    if (!trust_store) {
        LOG_ERROR("Provided trust store is null");
        return Error::InternalError;
    }
    out_cert_chain = X509CertChain(type, std::move(trust_store));
    return out_cert_chain.append_pem_chain(cert_chain);
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
    int length_int = ASN1_STRING_length(octet_str);

    if (data == nullptr || length_int <= 0) {
        LOG_ERROR("FWID extension data is empty or invalid.");
        return Error::InternalError;
    }
    size_t length = static_cast<size_t>(length_int);

    if (length < X509CertChain::m_fwid_hash_length) {
        LOG_ERROR("FWID extension data is too short for SHA384 hash (need atleast " << X509CertChain::m_fwid_hash_length << " bytes, got " << length << " bytes).");
        return Error::InternalError;
    }

    if (fwid_type == FWIDType::FWID_2_23_133_5_4_1) {
        // OID 2.23.133.5.4.1 is ambiguous: it may contain either a DiceTcbInfo structure
        // (newer devices, 3rd-party) or the legacy CompositeDeviceID structure (Hopper/GH100).
        // Try DiceTcbInfo first, then CompositeDeviceId, then raw tail-byte extraction.
        Error err = get_fwid_2_23_133_5_4_1_1(data, length, out_fwid, /*silent=*/true);
        if (err == Error::Ok) {
            return Error::Ok;
        }
        LOG_DEBUG("OID 2.23.133.5.4.1 did not parse as DiceTcbInfo, trying CompositeDeviceId");
        std::vector<uint8_t> der_vec(data, data + length);
        CompositeDeviceId composite;
        err = CompositeDeviceId::parse_from_der(der_vec, composite);
        if (err == Error::Ok) {
            out_fwid = composite.fwid().digest();
            return Error::Ok;
        }
        // Final fallback: extract last m_fwid_hash_length bytes as raw digest.
        // Some legacy devices and test certs store raw FWID bytes without proper ASN.1 wrapping.
        LOG_DEBUG("OID 2.23.133.5.4.1 did not parse as CompositeDeviceId either, using raw tail bytes");
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

Error X509CertChain::get_fwid_2_23_133_5_4_1_1(const unsigned char* extension_data, unsigned int length, std::vector<uint8_t>& out_fwid, bool silent) {
    // Delegate to the DiceTcbInfo parser for proper ASN.1 parsing of the 2.23.133.5.4.1.1 extension
    std::vector<uint8_t> der(extension_data, extension_data + length);
    DiceTcbInfo info;
    Error err = DiceTcbInfo::parse_from_der(der, info, silent);
    if (err != Error::Ok) {
        return err;
    }
    return info.get_first_fwid_digest(out_fwid);
}

Error X509CertChain::get_dice_tcb_info(size_t cert_index, const std::string& oid, DiceTcbInfo& out_dice_tcb_info,
                                       bool silent) const {
    if (cert_index >= m_certs.size()) {
        LOG_ERROR("Certificate index " << cert_index << " out of bounds. Chain size: " << m_certs.size());
        return Error::CertNotFound;
    }

    const X509* cert = m_certs[cert_index].get();
    if (cert == nullptr) {
        LOG_ERROR("Certificate at index " << cert_index << " is null.");
        return Error::CertNotFound;
    }

    return DiceTcbInfo::parse_from_x509_extension(cert, oid, out_dice_tcb_info, silent);
}

Error X509CertChain::get_multi_dice_tcb_info(size_t cert_index, MultiDiceTcbInfo& out_multi_dice_tcb_info,
                                             bool silent) const {
    if (cert_index >= m_certs.size()) {
        LOG_ERROR("Certificate index " << cert_index << " out of bounds. Chain size: " << m_certs.size());
        return Error::CertNotFound;
    }

    const X509* cert = m_certs[cert_index].get();
    if (cert == nullptr) {
        LOG_ERROR("Certificate at index " << cert_index << " is null.");
        return Error::CertNotFound;
    }

    return MultiDiceTcbInfo::parse_from_x509_extension(cert, out_multi_dice_tcb_info, silent);
}

Error X509CertChain::get_dice_ueid(size_t cert_index, std::vector<uint8_t>& out_ueid, bool silent) const {
    if (cert_index >= m_certs.size()) {
        LOG_ERROR("Certificate index " << cert_index << " out of bounds. Chain size: " << m_certs.size());
        return Error::CertFwidNotFound;
    }
    const X509* cert = m_certs[cert_index].get();
    if (cert == nullptr) {
        LOG_ERROR("Certificate at index " << cert_index << " is null.");
        return Error::CertFwidNotFound;
    }
    return parse_dice_ueid_from_x509_extension(cert, out_ueid, silent);
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

Error X509CertChain::get_subject_cn(std::size_t cert_index, std::string& out_cn) const {
    if (cert_index >= m_certs.size()) {
        LOG_ERROR("Certificate index " << cert_index << " out of bounds. Chain size: " << m_certs.size());
        return Error::CertNotFound;
    }

    const X509* cert = m_certs[cert_index].get();
    if (cert == nullptr) {
        LOG_ERROR("Certificate at index " << cert_index << " is null.");
        return Error::CertNotFound;
    }

    X509_NAME* subject_name = X509_get_subject_name(cert);
    if (subject_name == nullptr) {
        LOG_ERROR("Failed to get subject name from certificate at index " << cert_index << ": " << get_openssl_error());
        return Error::InternalError;
    }

    int lastpos = -1;
    int cn_index = X509_NAME_get_index_by_NID(subject_name, NID_commonName, lastpos);
    if (cn_index < 0) {
        LOG_ERROR("Common name (CN) not found in certificate at index " << cert_index);
        return Error::InternalError;
    }

    X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(subject_name, cn_index);
    if (cn_entry == nullptr) {
        LOG_ERROR("Failed to get common name entry from certificate at index " << cert_index << ": " << get_openssl_error());
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

    out_cn = std::string(reinterpret_cast<const char*>(cn_data), cn_length);
    return Error::Ok;
}

Error X509CertChain::get_cert_serial(size_t cert_index, std::string& out_serial) const {
    if (cert_index >= m_certs.size()) {
        LOG_ERROR("Certificate index " << cert_index
                  << " is out of bounds. Chain size: " << m_certs.size());
        return Error::CertNotFound;
    }

    const X509* cert = m_certs[cert_index].get();
    if (cert == nullptr) {
        LOG_ERROR("Certificate at index " << cert_index << " is null.");
        return Error::CertNotFound;
    }

    // Get the serial number from the certificate
    const ASN1_INTEGER* serial_asn1 = X509_get0_serialNumber(cert);
    if (serial_asn1 == nullptr) {
        LOG_ERROR("Failed to get serial number from certificate at index "
                  << cert_index << ": " << get_openssl_error());
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
    out_serial = std::string(dec_str);

    // Free the allocated string from OpenSSL
    OPENSSL_free(dec_str);

    return Error::Ok;
}

Error X509CertChain::get_end_entity_serial(std::string& out_serial) const {
    return get_cert_serial(0, out_serial);
}

// DMTF device-info otherName; the SPDM device certificate profile carries
// "<manufacturer>:<product>:<serial>" under this OID.
static const char* const kDmtfDeviceInfoOid = "1.3.6.1.4.1.412.274.1";

Error parse_dmtf_device_info(const std::string& device_info,
                             DmtfDeviceInfo& out_info) {
    const size_t kDmtfFieldSeparators = 2;
    if (std::count(device_info.begin(), device_info.end(), ':') !=
        static_cast<long>(kDmtfFieldSeparators)) {
        LOG_ERROR("DMTF device info is not <manufacturer>:<product>:<serial>");
        return Error::BadArgument;
    }
    const size_t first = device_info.find(':');
    const size_t last = device_info.rfind(':');
    DmtfDeviceInfo info;
    info.manufacturer = device_info.substr(0, first);
    info.product = device_info.substr(first + 1, last - first - 1);
    info.serial = device_info.substr(last + 1);
    if (info.serial.empty()) {
        LOG_ERROR("DMTF device info carries an empty serial");
        return Error::BadArgument;
    }
    out_info = std::move(info);
    return Error::Ok;
}

Error X509CertChain::get_end_entity_dmtf_device_info(DmtfDeviceInfo& out_info) const {
    if (m_certs.empty() || !m_certs[0]) {
        LOG_ERROR("Leaf certificate is null or chain is empty.");
        return Error::CertNotFound;
    }

    nv_unique_ptr<GENERAL_NAMES> names(static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(m_certs[0].get(), NID_subject_alt_name, nullptr, nullptr)));
    if (!names) {
        LOG_DEBUG("End-entity certificate has no SubjectAlternativeName");
        return Error::CertNotFound;
    }

    const int name_count = sk_GENERAL_NAME_num(names.get());
    for (int i = 0; i < name_count; ++i) {
        const GENERAL_NAME* gen_name = sk_GENERAL_NAME_value(names.get(), i);
        if (gen_name == nullptr || gen_name->type != GEN_OTHERNAME ||
            gen_name->d.otherName == nullptr) {
            continue;
        }

        const size_t oid_buf_len = 128;
        char oid[oid_buf_len] = {0};
        if (OBJ_obj2txt(oid, oid_buf_len, gen_name->d.otherName->type_id,
                        /*no_name=*/1) <= 0) {
            continue;
        }
        if (std::string(oid) != kDmtfDeviceInfoOid) {
            continue;
        }

        const ASN1_TYPE* value = gen_name->d.otherName->value;
        if (value == nullptr) {
            continue;
        }
        // ASN1_TYPE::value is a union; for a non-string type it holds an int,
        // which would be read as a pointer below.
        if (value->type != V_ASN1_UTF8STRING &&
            value->type != V_ASN1_IA5STRING &&
            value->type != V_ASN1_PRINTABLESTRING) {
            LOG_DEBUG("DMTF otherName is not a string type");
            continue;
        }
        if (value->value.asn1_string == nullptr) {
            continue;
        }
        const ASN1_STRING* str = value->value.asn1_string;
        const unsigned char* data = ASN1_STRING_get0_data(str);
        const int len = ASN1_STRING_length(str);
        if (data == nullptr || len <= 0) {
            continue;
        }
        const std::string device_info(reinterpret_cast<const char*>(data),
                                      static_cast<size_t>(len));

        // DSP0274 §330 fixes the layout; anything else is malformed.
        return parse_dmtf_device_info(device_info, out_info);
    }

    LOG_DEBUG("End-entity certificate has no DMTF otherName");
    return Error::CertNotFound;
}

Error X509CertChain::get_end_entity_public_key_pem(std::string& out_pem) const {
    nv_unique_ptr<EVP_PKEY> pkey;
    Error key_err = get_leaf_public_key(pkey);
    if (key_err != Error::Ok) {
        return key_err;
    }

    nv_unique_ptr<BIO> bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        LOG_ERROR("Failed to create BIO: " << get_openssl_error());
        return Error::InternalError;
    }

    if (PEM_write_bio_PUBKEY(bio.get(), pkey.get()) != 1) {
        LOG_ERROR("Failed to write public key to PEM: " << get_openssl_error());
        return Error::InternalError;
    }

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio.get(), &bptr);
    if (bptr == nullptr || bptr->data == nullptr) {
        LOG_ERROR("Failed to read PEM public key from BIO");
        return Error::InternalError;
    }
    out_pem = std::string(bptr->data, bptr->length);
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
