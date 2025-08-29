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

namespace nvattestation {

/**
 * @brief Creates an X509 object from a certificate file path.
 * @param path The file path to the certificate.
 * @return A unique pointer to the X509 object, or nullptr on error.
 */
nv_unique_ptr<X509> x509_from_cert_path(const std::string &path);

/**
 * @brief Creates an X509_STORE from a trust anchor certificate.
 * @param trust_anchor_cert Pointer to the X509 trust anchor certificate.
 * @return A unique pointer to the X509_STORE, or nullptr on error.
 */
nv_unique_ptr<X509_STORE> create_trust_store(X509* trust_anchor_cert);

/**
 * @brief Creates an X509 object from a certificate string.
 * @param cert_string The certificate string.
 * @return A unique pointer to the X509 object, or nullptr on error.
 */
nv_unique_ptr<X509> x509_from_cert_string(const std::string &cert_string);

enum class CertificateChainType {
    GPU_DEVICE_IDENTITY,
    GPU_VBIOS_RIM,
    GPU_DRIVER_RIM,
    NVSWITCH_DEVICE_IDENTITY,
    NVSWITCH_VBIOS_RIM,
};

enum class OCSPStatus {
    GOOD = 0,
    REVOKED,
    UNKOWN,
    UNDEFINED
};

inline std::string to_string(OCSPStatus status) {
    switch (status) {
        case OCSPStatus::GOOD:
            return "good";
        case OCSPStatus::REVOKED:
            return "revoked";
        case OCSPStatus::UNKOWN:
            return "unknown";
        case OCSPStatus::UNDEFINED:
            return "undefined";
        default:
            return "unknown";
    }
}

struct OCSPClaims {
    /**
     * "good" if ocsp responder status is "good" for all certs in the chain. otherwise "revoked" or "unknown"
     */
    OCSPStatus status;
    /**
     * will be "" if status is "good"
     * will be the string representation of the reason for revocation if status is "revoked"
     * the string value is obtained using OCSP_crl_reason_str()
     */
    std::shared_ptr<std::string> revocation_reason;
    /**
     * will be true if nonce is valid for all certs in the chain.
     * will be false if nonce is not valid for any of the certs in the chain 
     * or if any of the certs 
     * status is not "good"
     */
    bool nonce_matches;
    /**
     * expiration time of the ocsp response of the last cert in the chain.
     */
    time_t ocsp_resp_expiration_time;

    OCSPClaims(OCSPStatus status, const std::string& reason, bool nonce_matches, time_t ocsp_resp_expiration_time) : status(status), revocation_reason(std::make_shared<std::string>(reason)), nonce_matches(nonce_matches), ocsp_resp_expiration_time(ocsp_resp_expiration_time) {}
    OCSPClaims() : status(OCSPStatus::UNDEFINED), revocation_reason(nullptr), nonce_matches(false), ocsp_resp_expiration_time(0) {}
};

std::ostream& operator<<(std::ostream& os, const OCSPClaims& claims) ;

enum class CertChainStatus {
    VALID = 0,
    INVALID,
    REVOKED,
    EXPIRED
};

// Helper function to convert CertChainStatus enum to string
inline std::string to_string(CertChainStatus status) {
    switch (status) {
        case CertChainStatus::VALID:
            return "valid";
        case CertChainStatus::INVALID:
            return "invalid";
        case CertChainStatus::REVOKED:
            return "revoked";
        case CertChainStatus::EXPIRED:
            return "expired";
        default:
            return "unknown";
    }
}
struct CertChainClaims {
    std::string expiration_date;
    CertChainStatus status;
    OCSPClaims ocsp_claims;
};

std::ostream& operator<<(std::ostream& os, const CertChainClaims& claims);

/**
 * @brief Interface for an OCSP HTTP client.
 * This allows for mocking the HTTP transfer part of OCSP requests during testing.
 */
class IOcspHttpClient {
public:
    virtual ~IOcspHttpClient() = default;

    IOcspHttpClient() = default;

    /**
     * @brief Performs the HTTP transfer for an OCSP request with retry logic and response processing.
     *
     * @param req_bio The BIO containing the serialized OCSP request.
     * @param out_ocsp_resp Output parameter for the successfully parsed OCSP response.
     * @return Error code indicating the result of the operation.
     */
    virtual Error transfer_ocsp_request(
        BIO* req_bio,
        nv_unique_ptr<OCSP_RESPONSE>& out_ocsp_resp
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

    Error transfer_ocsp_request(
        BIO* req_bio,
        nv_unique_ptr<OCSP_RESPONSE>& out_ocsp_resp
    ) override;

    static Error create(
        NvHttpOcspClient& out_client,
        const std::string& base_url,
        HttpOptions http_options
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
        const char * base_url = nullptr,
        HttpOptions http_options = HttpOptions()
    );

private:
    HttpOptions m_http_options;
    std::string m_ocsp_url;
    NvHttpClient m_http_client;
};

class X509CertChain{
    private:
        std::vector<nv_unique_ptr<X509>> m_certs;
        CertificateChainType m_type;
        nv_unique_ptr<X509_STORE> m_trust_store;
        // fwid is 48 bytes long
        static const size_t m_fwid_hash_length = 48;
        // Private constructor
        static Error get_fwid_2_23_133_5_4_1_1(const unsigned char* extension_data, unsigned int length, std::vector<uint8_t>& out_fwid);

    public:
        static const std::string kFwidOid;

        X509CertChain(CertificateChainType type, nv_unique_ptr<X509_STORE> trust_store);
        X509CertChain() = default;
        // Static factory method
        static Error create(CertificateChainType type, const std::string& root_cert_str, X509CertChain& out_cert_chain);
        static Error create_from_cert_chain_str(CertificateChainType type, const std::string& root_cert_str, const std::string& cert_chain, X509CertChain& out_cert_chain);

        Error set_root_cert(nv_unique_ptr<X509> root_cert);
        Error push_back(const std::string &cert_string);
        
        Error verify() const;
        Error generate_cert_chain_claims(const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, CertChainClaims& out_cert_chain_claims) const;
        Error generate_ocsp_claims(const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, OCSPClaims& out_ocsp_claims) const;
        
        /**
         * @brief Calculate the minimum expiration time across all certificates in the chain
         * @param iso8601_time_out Output parameter for ISO8601 formatted time string
         * @return A unique pointer to a time_t value representing the minimum expiration time
         */
        Error calculate_min_expiration_time(time_t& out_min_expiration_time, std::string* iso8601_time_out = nullptr) const;
        size_t size() const;

        /**
         * @brief Verifies the signature of data using the leaf certificate in the chain and a given hash algorithm.
         * signature is expected to be in DER-encoded ASN.1 format.
         * 
         * @param data The data whose signature is to be verified.
         * @param signature The signature to verify.
         * @param md The EVP_MD (message digest) structure representing the hash algorithm (e.g., EVP_sha256()).
         * @return Error::Ok if the signature is valid, Error::InternalError if invalid.
         */
        Error verify_signature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const EVP_MD* md);

        /**
         * @brief Verifies a PKCS#11 style (fixed-length R||S) ECDSA signature of data using the leaf certificate and a given hash algorithm.
         * 
         * This method converts the PKCS#11 style signature to the DER-encoded ASN.1 format expected by OpenSSL 
         * before calling the standard verify_signature method.
         * 
         * @param data The data whose signature is to be verified.
         * @param pkcs11_signature The PKCS#11 style (concatenated R and S components) ECDSA signature.
         * @param md The EVP_MD (message digest) structure representing the hash algorithm (e.g., EVP_sha256()).
         * @return Error::Ok if the signature is valid, Error::InternalError if invalid.
         */
        Error verify_signature_pkcs11(const std::vector<uint8_t>& data, const std::vector<uint8_t>& pkcs11_signature, const EVP_MD* md);

        enum class FWIDType {
            FWID_2_23_133_5_4_1,
            FWID_2_23_133_5_4_1_1
        };

        static std::string to_string(FWIDType fwid_type);
        /**
         * @brief Extracts FWID (Firmware Identifier) from a certificate extension.
         * 
         * Process Flow:
         * - Certificate Access: The method accesses a specific certificate from the chain using the provided index.
         * - OID Preparation: The hardcoded FWID OID ("2.23.133.5.4.1") is converted to OpenSSL's internal ASN.1 object representation.
         * - Extension Search: OpenSSL searches through all extensions in the certificate looking for one with the matching OID.
         * - Data Extraction: Once found, the extension's data is extracted. Certificate extensions store their data as ASN.1 OCTET STRINGs, so the method extracts the raw bytes from this structure.
         * - Output: The raw FWID bytes are copied into the output vector.
         * 
         * @param cert_index Index of the certificate in the chain to extract FWID from.
         * @param out_fwid Output vector to store the extracted FWID bytes.
         * @return Error::Ok on success, Error::CertNotFound if certificate not found, Error::CertFwidNotFound if FWID extension not found.
         */
        Error get_fwid(size_t cert_index, FWIDType fwid_type, std::vector<uint8_t>& out_fwid) const;

};
}