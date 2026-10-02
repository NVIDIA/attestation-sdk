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
#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/dice_tcb_info.h"

namespace nvattestation {

// DMTF device-info fields from a certificate's SubjectAltName otherName.
struct DmtfDeviceInfo {
    std::string manufacturer;
    std::string product;
    std::string serial;
};

// DSP0274 §330 fixes the value at exactly "<manufacturer>:<product>:<serial>",
// with no colon inside a field; anything else is Error::BadArgument.
Error parse_dmtf_device_info(const std::string& device_info,
                             DmtfDeviceInfo& out_info);

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
 * @brief Creates an X509_STORE holding multiple trust anchors. A chain
 *        verified against it anchors if it roots to any one of them.
 * @param trust_anchor_certs The trust anchor certificates.
 * @return A unique pointer to the X509_STORE, or nullptr on error (including
 *         an empty input).
 */
nv_unique_ptr<X509_STORE> create_trust_store(const std::vector<X509*>& trust_anchor_certs);

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
    GENERIC,
};

enum class OCSPStatus {
    UNDEFINED = -1,
    GOOD = 0,
    REVOKED = 1,
    UNKOWN = 2,
    NOT_CHECKED = 3,
    ERROR = 4,
};

inline std::string to_string(OCSPStatus status) {
    switch (status) {
        case OCSPStatus::GOOD:
            return "good";
        case OCSPStatus::REVOKED:
            return "revoked";
        case OCSPStatus::UNKOWN:
            return "unknown";
        case OCSPStatus::NOT_CHECKED:
            return "not_checked";
        case OCSPStatus::ERROR:
            return "error";
        case OCSPStatus::UNDEFINED:
            return "undefined";
        default:
            return "undefined";
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
    /**
     * will be true if the ocsp response is valid for all certs in the chain, else false
     */
    bool ocsp_response_valid;


    OCSPClaims(OCSPStatus status, const std::string& reason, bool nonce_matches, time_t ocsp_resp_expiration_time) : status(status), revocation_reason(std::make_shared<std::string>(reason)), nonce_matches(nonce_matches), ocsp_resp_expiration_time(ocsp_resp_expiration_time) {}
    OCSPClaims() : status(OCSPStatus::NOT_CHECKED), revocation_reason(nullptr), nonce_matches(false), ocsp_resp_expiration_time(0), ocsp_response_valid(false) {}
    explicit OCSPClaims(OCSPStatus s) : OCSPClaims() { status = s; }
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

struct PerCertStatus {
    std::string expiration_date;
    bool expired = false;
    CertChainStatus cert_check_status = CertChainStatus::VALID;

    struct OcspInfo {
        bool response_valid = false;
        OCSPStatus crl_status = OCSPStatus::UNDEFINED;
        std::shared_ptr<std::string> revocation_reason;
        bool nonce_matches = false;
        bool response_expired = false;
        std::string response_expiration_date;
        std::string response_produced_at;
        // Set only when crl_status == REVOKED.
        std::string response_revoked_at;
    };
    std::shared_ptr<OcspInfo> ocsp;
};

// True only if every cert is unexpired and, when it has a known OCSP
// status, that status is GOOD with a matching nonce and valid response.
// No data or NOT_CHECKED is treated as not applicable.
bool all_certs_trusted(const std::vector<PerCertStatus>& chain);

class X509CertChain{
    private:
        std::vector<nv_unique_ptr<X509>> m_certs;
        CertificateChainType m_type;
        nv_unique_ptr<X509_STORE> m_trust_store;
        // fwid is 48 bytes long
        static const size_t m_fwid_hash_length = 48;
        // Private constructor
        static Error get_fwid_2_23_133_5_4_1_1(const unsigned char* extension_data, unsigned int length, std::vector<uint8_t>& out_fwid, bool silent = false);
        // Split a PEM chain string and push each certificate onto this chain.
        Error append_pem_chain(const std::string& cert_chain);
        // Shared by signature verification and get_end_entity_public_key_pem(),
        // so the exported key is the one signatures are checked against.
        Error get_leaf_public_key(nv_unique_ptr<EVP_PKEY>& out_pkey) const;
        // Raw per-cert OCSP collection shared by generate_ocsp_claims and generate_per_cert_status.
        Error collect_ocsp_responses(const OcspVerifyOptions& options, IOcspHttpClient& client,
                                     std::vector<std::pair<size_t, NvOcspResponse>>& out) const;
        // Maps one cert's raw OCSP response into its PerCertStatus::OcspInfo.
        static std::shared_ptr<PerCertStatus::OcspInfo> build_ocsp_info(const NvOcspResponse& resp, time_t now);

    public:
        static const std::string kFwidOid;

        X509CertChain(CertificateChainType type, nv_unique_ptr<X509_STORE> trust_store);
        X509CertChain() = default;
        // Static factory method
        static Error create(CertificateChainType type, const std::string& root_cert_str, X509CertChain& out_cert_chain);
        static Error create_from_cert_chain_str(CertificateChainType type, const std::string& root_cert_str, const std::string& cert_chain, X509CertChain& out_cert_chain);
        // Uses a caller-supplied (possibly multi-anchor) trust store instead of a single root string.
        static Error create_from_cert_chain_str(CertificateChainType type, nv_unique_ptr<X509_STORE> trust_store, const std::string& cert_chain, X509CertChain& out_cert_chain);

        Error set_root_cert(nv_unique_ptr<X509> root_cert);
        Error push_back(const std::string &cert_string);
        
        Error verify(bool allow_partial_chain = false) const;
        Error generate_cert_chain_claims(const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, CertChainClaims& out_cert_chain_claims) const;
        Error generate_ocsp_claims(const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, OCSPClaims& out_ocsp_claims) const;
        Error generate_per_cert_status(const OcspVerifyOptions& ocsp_options, IOcspHttpClient* ocsp_client,
                                       std::vector<PerCertStatus>& out_statuses) const;
        
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

        /**
         * @brief Extracts the common name from the first certificate in the chain.
         * This is applicable for only GPU certificate chains. It is used to generate
         * the hwmodel claim.
         */
        Error get_hwmodel(std::string& out_hwmodel) const;
        // Subject CN of the certificate at cert_index. Generic version of
        // the extraction get_hwmodel() does for a hardcoded index.
        Error get_subject_cn(std::size_t cert_index, std::string& out_cn) const;
        /**
         * @brief Extracts the serial number of the certificate at @p cert_index
         * as a decimal string.
         */
        Error get_cert_serial(size_t cert_index, std::string& out_serial) const;

        /**
         * @brief Extracts the serial number of the end-entity certificate
         * (index 0) as a decimal string.
         * The ueid claim for GPU and NVSwitch evidence is derived from this value.
         */
        Error get_end_entity_serial(std::string& out_serial) const;

        /**
         * @brief Extracts the SubjectPublicKeyInfo of the end-entity
         * certificate (index 0) as a PEM-encoded public key.
         * This is the key verify_signature_pkcs11() verifies against.
         */
        Error get_end_entity_public_key_pem(std::string& out_pem) const;

        /**
         * @brief Extracts the DMTF device info from the end-entity
         * certificate's SubjectAlternativeName otherName carrying the DMTF OID
         * 1.3.6.1.4.1.412.274.1.
         * Returns Error::CertNotFound when no such otherName is present.
         */
        Error get_end_entity_dmtf_device_info(DmtfDeviceInfo& out_info) const;

        /**
         * @brief Extracts and parses a DiceTcbInfo extension from a certificate in the chain.
         * @param cert_index Index of the certificate in the chain.
         * @param oid The OID of the DiceTcbInfo extension to parse (e.g., OID_TCG_DICE_TCB_INFO_ALIAS).
         * @param out_dice_tcb_info Output parameter for the parsed DiceTcbInfo.
         * @return Error::Ok on success.
         */
        Error get_dice_tcb_info(size_t cert_index, const std::string& oid, DiceTcbInfo& out_dice_tcb_info,
                                bool silent = false) const;

        /**
         * @brief Extracts and parses a MultiDiceTcbInfo extension from a certificate in the chain.
         * @param cert_index Index of the certificate in the chain.
         * @param out_multi_dice_tcb_info Output parameter for the parsed MultiDiceTcbInfo.
         * @return Error::Ok on success.
         */
        Error get_multi_dice_tcb_info(size_t cert_index, MultiDiceTcbInfo& out_multi_dice_tcb_info,
                                      bool silent = false) const;

        /**
         * @brief Extract DiceUeid (OID 2.23.133.5.4.4) octets from the cert at `cert_index`.
         * Returns raw UEID bytes (the inner OCTET STRING content), or Error::CertFwidNotFound
         * if the extension is absent.
         */
        Error get_dice_ueid(size_t cert_index, std::vector<uint8_t>& out_ueid,
                            bool silent = false) const;

};
}
