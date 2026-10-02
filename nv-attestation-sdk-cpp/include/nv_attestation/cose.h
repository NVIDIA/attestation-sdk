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

#include <string>
#include <vector>
#include <cstdint>

#include "nv_attestation/error.h"
#include "nv_attestation/verify.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/nv_ocsp.h"

namespace nvattestation {

/**
 * COSE header label constants per RFC 9052 and RFC 9360
 */
namespace cose {
    // Common Header Parameters (RFC 9052)
    constexpr int64_t HEADER_ALG = 1;

    // X.509 Header Parameters (RFC 9360)
    constexpr int64_t HEADER_X5CHAIN = 33;
    constexpr int64_t HEADER_X5T = 34;

    // Algorithm identifiers (RFC 9053)
    constexpr int64_t ALG_ES384 = -35;  // ECDSA w/ SHA-384

    // Hash algorithm identifiers for x5t (RFC 9053)
    constexpr int64_t HASH_SHA256 = -16;
    constexpr int64_t HASH_SHA384 = -43;
    constexpr int64_t HASH_SHA512 = -44;
}

/**
 * @brief Decoded fields of a COSE_Sign1, prior to any verification.
 */
struct CoseSign1Components {
    std::vector<uint8_t> protected_header_bytes;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> signature;
    int64_t alg = 0;
    bool has_alg = false;
    std::vector<std::vector<uint8_t>> x5chain;
    bool x5chain_in_protected = false;
    int64_t x5t_hash_alg = 0;
    std::vector<uint8_t> x5t_thumbprint;
    bool has_x5t = false;
};

/**
 * @brief Options for verifying a COSE_Sign1 structure.
 */
struct CoseSign1VerifyOptions {
    /**
     * Whether to perform OCSP revocation checking on the certificate chain.
     */
    bool verify_ocsp = true;

    /**
     * OCSP verification options (used if verify_ocsp is true).
     */
    OcspVerifyOptions ocsp_options;

    /**
     * PEM-encoded root certificate to use as the trust anchor for chain validation.
     * This must be provided for certificate chain verification.
     */
    std::string root_cert_pem;
};

/**
 * @brief Result of COSE_Sign1 verification.
 */
struct CoseSign1Result {
    /**
     * The raw payload bytes extracted from the COSE_Sign1 structure.
     * The caller is responsible for interpreting the payload format.
     */
    std::vector<uint8_t> payload;

    /**
     * Per-cert status for every certificate in the signing chain.
     * Only populated if certificate chain verification was performed.
     */
    std::vector<PerCertStatus> cert_chain_claims;
};

/**
 * @brief Extracts the payload from a COSE_Sign1 structure without verifying the signature.
 *
 * @param cose_sign1_bytes The raw CBOR-encoded COSE_Sign1 bytes (must begin with tag #6.18).
 * @param out_payload Output parameter for the extracted payload bytes.
 * @return Error::Ok on success, Error::BadArgument if not a COSE_Sign1 structure.
 */
Error extract_cose_sign1_payload(
    const std::vector<uint8_t>& cose_sign1_bytes,
    std::vector<uint8_t>& out_payload
);

/**
 * @brief Decodes a tag #6.18 COSE_Sign1 into its component fields, without
 *        verifying the signature or resolving the signing chain.
 */
Error decode_cose_sign1(
    const std::vector<uint8_t>& cose_sign1_bytes,
    CoseSign1Components& out_components
);

/**
 * @brief Validates that an x5chain is present and, when x5t is present, that
 *        the thumbprint matches the leaf certificate.
 */
Error validate_cose_sign1_x5chain(
    const CoseSign1Components& components
);

/**
 * @brief Converts a COSE x5chain (DER certificates, leaf first) into a
 *        concatenated PEM chain.
 */
Error x5chain_to_pem(
    const std::vector<std::vector<uint8_t>>& der_chain,
    std::string& out_pem
);

/**
 * @brief Verifies a decoded COSE_Sign1's signature against a certificate
 *        chain the caller has already anchored to a trusted root.
 *
 * Only ES384 (ECDSA with P-384 and SHA-384) is supported.
 */
Error verify_cose_sign1_signature(
    const CoseSign1Components& components,
    X509CertChain& validated_chain
);

/**
 * @brief Verifies a COSE_Sign1 structure.
 *
 * This function parses and validates a COSE_Sign1 message per RFC 9052.
 * It supports certificate chains provided via x5chain in either the protected
 * or unprotected header, with x5t thumbprint binding when the chain is in
 * the unprotected header (per RFC 9360).
 *
 * Signature algorithm: Only ES384 (ECDSA with P-384 and SHA-384) is supported.
 *
 * @param cose_sign1_bytes The raw CBOR-encoded COSE_Sign1 bytes.
 * @param options Verification options including OCSP settings and trust anchor.
 * @param ocsp_client The OCSP client to use for revocation checking (if enabled).
 * @param out_result Output parameter for the verification result.
 * @return Error::Ok on success, or an appropriate error code on failure.
 */
Error verify_cose_sign1(
    const std::vector<uint8_t>& cose_sign1_bytes,
    const CoseSign1VerifyOptions& options,
    IOcspHttpClient& ocsp_client,
    CoseSign1Result& out_result
);

/**
 * @brief Creates an X509 certificate from DER-encoded bytes.
 *
 * @param der_bytes The DER-encoded certificate bytes.
 * @return A unique pointer to the X509 object, or nullptr on error.
 */
nv_unique_ptr<X509> x509_from_der(const std::vector<uint8_t>& der_bytes);

/**
 * @brief Computes the SHA-256 thumbprint of a DER-encoded certificate.
 *
 * @param der_bytes The DER-encoded certificate bytes.
 * @param out_thumbprint Output parameter for the thumbprint bytes (32 bytes).
 * @return Error::Ok on success, Error::InternalError on failure.
 */
Error compute_cert_thumbprint_sha256(const std::vector<uint8_t>& der_bytes, std::vector<uint8_t>& out_thumbprint);

/**
 * @brief Computes the SHA-384 thumbprint of a DER-encoded certificate.
 *
 * @param der_bytes The DER-encoded certificate bytes.
 * @param out_thumbprint Output parameter for the thumbprint bytes (48 bytes).
 * @return Error::Ok on success, Error::InternalError on failure.
 */
Error compute_cert_thumbprint_sha384(const std::vector<uint8_t>& der_bytes, std::vector<uint8_t>& out_thumbprint);

/**
 * @brief Computes the SHA-512 thumbprint of a DER-encoded certificate.
 *
 * @param der_bytes The DER-encoded certificate bytes.
 * @param out_thumbprint Output parameter for the thumbprint bytes (64 bytes).
 * @return Error::Ok on success, Error::InternalError on failure.
 */
Error compute_cert_thumbprint_sha512(const std::vector<uint8_t>& der_bytes, std::vector<uint8_t>& out_thumbprint);

} // namespace nvattestation

