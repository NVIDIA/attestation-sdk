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

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <zcbor_encode.h>
#include "cose_decode.h"
#include "cose_decode_types.h"

#include "nv_attestation/cose.h"
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"
#include "internal/cbor_decode_utils.h"

namespace nvattestation {

namespace {

std::vector<uint8_t> bstr_to_vec(const zcbor_string& str) {
    return {str.value, str.value + str.len};
}

void extract_x5chain(const COSE_X509& x509, std::vector<std::vector<uint8_t>>& out_chain) {
    if (x509.COSE_X509_choice == COSE_X509::COSE_X509_single_m_c) {
        out_chain.push_back(bstr_to_vec(x509.COSE_X509_single_m));
    } else {
        const auto& chain = x509.COSE_X509_chain_m;
        for (size_t i = 0; i < chain.COSE_X509_chain_bstr_count; i++) {
            out_chain.push_back(bstr_to_vec(chain.COSE_X509_chain_bstr[i]));
        }
    }
}

Error extract_from_header_map(const header_map& hmap, bool is_protected, CoseSign1Components& components) {
    if (is_protected && hmap.header_map_alg_present) {
        if (hmap.header_map_alg.header_map_alg_choice != header_map_alg_r::header_map_alg_int_c) {
            LOG_ERROR("alg header must be an integer");
            return Error::CoseParseError;
        }
        components.alg = hmap.header_map_alg.header_map_alg_int;
        components.has_alg = true;
    }

    if (!is_protected && hmap.header_map_alg_present) {
        LOG_WARN("alg header found in unprotected header — ignored per RFC 9052");
    }

    if (hmap.header_map_x5chain_present) {
        if (!components.x5chain.empty()) {
            LOG_ERROR("x5chain appears in both protected and unprotected headers");
            return Error::CoseParseError;
        }
        extract_x5chain(hmap.header_map_x5chain.header_map_x5chain, components.x5chain);
        components.x5chain_in_protected = is_protected;
    }

    if (is_protected && hmap.header_map_x5t_present) {
        const auto& x5t = hmap.header_map_x5t.header_map_x5t;
        components.x5t_hash_alg = x5t.COSE_CertHash_hashAlg;
        components.x5t_thumbprint = bstr_to_vec(x5t.COSE_CertHash_hashValue);
        components.has_x5t = true;
    }

    return Error::Ok;
}

Error parse_cose_sign1(const std::vector<uint8_t>& cose_bytes, CoseSign1Components& out_components) {
    out_components = CoseSign1Components{};
    std::unique_ptr<COSE_Sign1> decoded;
    Error err = decode_cbor(cose_bytes, "COSE_Sign1", cbor_decode_COSE_Sign1_Tagged, decoded,
                            Error::CoseParseError);
    if (err != Error::Ok) {
        return err;
    }

    const auto& prot = decoded->COSE_Sign1_protected;
    if (prot.empty_or_serialized_map_choice == empty_or_serialized_map::empty_or_serialized_map_serialized_header_map_m_c) {
        const auto& shm = prot.empty_or_serialized_map_serialized_header_map_m;
        out_components.protected_header_bytes = bstr_to_vec(shm.serialized_header_map);

        Error error = extract_from_header_map(shm.serialized_header_map_cbor, true, out_components);
        if (error != Error::Ok) {
            return error;
        }
    } else {
        LOG_DEBUG("Protected header is empty");
    }

    Error error = extract_from_header_map(decoded->COSE_Sign1_unprotected, false, out_components);
    if (error != Error::Ok) {
        return error;
    }

    if (decoded->COSE_Sign1_payload_choice == COSE_Sign1::COSE_Sign1_payload_nil_c) {
        LOG_ERROR("Detached payloads (null) are not supported");
        return Error::CoseParseError;
    }
    out_components.payload = bstr_to_vec(decoded->COSE_Sign1_payload_bstr);
    out_components.signature = bstr_to_vec(decoded->COSE_Sign1_signature);

    return Error::Ok;
}

Error build_sig_structure(const std::vector<uint8_t>& protected_header,
                          const std::vector<uint8_t>& payload,
                          std::vector<uint8_t>& out_tbs) {
    // Sig_structure = [
    //   context : "Signature1",
    //   body_protected : bstr,
    //   external_aad : bstr,  (empty for us)
    //   payload : bstr
    // ]

    static constexpr size_t CBOR_SIG_STRUCTURE_OVERHEAD = 64;
    size_t estimated_size = CBOR_SIG_STRUCTURE_OVERHEAD + protected_header.size() + payload.size();
    out_tbs.resize(estimated_size);

    // 1 state + 1 backup is sufficient for a flat array with no nested containers
    ZCBOR_STATE_E(state, 1, out_tbs.data(), out_tbs.size(), 1);

    bool ok = zcbor_list_start_encode(state, 4)
           && zcbor_tstr_put_lit(state, "Signature1")
           && zcbor_bstr_encode_ptr(state, reinterpret_cast<const char*>(protected_header.data()), protected_header.size())
           && zcbor_bstr_encode_ptr(state, nullptr, 0)
           && zcbor_bstr_encode_ptr(state, reinterpret_cast<const char*>(payload.data()), payload.size())
           && zcbor_list_end_encode(state, 4);

    if (!ok) {
        LOG_ERROR("Failed to encode Sig_structure");
        return Error::InternalError;
    }

    size_t actual_size = static_cast<size_t>(state->payload - out_tbs.data());
    out_tbs.resize(actual_size);

    return Error::Ok;
}

Error compute_thumbprint(const std::vector<uint8_t>& der_bytes, const EVP_MD* md, std::vector<uint8_t>& out_thumbprint) {
    int md_size = EVP_MD_size(md);
    if (md_size <= 0) {
        LOG_ERROR("Invalid digest type");
        return Error::InternalError;
    }
    unsigned int digest_len = static_cast<unsigned int>(md_size);
    out_thumbprint.resize(digest_len);

    nv_unique_ptr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
    if (!ctx) {
        LOG_ERROR("Failed to create EVP_MD_CTX: " << get_openssl_error());
        return Error::InternalError;
    }

    if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
        LOG_ERROR("Failed to init digest: " << get_openssl_error());
        return Error::InternalError;
    }

    if (EVP_DigestUpdate(ctx.get(), der_bytes.data(), der_bytes.size()) != 1) {
        LOG_ERROR("Failed to update digest: " << get_openssl_error());
        return Error::InternalError;
    }

    if (EVP_DigestFinal_ex(ctx.get(), out_thumbprint.data(), &digest_len) != 1) {
        LOG_ERROR("Failed to finalize digest: " << get_openssl_error());
        return Error::InternalError;
    }

    out_thumbprint.resize(digest_len);
    return Error::Ok;
}

} // anonymous namespace

Error extract_cose_sign1_payload(
    const std::vector<uint8_t>& cose_sign1_bytes,
    std::vector<uint8_t>& out_payload
) {
    // CBOR tag #6.18 encodes as 0xd2; absence means this is not a COSE_Sign1.
    static constexpr uint8_t kCoseSign1TagByte = 0xd2;
    if (cose_sign1_bytes.empty() || cose_sign1_bytes[0] != kCoseSign1TagByte) {
        return Error::CoseParseError;
    }
    CoseSign1Components components;
    Error err = parse_cose_sign1(cose_sign1_bytes, components);
    if (err != Error::Ok) {
        return err;
    }
    out_payload = std::move(components.payload);
    return Error::Ok;
}

nv_unique_ptr<X509> x509_from_der(const std::vector<uint8_t>& der_bytes) {
    const unsigned char* ptr = der_bytes.data();
    X509* cert = d2i_X509(nullptr, &ptr, static_cast<long>(der_bytes.size()));
    if (cert == nullptr) {
        LOG_ERROR("Failed to parse DER certificate: " << get_openssl_error());
        return nullptr;
    }
    return nv_unique_ptr<X509>(cert);
}

Error compute_cert_thumbprint_sha256(const std::vector<uint8_t>& der_bytes, std::vector<uint8_t>& out_thumbprint) {
    return compute_thumbprint(der_bytes, EVP_sha256(), out_thumbprint);
}

Error compute_cert_thumbprint_sha384(const std::vector<uint8_t>& der_bytes, std::vector<uint8_t>& out_thumbprint) {
    return compute_thumbprint(der_bytes, EVP_sha384(), out_thumbprint);
}

Error compute_cert_thumbprint_sha512(const std::vector<uint8_t>& der_bytes, std::vector<uint8_t>& out_thumbprint) {
    return compute_thumbprint(der_bytes, EVP_sha512(), out_thumbprint);
}

Error validate_cose_sign1_x5chain(
    const CoseSign1Components& components
) {
    if (components.x5chain.empty()) {
        LOG_ERROR("No x5chain found in headers");
        return Error::CoseParseError;
    }
    if (!components.has_x5t) {
        return Error::Ok;
    }

    std::vector<uint8_t> computed_thumbprint;
    Error error = Error::CoseParseError;
    if (components.x5t_hash_alg == cose::HASH_SHA256) {
        error = compute_cert_thumbprint_sha256(components.x5chain.front(),
                                               computed_thumbprint);
    } else if (components.x5t_hash_alg == cose::HASH_SHA384) {
        error = compute_cert_thumbprint_sha384(components.x5chain.front(),
                                               computed_thumbprint);
    } else if (components.x5t_hash_alg == cose::HASH_SHA512) {
        error = compute_cert_thumbprint_sha512(components.x5chain.front(),
                                               computed_thumbprint);
    } else {
        LOG_ERROR("Unsupported x5t hash algorithm: "
                  << components.x5t_hash_alg);
        return Error::CoseParseError;
    }
    if (error != Error::Ok) {
        return error;
    }
    if (computed_thumbprint != components.x5t_thumbprint) {
        LOG_ERROR("x5t thumbprint does not match the x5chain leaf certificate");
        return Error::CoseThumbprintMismatch;
    }
    return Error::Ok;
}

Error decode_cose_sign1(
    const std::vector<uint8_t>& cose_sign1_bytes,
    CoseSign1Components& out_components
) {
    return parse_cose_sign1(cose_sign1_bytes, out_components);
}

Error x5chain_to_pem(
    const std::vector<std::vector<uint8_t>>& der_chain,
    std::string& out_pem
) {
    std::string pem;
    for (const auto& der_cert : der_chain) {
        nv_unique_ptr<X509> x509_cert = x509_from_der(der_cert);
        if (!x509_cert) {
            LOG_ERROR("Failed to parse certificate from x5chain");
            return Error::CoseParseError;
        }

        nv_unique_ptr<BIO> bio(BIO_new(BIO_s_mem()));
        if (!bio) {
            LOG_ERROR("Failed to create BIO: " << get_openssl_error());
            return Error::InternalError;
        }

        if (PEM_write_bio_X509(bio.get(), x509_cert.get()) != 1) {
            LOG_ERROR("Failed to write certificate to PEM: " << get_openssl_error());
            return Error::InternalError;
        }

        BUF_MEM* bptr = nullptr;
        BIO_get_mem_ptr(bio.get(), &bptr);
        pem.append(bptr->data, bptr->length);
    }
    out_pem = std::move(pem);
    return Error::Ok;
}

Error verify_cose_sign1_signature(
    const CoseSign1Components& components,
    X509CertChain& validated_chain
) {
    if (!components.has_alg) {
        LOG_ERROR("No algorithm specified in protected header");
        return Error::CoseParseError;
    }

    if (components.alg != cose::ALG_ES384) {
        LOG_ERROR("Unsupported algorithm: " << components.alg << ". Only ES384 (-35) is supported.");
        return Error::CoseParseError;
    }

    std::vector<uint8_t> tbs_data;
    Error error = build_sig_structure(components.protected_header_bytes, components.payload, tbs_data);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to build Sig_structure");
        return error;
    }

    // RFC 9053 §2.1: COSE ECDSA signatures are raw r||s, not DER. Use the
    // pkcs11 helper which converts r||s → DER before calling EVP_DigestVerifyFinal.
    error = validated_chain.verify_signature_pkcs11(tbs_data, components.signature, EVP_sha384());
    if (error != Error::Ok) {
        LOG_ERROR("COSE signature verification failed");
        return Error::CoseInvalidSignature;
    }

    LOG_DEBUG("COSE signature verification successful");
    return Error::Ok;
}

Error verify_cose_sign1(
    const std::vector<uint8_t>& cose_sign1_bytes,
    const CoseSign1VerifyOptions& options,
    IOcspHttpClient& ocsp_client,
    CoseSign1Result& out_result
) {
    if (cose_sign1_bytes.empty()) {
        LOG_ERROR("Empty COSE_Sign1 input");
        return Error::CoseParseError;
    }

    if (options.root_cert_pem.empty()) {
        LOG_ERROR("Root certificate PEM must be provided for chain validation");
        return Error::BadArgument;
    }

    CoseSign1Components components;
    Error error = parse_cose_sign1(cose_sign1_bytes, components);
    if (error != Error::Ok) {
        return error;
    }

    if (!components.has_alg) {
        LOG_ERROR("No algorithm specified in protected header");
        return Error::CoseParseError;
    }

    if (components.alg != cose::ALG_ES384) {
        LOG_ERROR("Unsupported algorithm: " << components.alg << ". Only ES384 (-35) is supported.");
        return Error::CoseParseError;
    }

    error = validate_cose_sign1_x5chain(components);
    if (error != Error::Ok) {
        return error;
    }

    std::string x5chain_pem;
    error = x5chain_to_pem(components.x5chain, x5chain_pem);
    if (error != Error::Ok) {
        return error;
    }

    X509CertChain cert_chain;
    error = X509CertChain::create_from_cert_chain_str(
        CertificateChainType::GENERIC, options.root_cert_pem, x5chain_pem, cert_chain);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to build certificate chain with root cert");
        return error;
    }

    error = cert_chain.verify();
    if (error != Error::Ok) {
        LOG_ERROR("Certificate chain verification failed");
        return error;
    }

    error = verify_cose_sign1_signature(components, cert_chain);
    if (error != Error::Ok) {
        return error;
    }

    {
        IOcspHttpClient* ocsp_ptr = options.verify_ocsp ? &ocsp_client : nullptr;
        error = cert_chain.generate_per_cert_status(options.ocsp_options, ocsp_ptr, out_result.cert_chain_claims);
        if (error != Error::Ok) {
            LOG_ERROR("Failed to generate per-cert status");
            return error;
        }
        if (!all_certs_trusted(out_result.cert_chain_claims)) {
            LOG_ERROR("Signing cert chain has an expired, revoked, or untrusted-OCSP-status certificate");
            return Error::CertChainVerificationFailure;
        }
    }

    out_result.payload = std::move(components.payload);

    return Error::Ok;
}

} // namespace nvattestation
