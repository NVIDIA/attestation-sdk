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

#include <cstdint>
#include <memory>

#include <nlohmann/json.hpp>

#include "nv_attestation/claims.h"
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"
#include "nv_attestation/nv_jwt.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/verify.h"
#include "nvat.h"

namespace nvattestation {

// Decode the authenticated EAR nonce before comparing it with caller bytes.
static Error decode_ear_nonce(const nlohmann::json& value,
                              std::vector<uint8_t>& out_nonce) {
    if (!value.is_string()) {
        return Error::NrasTokenInvalid;
    }
    const std::string& encoded = value.get_ref<const std::string&>();
    if (encoded.empty()) {
        return Error::NrasTokenInvalid;
    }
    std::vector<uint8_t> decoded;
    if (decode_base64url(encoded, decoded) != Error::Ok || decoded.empty()) {
        return Error::NrasTokenInvalid;
    }
    out_nonce = std::move(decoded);
    return Error::Ok;
}

// Compare the caller's nonce with the decoded, authenticated claim.
static Error validate_expected_ear_nonce(
    const std::string& payload_json,
    const std::vector<uint8_t>& expected_nonce) {
    if (expected_nonce.empty()) {
        return Error::Ok;
    }

    const auto payload = nlohmann::json::parse(payload_json, nullptr, false);
    if (payload.is_discarded() || !payload.is_object() ||
        !payload.contains("eat_nonce")) {
        return Error::NrasTokenInvalid;
    }

    std::vector<uint8_t> nonce;
    if (decode_ear_nonce(payload.at("eat_nonce"), nonce) != Error::Ok) {
        return Error::NrasTokenInvalid;
    }
    return nonce == expected_nonce ? Error::Ok : Error::NonceMismatch;
}

Error verifier_type_from_c(nvat_verifier_type_t c_type, VerifierType& out_type) {
    switch (c_type) {
        case NVAT_VERIFY_LOCAL:
            out_type = VerifierType::Local;
            return Error::Ok;
        case NVAT_VERIFY_REMOTE:
            out_type = VerifierType::Remote;
            return Error::Ok;
        default:
            LOG_ERROR("Unknown verifier type: " << c_type);
            return Error::BadArgument;
    }
}

std::string to_string(VerifierType verifier_type) {
    switch (verifier_type) {
        case VerifierType::Local: return "LOCAL";
        case VerifierType::Remote: return "REMOTE";
        default: return "UNKNOWN";
    }
}

void to_json(nlohmann::json& json, const NRASAttestRequestV4& attest_request) {
    json["nonce"] = attest_request.nonce;
    json["arch"] = attest_request.arch;
    json["claims_version"] = attest_request.claims_version;
    nlohmann::json evidence_list_json = nlohmann::json::array();
    for (const auto& evidence : attest_request.evidence_list) {
        evidence_list_json.push_back({{"evidence", evidence.first}, {"certificate", evidence.second}});
    }
    json["evidence_list"] = evidence_list_json;
}

Error validate_and_decode_EAT(
    const SerializableDetachedEAT& detached_eat,
    std::shared_ptr<JwkStore>& jwk_store, std::string &eat_issuer,
    NvHttpClient& http_client, const JwtValidationOptions& jwt_options,
    std::vector<uint8_t>& out_eat_nonce,
    std::unordered_map<std::string, std::string>& out_claims,
    bool& out_overall_result) {
    LOG_DEBUG("Validating and decoding EAT");
    std::string overall_jwt_payload;
    Error error = NvJwt::validate_and_decode(
        detached_eat.m_overall_jwt_token, jwk_store, eat_issuer,
        overall_jwt_payload, jwt_options);
    if (error != Error::Ok) {
        return error;
    }
    SerializableOverallEATClaims overall_jwt_payload_json;
    LOG_DEBUG("Deserializing overall EAT claims from JSON");
    error = deserialize_from_json<SerializableOverallEATClaims>(overall_jwt_payload, overall_jwt_payload_json);
    if (error != Error::Ok) {
        return error;
    }
    if (overall_jwt_payload_json.m_eat_nonce.empty()) {
        LOG_ERROR("NRAS token does not contain eat_nonce");
        return Error::NrasTokenInvalid;
    }
    std::string eat_nonce = overall_jwt_payload_json.m_eat_nonce;
    LOG_DEBUG("EAT nonce: " << eat_nonce);
    out_eat_nonce = hex_string_to_bytes(eat_nonce);

    out_overall_result = overall_jwt_payload_json.m_overall_result;

    out_claims = std::unordered_map<std::string, std::string>();

    // for each submod digest in the main JWT, validate it is equal to 
    // digest of the submod JWT token
    for (const auto& submod_digest_item : overall_jwt_payload_json.m_submod_digests) {
        std::string device_id = submod_digest_item.first;
        std::string submod_digest_from_overall_jwt = submod_digest_item.second;
        auto it = detached_eat.m_device_jwt_tokens.find(device_id);
        if (it == detached_eat.m_device_jwt_tokens.end()) {
            LOG_ERROR("Submod digest for device: " << device_id << " not found in detached EAT");
            return Error::NrasTokenInvalid;
        }
        std::string device_claims_jwt = it->second;
        std::string claims_payload;
        error = NvJwt::validate_and_decode(
            device_claims_jwt, jwk_store, eat_issuer, claims_payload,
            jwt_options);
        if (error != Error::Ok) {
            return error;
        }
        std::string device_claims_digest;
        error = compute_sha256_hex(device_claims_jwt, device_claims_digest);
        if (error != Error::Ok) {
            return error;
        }
        if (device_claims_digest != submod_digest_from_overall_jwt) {
            LOG_ERROR("Submod digest for device: " << device_id << " does not match");
            LOG_ERROR("Expected digest (from overall JWT): " << submod_digest_from_overall_jwt);
            LOG_ERROR("Actual digest (from submod JWT): " << device_claims_digest);
            return Error::NrasTokenInvalid;
        }
        out_claims.insert({device_id, claims_payload});
    }

    if (overall_jwt_payload_json.m_submod_digests.size() != detached_eat.m_device_jwt_tokens.size()) {
        LOG_ERROR("Number of submod digests in overall JWT does not match number of submod JWT tokens in detached EAT");
        return Error::NrasTokenInvalid;
    }

    return Error::Ok;
}

Error map_submod_payloads_to_claims(
    const std::unordered_map<std::string, std::string>& device_claims_json,
    ClaimsCollection& out_claims) {
    ClaimsCollection local;
    for (const auto& item : device_claims_json) {
        SerializableEATSubmodClaims submod_claims;
        Error error = deserialize_from_json(item.second, submod_claims);
        if (error != Error::Ok) {
            LOG_WARN("Failed to map submod claims for device " << item.first);
            return Error::NrasTokenInvalid;
        }
        if (submod_claims.m_device_claims == nullptr) {
            LOG_WARN("No device claims produced for device: " << item.first);
            return Error::NrasTokenInvalid;
        }
        local.append(submod_claims.m_device_claims);
    }
    out_claims = local;
    return Error::Ok;
}

Error verify_attestation_result(
    const std::string& detached_eat_json,
    const std::string& nras_base_url,
    const std::string& service_key,
    const HttpOptions& http_options,
    const JwtValidationOptions& jwt_options,
    const std::vector<uint8_t>& expected_nonce,
    ClaimsCollection& out_claims) {
    if (detached_eat_json.empty()) {
        LOG_ERROR("detached_eat_json is empty");
        return Error::BadArgument;
    }
    if (nras_base_url.empty()) {
        LOG_ERROR("nras_base_url is empty");
        return Error::BadArgument;
    }

    // Parse the detached EAT envelope.
    SerializableDetachedEAT detached_eat;
    Error error = deserialize_from_json(detached_eat_json, detached_eat);
    if (error != Error::Ok) {
        LOG_WARN("Failed to parse detached EAT");
        return error;
    }

    std::string normalized_nras_base_url;
    error = require_https_and_normalize(nras_base_url, normalized_nras_base_url);
    if (error != Error::Ok) {
        return error;
    }

    // Build a JWKS-backed key store from the base NRAS URL. The JWKS endpoint is
    // public, so service_key is normally empty; it is threaded through for
    // consistency with the other remote clients and for deployments that
    // authenticate the JWKS fetch.
    std::string jwks_url = normalized_nras_base_url + "/.well-known/jwks.json";
    std::string eat_issuer = normalized_nras_base_url;
    std::shared_ptr<JwkStore> jwk_store;
    error = JwkStore::create_from_issuer(
        jwk_store, normalized_nras_base_url, service_key, http_options);
    if (error != Error::Ok) {
        LOG_WARN("Failed to initialize JWK store for " << jwks_url);
        return error;
    }

    NvHttpClient http_client;
    error = NvHttpClient::create(http_client, service_key, http_options);
    if (error != Error::Ok) {
        LOG_WARN("Failed to create HTTP client for EAT verification");
        return error;
    }

    std::vector<uint8_t> eat_nonce; // overall token nonce, compared against expected_nonce below
    std::unordered_map<std::string, std::string> device_claims_json;
    bool overall_result = true;
    error = validate_and_decode_EAT(detached_eat, jwk_store, eat_issuer, http_client,
                                    jwt_options,
                                    eat_nonce, device_claims_json, overall_result);
    if (error != Error::Ok) {
        return error;
    }

    // If the relying party supplied an expected nonce, the token's overall
    // eat_nonce must match it. A token bound to the wrong request is invalid
    // regardless of its overall result, so this takes precedence over the
    // OVERALL_RESULT_FALSE handling below.
    if (!expected_nonce.empty() && eat_nonce != expected_nonce) {
        LOG_WARN("EAT nonce mismatch: token nonce " << to_hex_string(eat_nonce)
                 << " != expected nonce " << to_hex_string(expected_nonce));
        return Error::NonceMismatch;
    }

    Error map_error = map_submod_payloads_to_claims(device_claims_json, out_claims);
    if (map_error != Error::Ok) {
        return map_error;
    }
    if (!overall_result) {
        LOG_WARN("Overall attestation result is false");
        return Error::OverallResultFalse;
    }
    return Error::Ok;
}

Error verify_ear(
    const std::string& ear_jwt,
    const std::string& verifier_base_url,
    const std::string& service_key,
    const HttpOptions& http_options,
    const JwtValidationOptions& jwt_options,
    const std::vector<uint8_t>& expected_nonce,
    std::string& out_ear_json) {
    out_ear_json.clear();
    if (ear_jwt.empty() || verifier_base_url.empty()) {
        return Error::BadArgument;
    }

    std::string normalized_url;
    Error err = require_https_and_normalize(verifier_base_url, normalized_url);
    if (err != Error::Ok) {
        return err;
    }

    std::shared_ptr<JwkStore> jwk_store;
    err = JwkStore::create_from_issuer(
        jwk_store, normalized_url, service_key,
        http_options);
    if (err != Error::Ok) {
        return err;
    }

    std::string payload_json;
    err = NvJwt::validate_and_decode(
        ear_jwt, jwk_store, normalized_url, payload_json, jwt_options,
        Error::NrasTokenInvalid, true, std::chrono::system_clock::now());
    if (err != Error::Ok) {
        return err;
    }

    err = validate_expected_ear_nonce(payload_json, expected_nonce);
    if (err != Error::Ok) {
        return err;
    }

    out_ear_json = std::move(payload_json);
    return Error::Ok;
}

Error handle_nras_error_claim(const nlohmann::json& nras_claims, nvat_devices_t device_type, const EvidencePolicy& evidence_policy) {
    // https://docs.nvidia.com/attestation/advanced-documentation/latest/attestation-troubleshooting-guide/attestation_troubleshooting_guide_python_sdk.html#nvidia-remote-attestation-service-error-codes

    if (!nras_claims.contains("x-nvidia-error-details") || nras_claims.at("x-nvidia-error-details").is_null()) {
        return Error::Ok;
    }

    NrasErrorClaim nras_error_claim = nras_claims.at("x-nvidia-error-details").get<NrasErrorClaim>();
    std::string nras_error_claim_log = 
        "\nNRAS code: " + std::to_string(nras_error_claim.code) +
        "\nHTTP code: " + nras_error_claim.http_status +
        "\nMessage: " + nras_error_claim.message +
        "\nDescription: " + nras_error_claim.description;

    LOG_ERROR("NRAS error details: " << nras_error_claim_log);
    
    const int INVALID_NONCE = 4003;
    const int NONCE_NOT_MATCHING = 4010;
    const int INVALID_CERT_CHAIN = 4007;
    const int INVALID_ATTESTATION_CERTIFICATE_CHAIN = 4014;
    const int INVALID_RIM_CERTIFICATE_CHAIN = 4015;
    const int INVALID_EVIDENCE_SIGNATURE = 4013;
    const int INVALID_RIM_SIGNATURE = 5013;

    switch (nras_error_claim.code) {
        // only ocsp response nonce mismatch is not fail fast
        // evidence nonce mismatch is still fail fast
        case INVALID_NONCE:
        case NONCE_NOT_MATCHING:
            if (device_type == NVAT_DEVICE_GPU) {
                return Error::GpuEvidenceNonceMismatch;
            } else if (device_type == NVAT_DEVICE_NVSWITCH) {
                return Error::SwitchEvidenceNonceMismatch;
            } else {
                return Error::InternalError;
            }
        case INVALID_CERT_CHAIN:
        case INVALID_ATTESTATION_CERTIFICATE_CHAIN:
        case INVALID_RIM_CERTIFICATE_CHAIN:
            return Error::CertChainVerificationFailure;
        case INVALID_EVIDENCE_SIGNATURE:
            if (device_type == NVAT_DEVICE_GPU) {
                return Error::GpuEvidenceInvalidSignature;
            } else if (device_type == NVAT_DEVICE_NVSWITCH) {
                return Error::SwitchEvidenceInvalidSignature;
            } else {
                return Error::InternalError;
            }
        case INVALID_RIM_SIGNATURE:
            if (evidence_policy.verify_rim_signature) {
                return Error::RimInvalidSignature;
            }
            return Error::Ok;
    }

    // all the other error codes should not happen since the 
    // evidence signature / rim signatureis verified first
    return Error::InternalError;
    }
}
