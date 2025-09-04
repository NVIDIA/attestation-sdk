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

#include "nv_attestation/log.h"
#include "nv_attestation/verify.h"
#include <nlohmann/json.hpp>
#include "nv_attestation/error.h"
#include "nv_attestation/nv_jwt.h"
#include "nv_attestation/utils.h"
#include "nvat.h"
#include "nv_attestation/claims.h"

namespace nvattestation {

Error verifier_type_from_c(nvat_verifier_type_t c_type, VerifierType& out_type) {
    switch (c_type) {
        case NVAT_VERIFY_LOCAL:
            out_type = VerifierType::Local;
            return Error::Ok;
        case NVAT_VERIFY_REMOTE:
            out_type = VerifierType::Remote;
            return Error::Ok;
        default:
            LOG_ERROR("unknown verifier type: " << c_type);
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

void OcspVerifyOptions::set_nonce_enabled(bool enabled) {
    m_nonce_enabled = enabled;
}

bool OcspVerifyOptions::get_nonce_enabled() const{
    return m_nonce_enabled;
}

void OcspVerifyOptions::set_allow_cert_hold(bool allow_cert_hold) {
    m_allow_cert_hold = allow_cert_hold;
}

bool OcspVerifyOptions::get_allow_cert_hold() const {
    return m_allow_cert_hold;
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

Error validate_and_decode_EAT(const SerializableDetachedEAT& detached_eat, std::shared_ptr<JwkStore>& jwk_store, std::string &eat_issuer, NvHttpClient& http_client, std::vector<uint8_t>& out_eat_nonce, std::unordered_map<std::string, std::string>& out_claims) {
    LOG_DEBUG("Validating and decoding EAT");
    std::string overall_jwt_payload;
    Error error = NvJwt::validate_and_decode(detached_eat.m_overall_jwt_token, jwk_store, eat_issuer, overall_jwt_payload);
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
        error = NvJwt::validate_and_decode(device_claims_jwt, jwk_store, eat_issuer, claims_payload);
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
}