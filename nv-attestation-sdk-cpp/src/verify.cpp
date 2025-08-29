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

void from_json(const nlohmann::json& json, NRASAttestResponseV4& attest_response) {
    attest_response.overall_jwt_token = json.at(0).at(1).get<std::string>();
    unsigned long response_array_length = json.size();
    attest_response.device_attest_responses = std::unordered_map<std::string, std::string>();
    // first element is the overall JWT token
    for(unsigned long i = 1; i < response_array_length; i++) {
        auto claims_jwt_pair = json.at(i).get<nlohmann::json>();
        for (const auto &items : claims_jwt_pair.items()) {
            attest_response.device_attest_responses.insert({items.key(), items.value().get<std::string>()});
        }
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

Error validate_and_decode_EAT(const NRASAttestResponseV4& attest_response, std::shared_ptr<JwkStore>& jwk_store, std::string &eat_issuer, NvHttpClient& http_client, std::vector<uint8_t>& out_eat_nonce, std::unordered_map<std::string, std::string>& out_claims) {
    LOG_DEBUG("Validating and decoding EAT");
    std::string overall_jwt_payload;
    Error error = NvJwt::validate_and_decode(attest_response.overall_jwt_token, jwk_store, eat_issuer, overall_jwt_payload);
    if (error != Error::Ok) {
        return error;
    }
    nlohmann::json overall_jwt_payload_json;
    error = deserialize_from_json<nlohmann::json>(overall_jwt_payload, overall_jwt_payload_json);
    if (error != Error::Ok) {
        return error;
    }
    if (!overall_jwt_payload_json.contains("eat_nonce")) {
        LOG_ERROR("NRAS token does not contain eat_nonce");
        return Error::NrasTokenInvalid;
    }
    std::string eat_nonce = overall_jwt_payload_json["eat_nonce"].get<std::string>();
    LOG_DEBUG("EAT nonce: " << eat_nonce);
    out_eat_nonce = hex_string_to_bytes(eat_nonce);

    out_claims = std::unordered_map<std::string, std::string>();
    
    for(const auto &item : attest_response.device_attest_responses) {
        std::string device_id = item.first;
        std::string claims_jwt = item.second;
        std::string claims_payload;
        error = NvJwt::validate_and_decode(claims_jwt, jwk_store, eat_issuer, claims_payload);
        if (error != Error::Ok) {
            return error;
        }
        LOG_DEBUG("Validated and decoded claims for device: " << device_id);
        out_claims.insert({device_id, claims_payload});
    }

    return Error::Ok;
}
}