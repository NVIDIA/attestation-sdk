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

#include <cstddef>
#include <memory>
#include <string>

#include <chrono>
#include <map>
#include <vector>

#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>
#include "jwt-cpp/traits/nlohmann-json/traits.h"

#include "nv_attestation/claims.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/log.h"
#include "nv_attestation/error.h"
#include "nv_attestation/nv_types.h"
#include "nv_attestation/gpu/claims.h"
#include "nv_attestation/switch/claims.h"

namespace nvattestation {
    static constexpr std::int64_t JWT_TTL_SECONDS = 3600LL; // 1 hour
    static constexpr std::size_t JTI_SIZE_BYTES = 32;

    static Error get_current_times(std::int64_t& out_iat, std::int64_t& out_exp) {
        try {
            std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
            const std::int64_t ttl_seconds = JWT_TTL_SECONDS;
            out_iat = now;
            out_exp = now + ttl_seconds;
            return Error::Ok;
        } catch (...) {
            LOG_ERROR("Failed to compute current times");
            return Error::InternalError;
        }
    }

    bool operator==(const SerializableCertChainClaims& lhs, const SerializableCertChainClaims& rhs) {
        return lhs.m_cert_expiration_date == rhs.m_cert_expiration_date &&
               lhs.m_cert_status == rhs.m_cert_status &&
               lhs.m_cert_ocsp_status == rhs.m_cert_ocsp_status &&
               compare_shared_ptr(lhs.m_cert_revocation_reason, rhs.m_cert_revocation_reason);
    }

    Error ClaimsCollection::serialize_json(std::string& out_json) const {
        try {
            nlohmann::json json_array = nlohmann::json::array();
            for (const auto& claim : m_claims) {
                json_array.push_back(claim->to_json_object());
            }
            out_json = json_array.dump();
            return Error::Ok;
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to serialize to JSON: " << e.what());
            return Error::InternalError;
        }    
    }

    void ClaimsCollection::extend(ClaimsCollection other) {
        m_claims.insert(m_claims.end(), other.m_claims.begin(), other.m_claims.end());
    }

    void ClaimsCollection::append(const std::shared_ptr<Claims>& claims) {
        m_claims.push_back(claims);
    }

    bool ClaimsCollection::empty() const {
        return m_claims.empty();
    }

    size_t ClaimsCollection::size() const {
        return m_claims.size();
    }

    std::shared_ptr<Claims> ClaimsCollection::operator[](size_t index) {
        return m_claims[index];
    }

    Error ClaimsCollection::get_detached_eat(
        std::string& out_json,
        const DetachedEATOptions& options
    ) const {
        std::string issuer_to_use = options.m_issuer;

        SerializableDetachedEAT detached_eat;
        SerializableOverallEATClaims overall_claims;

        Error err = get_current_times(overall_claims.m_common_claims.m_iat, overall_claims.m_common_claims.m_exp);
        if (err != Error::Ok) {
            return err;
        }

        overall_claims.m_common_claims.m_iss = issuer_to_use;
        overall_claims.m_sub = "NVIDIA-PLATFORM-ATTESTATION";
        // todo (p0): deprecate this in the future as the claims version
        // will be only in the submod claims. this is because 
        // the submod claims can contain claims from different devices and 
        // the versions of those claims can be different.
        overall_claims.m_claims_version = "3.0";
        std::vector<uint8_t> overall_jti(JTI_SIZE_BYTES);
        err = generate_nonce(overall_jti);
        if (err != Error::Ok) {
            return err;
        }
        std::string overall_jti_str = to_hex_string(overall_jti);
        overall_claims.m_common_claims.m_jti = overall_jti_str;

        std::string overall_nonce;
        bool overall_result = true;
        std::unordered_map<std::string, int, std::hash<std::string>, std::equal_to<>> device_index_for_submod_label;

        for (const auto& claim : m_claims) {
            std::string device_type;
            err = claim->get_device_type(device_type);
            if (err != Error::Ok) {
                return err;
            }
            std::transform(device_type.begin(), device_type.end(), device_type.begin(), ::toupper);
            if (device_type != "GPU" && device_type != "SWITCH") {
                LOG_ERROR("Unknown device type: " << device_type << " in claim: " << claim->to_json_object());
                return Error::BadArgument;
            }

            int index = device_index_for_submod_label[device_type];
            device_index_for_submod_label[device_type] = index + 1;
            std::string submod_key = device_type + std::string("-") + std::to_string(index);

            std::string nonce;
            err = claim->get_nonce(nonce);
            if (err != Error::Ok) {
                return err;
            }
            if (overall_nonce.empty()) {
                overall_nonce = nonce;
            } else if (overall_nonce != nonce) {
                LOG_ERROR("For submod " << submod_key<< " and submod claims" << claim->to_json_object() << "Nonce mismatch: overall_nonce: " << overall_nonce << " != nonce: " << nonce);
                return Error::BadArgument;
            }

            bool claim_result = false;
            err = claim->get_overall_result(claim_result);
            if (err != Error::Ok) {
                return err;
            }
            if (!claim_result) {
                overall_result = false;
            }

            SerializableEATSubmodClaims submod_claims;
            submod_claims.m_common_claims = overall_claims.m_common_claims;
            std::vector<uint8_t> submod_jti(JTI_SIZE_BYTES);
            err = generate_nonce(submod_jti);
            if (err != Error::Ok) {
                return err;
            }
            std::string submod_jti_str = to_hex_string(submod_jti);
            submod_claims.m_common_claims.m_jti = submod_jti_str;
            submod_claims.m_device_claims = claim;
            // convert submod claims to json object and set the claims 
            // in jwt token
            nlohmann::json submod_claims_payload_json = submod_claims;
            auto token = jwt::create<jwt::traits::nlohmann_json>();
            for (auto it = submod_claims_payload_json.begin(); it != submod_claims_payload_json.end(); ++it) {
                token.set_payload_claim(it.key(), jwt::basic_claim<jwt::traits::nlohmann_json>(it.value()));
            }
            if (!options.m_kid.empty()) {
                token.set_header_claim("kid", jwt::basic_claim<jwt::traits::nlohmann_json>(options.m_kid));
            }
            std::string submod_jwt_token;
            if (options.m_private_key_pem.empty()) {
                submod_jwt_token = token.sign(jwt::algorithm::none{});
            } else {
                submod_jwt_token = token.sign(jwt::algorithm::es384("", options.m_private_key_pem, "", ""));
            }
            std::string digest_hex;
            err = compute_sha256_hex(submod_jwt_token, digest_hex);
            if (err != Error::Ok) {
                return err;
            }
            overall_claims.m_submod_digests[submod_key] = digest_hex;
            detached_eat.m_device_jwt_tokens[submod_key] = submod_jwt_token;
        }

        overall_claims.m_overall_result = overall_result;
        overall_claims.m_eat_nonce = overall_nonce;

        nlohmann::json overall_claims_payload_json = overall_claims;
        auto overall_jwt_token = jwt::create<jwt::traits::nlohmann_json>();
        for (auto it = overall_claims_payload_json.begin(); it != overall_claims_payload_json.end(); ++it) {
            overall_jwt_token.set_payload_claim(it.key(), jwt::basic_claim<jwt::traits::nlohmann_json>(it.value()));
        }
        if (!options.m_kid.empty()) {
            overall_jwt_token.set_header_claim("kid", jwt::basic_claim<jwt::traits::nlohmann_json>(options.m_kid));
        }
        if (options.m_private_key_pem.empty()) {
            detached_eat.m_overall_jwt_token = overall_jwt_token.sign(jwt::algorithm::none{});
        } else {
            detached_eat.m_overall_jwt_token = overall_jwt_token.sign(jwt::algorithm::es384("", options.m_private_key_pem, "", ""));
        }

        err = serialize_to_json(detached_eat, out_json);
        if (err != Error::Ok) {
            return err;
        }
        if (!overall_result) {
            return Error::OverallResultFalse;
        }
        return Error::Ok;

    }

    void to_json(nlohmann::json& js, const ClaimsCollection& claims) {
        js = nlohmann::json::array();
        for (const auto& claim : claims.m_claims) {
            js.push_back(claim->to_json_object());
        }
    }

    void to_json(nlohmann::json& js, const SerializableCommonEATClaims& out_common_claims) {
        js["iat"] = out_common_claims.m_iat;
        js["exp"] = out_common_claims.m_exp;
        js["jti"] = out_common_claims.m_jti;
        js["iss"] = out_common_claims.m_iss;
    }

    void to_json(nlohmann::json& js, const SerializableEATSubmodClaims& submod_claims) {
        to_json(js, submod_claims.m_common_claims);
        js.update(submod_claims.m_device_claims->to_json_object());
    }

    void to_json(nlohmann::json& js, const SerializableOverallEATClaims& overall_claims) {
        js["sub"] = overall_claims.m_sub;
        to_json(js, overall_claims.m_common_claims);

        js["x-nvidia-ver"] = overall_claims.m_claims_version;
        js["x-nvidia-overall-att-result"] = overall_claims.m_overall_result;
        js["eat_nonce"] = overall_claims.m_eat_nonce;

        for (const auto& item : overall_claims.m_submod_digests) {
            // Format: submods[key] = ["DIGEST", ["SHA256", hex_digest]]
            js["submods"][item.first] = nlohmann::json::array({"DIGEST", nlohmann::json::array({"SHA256", item.second})});
        }
    }

    void to_json(nlohmann::json& js, const SerializableDetachedEAT& detached_eat) {
        js = nlohmann::json::array();
        js.push_back(nlohmann::json::array({"JWT", detached_eat.m_overall_jwt_token}));

        nlohmann::json submod_objects = nlohmann::json::object();
        
        for(const auto& item: detached_eat.m_device_jwt_tokens) {
            submod_objects[item.first] = item.second;
        }
        js.push_back(submod_objects);
    }

    void from_json(const nlohmann::json& json, SerializableDetachedEAT& detached_eat) {
        detached_eat.m_overall_jwt_token = json.at(0).at(1).get<std::string>();
        for(const auto& submod_item: json.at(1).items()) {
            const auto& submod_key = submod_item.key();
            const auto& submod_value = submod_item.value();
            detached_eat.m_device_jwt_tokens.insert({submod_key, submod_value.get<std::string>()});
        }
    }

    void from_json(const nlohmann::json& json, SerializableCommonEATClaims& out_common_claims) {
        out_common_claims.m_iat = json.at("iat").get<std::int64_t>();
        out_common_claims.m_exp = json.at("exp").get<std::int64_t>();
        out_common_claims.m_jti = json.at("jti").get<std::string>();
        out_common_claims.m_iss = json.at("iss").get<std::string>();
    }

    void from_json(const nlohmann::json& json, SerializableEATSubmodClaims& submod_claims) {
        from_json(json, submod_claims.m_common_claims);
        // todo (p0): after x-nvidia-device-type is added to nras, get the device from that key
        // and then use the device type to create the appropriate claims object
        // std::string device_type = json.at("x-nvidia-device-type").get<std::string>();

        // todo (p2): this can be used to deserilize the claims from NRAS response in verify.cpp
        // can be done when refactoring gpu and switch remote verifiers to a single remote verifier
        if (json.contains("x-nvidia-gpu-attestation-report-cert-chain")) {
            LOG_DEBUG("Deserializing submod GPU claims from JSON");
            auto gpu_claims = std::make_shared<SerializableGpuClaimsV3>();
            from_json(json, *gpu_claims);
            submod_claims.m_device_claims = std::static_pointer_cast<Claims>(gpu_claims);
        } else if (json.contains("x-nvidia-switch-attestation-report-cert-chain")) {
            LOG_DEBUG("Deserializing submod switch claims from JSON");
            auto switch_claims = std::make_shared<SerializableSwitchClaimsV3>();
            from_json(json, *switch_claims);
            submod_claims.m_device_claims = std::static_pointer_cast<Claims>(switch_claims);
        } else {
            throw std::runtime_error("Invalid submod claims in detached EAT - unkown device type");
        }
    }

    void from_json(const nlohmann::json& json, SerializableOverallEATClaims& overall_claims) {
        overall_claims.m_sub = json.at("sub").get<std::string>();
        from_json(json, overall_claims.m_common_claims);
        overall_claims.m_claims_version = json.at("x-nvidia-ver").get<std::string>();
        overall_claims.m_overall_result = json.at("x-nvidia-overall-att-result").get<bool>();
        overall_claims.m_eat_nonce = json.at("eat_nonce").get<std::string>();

        for (const auto& item : json.at("submods").items()) {
            overall_claims.m_submod_digests[item.key()] = item.value().at(1).at(1).get<std::string>();
        }
    }


} // namespace nvattestation
