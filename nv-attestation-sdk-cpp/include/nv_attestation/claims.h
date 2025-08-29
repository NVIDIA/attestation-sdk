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
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

#include <nlohmann/json.hpp>
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"

namespace nvattestation {
/**
 * @brief Represents certificate chain claims for attestation
 * 
 */
class SerializableCertChainClaims {
    public:
    std::string m_cert_expiration_date;
    std::string m_cert_status;
    std::string m_cert_ocsp_status;
    std::shared_ptr<std::string> m_cert_revocation_reason;

    SerializableCertChainClaims() 
        : m_cert_expiration_date("")
        , m_cert_status("")
        , m_cert_ocsp_status("")
        , m_cert_revocation_reason(nullptr) {}
};

/**
 * @brief Serializes SerializableCertChainClaims to JSON using nlohmann json ADL
 * @param j JSON object to populate
 * @param claims SerializableCertChainClaims object to serialize
 */
inline void to_json(nlohmann::json& j, const SerializableCertChainClaims& claims) {
    j["x-nvidia-cert-expiration-date"] = claims.m_cert_expiration_date;
    j["x-nvidia-cert-status"] = claims.m_cert_status;
    j["x-nvidia-cert-ocsp-status"] = claims.m_cert_ocsp_status;
    j["x-nvidia-cert-revocation-reason"] = serialize_optional_shared_ptr(claims.m_cert_revocation_reason.get());
}

/* @brief Deserializes SerializableCertChainClaims from JSON
* @param j JSON object to read from
* @param out_claims SerializableCertChainClaims object to populate
* @return Error code
*/
inline void from_json(const nlohmann::json& j, SerializableCertChainClaims& out_claims) {
    out_claims.m_cert_expiration_date = j.at("x-nvidia-cert-expiration-date").get<std::string>();
    out_claims.m_cert_status = j.at("x-nvidia-cert-status").get<std::string>();
    out_claims.m_cert_ocsp_status = j.at("x-nvidia-cert-ocsp-status").get<std::string>();
    out_claims.m_cert_revocation_reason = deserialize_optional_shared_ptr<std::string>(j, "x-nvidia-cert-revocation-reason");
}

enum class SerializableMeasresClaim {
    Success,
    Failure,
    NotRun,
    Absent
};

NLOHMANN_JSON_SERIALIZE_ENUM(SerializableMeasresClaim, {
    {SerializableMeasresClaim::Success, "success"},
    {SerializableMeasresClaim::Failure, "fail"},
    {SerializableMeasresClaim::NotRun, "not-run"},
    {SerializableMeasresClaim::Absent, "absent"}
});


class SerializableMismatchedMeasurements {
    public: 
        enum class MeasurementSource {
            VBIOS,
            DRIVER
        };

        NLOHMANN_JSON_SERIALIZE_ENUM(MeasurementSource, {
            {MeasurementSource::VBIOS, "firmware"},
            {MeasurementSource::DRIVER, "driver"}
        })

        uint32_t m_index;
        uint32_t m_golden_size;
        std::string m_golden_value;
        uint32_t m_runtime_size;
        std::string m_runtime_value;
        MeasurementSource m_source;

        SerializableMismatchedMeasurements()
            : m_index(0)
            , m_golden_size(0)
            , m_golden_value("")
            , m_runtime_size(0)
            , m_runtime_value("")
            , m_source(MeasurementSource::VBIOS) // need to give a default value to satisfy the linter
        {}

        SerializableMismatchedMeasurements(uint32_t index, uint32_t golden_size, std::string golden_value, uint32_t runtime_size, std::string runtime_value, MeasurementSource source)
            : m_index(index)
            , m_golden_size(golden_size)
            , m_golden_value(golden_value)
            , m_runtime_size(runtime_size)
            , m_runtime_value(runtime_value)
            , m_source(source) {}

};

inline void to_json(nlohmann::json& j, const SerializableMismatchedMeasurements& mismatched_measurements) {
    j["index"] = mismatched_measurements.m_index;
    j["goldenSize"] = mismatched_measurements.m_golden_size;
    j["goldenValue"] = mismatched_measurements.m_golden_value;
    j["runtimeSize"] = mismatched_measurements.m_runtime_size;
    j["runtimeValue"] = mismatched_measurements.m_runtime_value;
    j["measurementSource"] = mismatched_measurements.m_source;
}

inline void from_json(const nlohmann::json& j, SerializableMismatchedMeasurements& out_mismatched_measurements) {
    out_mismatched_measurements.m_index = j.at("index").get<uint32_t>();
    out_mismatched_measurements.m_golden_size = j.at("goldenSize").get<uint32_t>();
    out_mismatched_measurements.m_golden_value = j.at("goldenValue").get<std::string>();
    out_mismatched_measurements.m_runtime_size = j.at("runtimeSize").get<uint32_t>();
    out_mismatched_measurements.m_runtime_value = j.at("runtimeValue").get<std::string>();
    out_mismatched_measurements.m_source = j.at("measurementSource").get<SerializableMismatchedMeasurements::MeasurementSource>();
}

// Operator== for SerializableMismatchedMeasurements
inline bool operator==(const SerializableMismatchedMeasurements& lhs, const SerializableMismatchedMeasurements& rhs) {
    return lhs.m_index == rhs.m_index &&
           lhs.m_golden_size == rhs.m_golden_size &&
           lhs.m_golden_value == rhs.m_golden_value &&
           lhs.m_runtime_size == rhs.m_runtime_size &&
           lhs.m_runtime_value == rhs.m_runtime_value &&
           lhs.m_source == rhs.m_source;
}

// Operator== for SerializableCertChainClaims
bool operator==(const SerializableCertChainClaims& lhs, const SerializableCertChainClaims& rhs);

/**
 * @brief Virtual base class for claims
 * 
 */
class Claims {
    public:
        Claims() = default;
        virtual ~Claims() = default;
        virtual Error serialize_json(std::string& out_json) const = 0;
        // these functions are used to create the detached EAT
        virtual Error get_nonce(std::string& out_nonce) const = 0;
        virtual Error get_overall_result(bool& out_result) const = 0;
        virtual Error get_version(std::string& out_version) const = 0;
        virtual Error get_device_type(std::string& out_device_type) const = 0;
        // this is needed because Claims is a virtual class and when working with 
        // shared_ptr<Claims> it is not straightforward to define nlohmann json's 
        // adl (to_json and from_json)
        virtual nlohmann::json to_json_object() const = 0;
};

class DetachedEATOptions {
    public: 
        std::string m_private_key_pem = "";
        std::string m_issuer = "NVAT-LOCAL-VERIFIER";
        std::string m_kid = "";

        DetachedEATOptions() = default;
        ~DetachedEATOptions() = default;
};

class ClaimsCollection {
    public:
        ClaimsCollection() = default;
        ClaimsCollection(std::vector<std::shared_ptr<Claims>> claims) : m_claims(claims) {}
        ~ClaimsCollection() = default;

        Error serialize_json(std::string& out_json) const;
        Error get_detached_eat(
            std::string& out_json,
            const DetachedEATOptions& options
        ) const;
        void extend(ClaimsCollection other);
        void append(const std::shared_ptr<Claims>& claims);
        bool empty() const;
        size_t size() const;
        std::shared_ptr<Claims> operator[](size_t index);

        // because this function needs m_claims, which is private
        friend void to_json(nlohmann::json& j, const ClaimsCollection& claims);

    private:
        std::vector<std::shared_ptr<Claims>> m_claims;
};

void to_json(nlohmann::json& j, const ClaimsCollection& claims);
// claims common to payloads inside all JWTs
class SerializableCommonEATClaims {
    public: 
        std::int64_t m_iat;
        std::int64_t m_exp;
        std::string m_iss;
        std::string m_jti;
};

// payload inside the overall JWT token
class SerializableOverallEATClaims {
    public: 
        std::string m_sub;
        SerializableCommonEATClaims m_common_claims;

        std::string m_claims_version;
        std::unordered_map<std::string, std::string, std::hash<std::string>, std::equal_to<>> m_submod_digests;

        bool m_overall_result;
        std::string m_eat_nonce;
};

// payload inside the submod JWT tokens
class SerializableEATSubmodClaims {
    public: 
        SerializableCommonEATClaims m_common_claims;
        std::shared_ptr<Claims> m_device_claims;
};

// the entire detached EAT
class SerializableDetachedEAT {
      public: 
         // can be deserialized to SerializableOverallEATClaims
         std::string m_overall_jwt_token;
         // each element can be deserialized to SerializableEATSubmodClaims
         std::unordered_map<std::string, std::string, std::hash<std::string>, std::equal_to<>> m_device_jwt_tokens;
};

void to_json(nlohmann::json& j, const SerializableDetachedEAT& detached_eat);
void to_json(nlohmann::json& j, const SerializableOverallEATClaims& overall_claims);
void to_json(nlohmann::json& j, const SerializableEATSubmodClaims& submod_claims);
void to_json(nlohmann::json& j, const SerializableCommonEATClaims& out_common_claims);

void from_json(const nlohmann::json& j, SerializableDetachedEAT& detached_eat);
void from_json(const nlohmann::json& j, SerializableOverallEATClaims& overall_claims);
void from_json(const nlohmann::json& j, SerializableEATSubmodClaims& submod_claims);
void from_json(const nlohmann::json& j, SerializableCommonEATClaims& out_common_claims);
} // namespace nvattestation