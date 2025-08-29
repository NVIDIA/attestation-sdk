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

#include "nvat.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/error.h"

namespace nvattestation {


enum class GpuClaimsVersion  {
    V2,
    V3,
};

std::string to_string(GpuClaimsVersion version);
Error gpu_claims_version_from_c(uint8_t value, GpuClaimsVersion& out_version);

/**
 * @brief Represents claims which are used for attestation
 * 
 * These claims are included in attestation evidence and are used by a verifier 
 * to evaluate the trustworthiness of the computing environment.
 */
class SerializableGpuClaimsV3 : public Claims {
    public:
        std::string m_driver_version;
        std::string m_vbios_version;

        // Top-level measurement claims
        SerializableMeasresClaim m_measurements_matching;
        bool m_gpu_arch_match;
        std::shared_ptr<bool> m_secure_boot; // "true" if m_measurements_matching is "success", else null
        std::shared_ptr<std::string> m_debug_status; // "disabled" if m_measurements_matching is "success", else null
        std::shared_ptr<std::vector<SerializableMismatchedMeasurements>> m_mismatched_measurements; // null if m_measurements_matching is "success", else the mismatched measurements


        // Attestation report certificate chain claims
        SerializableCertChainClaims m_ar_cert_chain;
        bool m_ar_cert_chain_fwid_match;
        bool m_ar_parsed;
        bool m_gpu_ar_nonce_match;
        bool m_ar_signature_verified;

        // Driver RIM claims
        bool m_driver_rim_fetched;
        SerializableCertChainClaims m_driver_rim_cert_chain;
        bool m_driver_rim_signature_verified;
        bool m_gpu_driver_rim_version_match;
        bool m_driver_rim_measurements_available;

        // VBIOS RIM claims
        bool m_vbios_rim_fetched;
        SerializableCertChainClaims m_vbios_rim_cert_chain;
        bool m_gpu_vbios_rim_version_match;
        bool m_vbios_rim_signature_verified;
        bool m_vbios_rim_measurements_available;
        bool m_vbios_index_no_conflict;

        

        /**
         * @brief Constructs a GpuClaims object with default values.
         *
         * Initializes all claims to false.
         */
        SerializableGpuClaimsV3();

        /**
         * @brief Destructor
         */
        ~SerializableGpuClaimsV3() override = default;

        /**
         * @brief Serializes the GpuClaims as JSON
         * @return JSON string with the exact structure matching the Python implementation
         */
        Error serialize_json(std::string& out_string) const override;

        /**
         * @brief Serializes the GpuClaims as CBOR
         * @return CBOR bytes
         */
        std::vector<std::uint8_t> to_cbor() const;
    
    protected:
        nlohmann::json to_json_object() const override;
    };

/**
 * @brief Deserializes the GpuClaims from JSON
 * @param j JSON object to read from
 * @param out_claims SerializableGpuClaimsV3 object to populate
 */
void from_json(const nlohmann::json& j, SerializableGpuClaimsV3& out_claims);

/**
 * @brief Serializes the GpuClaims as JSON
 * @param j JSON object to populate
 * @param claims SerializableGpuClaimsV3 object to serialize
 */
void to_json(nlohmann::json& j, const SerializableGpuClaimsV3& claims);

/**
 * @brief Operator== for SerializableGpuClaimsV3
 * @param lhs Left-hand side SerializableGpuClaimsV3 object
 * @param rhs Right-hand side SerializableGpuClaimsV3 object
 * @return true if objects are equal, false otherwise
 */
bool operator==(const SerializableGpuClaimsV3& lhs, const SerializableGpuClaimsV3& rhs);

}