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
#include <map>
#include <memory>
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
    V4,
};

std::string to_string(GpuClaimsVersion version);
Error gpu_claims_version_from_c(uint8_t value, GpuClaimsVersion& out_version);

struct SerializableOpaqueDataMismatch {
    uint16_t                      opaque_data_id = 0;
    std::string                   name;
    std::string                   golden_type    = "MIN_SVN";
    uint64_t                      golden_value   = 0;
    std::shared_ptr<std::string>  runtime_type;
    std::shared_ptr<uint64_t>     runtime_value;
};

class SerializableGpuClaimsV4 : public Claims {
    public:
        std::string m_nonce;
        std::string m_hwmodel;
        std::string m_ueid;
        std::string m_oem_id;

        std::string m_driver_version;
        std::string m_vbios_version;

        std::vector<std::string> m_gpu_switch_pdis;

        // Top-level measurement claims
        SerializableMeasresClaim m_measurements_matching;
        bool m_gpu_arch_match;
        std::shared_ptr<bool> m_secure_boot;
        std::shared_ptr<std::string> m_debug_status;
        std::shared_ptr<std::vector<SerializableMismatchedMeasurements>> m_mismatched_measurements;

        // Opaque data comparison claims
        std::shared_ptr<std::vector<SerializableOpaqueDataMismatch>> m_mismatched_opaque_records;
        std::map<std::string, uint64_t> m_attester_claims;

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

        std::string m_mode;
        std::string m_version;

        SerializableGpuClaimsV4();
        ~SerializableGpuClaimsV4() override = default;

        Error serialize_json(std::string& out_string) const override;

        Error get_nonce(std::string& out_nonce) const override;
        Error get_version(std::string& out_version) const override;
        Error get_device_type(std::string& out_device_type) const override;

        std::vector<std::uint8_t> to_cbor() const;

    protected:
        nlohmann::json to_json_object() const override;
    };

void to_json(nlohmann::json& js, const SerializableOpaqueDataMismatch& mm);
void from_json(const nlohmann::json& j, SerializableGpuClaimsV4& out_claims);
void to_json(nlohmann::json& j, const SerializableGpuClaimsV4& claims);

bool operator==(const SerializableGpuClaimsV4& lhs, const SerializableGpuClaimsV4& rhs);
}