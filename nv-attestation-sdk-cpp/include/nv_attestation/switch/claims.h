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

#include "nvat.h"
#include "nv_attestation/claims.h"
#include <cstdint>

namespace nvattestation {

enum class SwitchClaimsVersion {
    V3
};

std::string to_string(SwitchClaimsVersion claims_version);
Error switch_claims_version_from_c(uint8_t value, SwitchClaimsVersion& out_version);

class SerializableSwitchClaimsV3 : public Claims {
    public:
        std::string m_nonce;
        std::string m_hwmodel;
        std::string m_ueid;
        SerializableMeasresClaim m_measurements_matching;
        std::shared_ptr<bool> m_secure_boot; // "true" if m_measurements_matching is "success", else null
        std::shared_ptr<std::string> m_debug_status; // "disabled" if m_measurements_matching is "success", else null
        std::shared_ptr<std::vector<SerializableMismatchedMeasurements>> m_mismatched_measurements; // null if m_measurements_matching is "success", else the mismatched measurements

        bool m_switch_arch_match; // true if switch architecture is supported
        bool m_switch_ar_nonce_match; // true if nonce matches between switch evidence and switch attestation report
        std::string m_switch_bios_version; 
        
        // AR claims
        SerializableCertChainClaims m_ar_cert_chain_claims;
        // if fwid is not present, this is true. if present, this is true if fwid matches with the fwid in the leaf certificate
        bool m_ar_cert_chain_fwid_match; 
        bool m_ar_parsed;
        bool m_ar_signature_verified;

        // BIOS RIM claims
        bool m_bios_rim_fetched;
        SerializableCertChainClaims m_bios_rim_cert_chain;
        bool m_bios_rim_signature_verified;

        bool m_switch_bios_rim_version_match; // true if switch bios rim version matches the version in the gpu evidence

        bool m_bios_rim_measurements_available;

        std::string m_version;


        SerializableSwitchClaimsV3();
        ~SerializableSwitchClaimsV3() override = default;
        Error get_nonce(std::string& out_nonce) const override;
        Error get_overall_result(bool& out_result) const override;
        Error get_version(std::string& out_version) const override;
        Error get_device_type(std::string& out_device_type) const override;
        Error serialize_json(std::string& out_string) const override;
        static std::vector<std::uint8_t> to_cbor();
    protected:
        nlohmann::json to_json_object() const override;
};

void to_json(nlohmann::json& j, const SerializableSwitchClaimsV3& claims);
void from_json(const nlohmann::json& js, SerializableSwitchClaimsV3& out_claims);


bool operator==(const SerializableSwitchClaimsV3& lhs, const SerializableSwitchClaimsV3& rhs);

}