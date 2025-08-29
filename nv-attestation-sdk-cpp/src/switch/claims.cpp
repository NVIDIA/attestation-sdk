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

#include "nv_attestation/switch/claims.h"
#include <nlohmann/json.hpp>
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"

namespace nvattestation {

    std::string to_string(SwitchClaimsVersion claims_version) {
        switch (claims_version) {
            case SwitchClaimsVersion::V3:
                return "3.0";
            default:
                return "Unknown";
        }
    }

    Error switch_claims_version_from_c(uint8_t value, SwitchClaimsVersion& out_version) {
        switch(value) {
            case NVAT_SWITCH_CLAIMS_VERSION_V3:
                out_version = SwitchClaimsVersion::V3;
                return Error::Ok;
            default:
                LOG_ERROR("unknown switch claims version: " << static_cast<int>(value));
                return Error::BadArgument;
        }
    }


    SerializableSwitchClaimsV3::SerializableSwitchClaimsV3()
        : m_measurements_matching(SerializableMeasresClaim::Failure)
        , m_switch_arch_match(false)
        , m_switch_ar_nonce_match(false)
        , m_ar_cert_chain_fwid_match(false)
        , m_ar_parsed(false)
        , m_ar_signature_verified(false)
        , m_bios_rim_fetched(false)
        , m_bios_rim_signature_verified(false)
        , m_switch_bios_rim_version_match(false)
        , m_bios_rim_measurements_available(false)
    {
    }

    Error SerializableSwitchClaimsV3::serialize_json(std::string& out_string) const {
        return serialize_to_json(*this, out_string);
    }

    std::vector<std::uint8_t> SerializableSwitchClaimsV3::to_cbor() {
        return std::vector<std::uint8_t>();
    }

    void from_json(const nlohmann::json& js, SerializableSwitchClaimsV3& out_claims) {
        out_claims.m_measurements_matching = js.at("measres").get<SerializableMeasresClaim>();
        out_claims.m_secure_boot = deserialize_optional_shared_ptr<bool>(js, "secboot");
        out_claims.m_debug_status = deserialize_optional_shared_ptr<std::string>(js, "dbgstat");
        out_claims.m_mismatched_measurements = deserialize_optional_shared_ptr<std::vector<SerializableMismatchedMeasurements>>(js, "x-nvidia-mismatch-measurement-records");
        
        out_claims.m_switch_arch_match = js.at("x-nvidia-switch-arch-check").get<bool>();
        out_claims.m_switch_bios_version = js.at("x-nvidia-switch-bios-version").get<std::string>();

        out_claims.m_ar_cert_chain_claims = js.at("x-nvidia-switch-attestation-report-cert-chain").get<SerializableCertChainClaims>();
        out_claims.m_ar_cert_chain_fwid_match = js.at("x-nvidia-switch-attestation-report-cert-chain-fwid-match").get<bool>();
        out_claims.m_ar_parsed = js.at("x-nvidia-switch-attestation-report-parsed").get<bool>();
        out_claims.m_switch_ar_nonce_match = js.at("x-nvidia-switch-attestation-report-nonce-match").get<bool>();
        out_claims.m_ar_signature_verified = js.at("x-nvidia-switch-attestation-report-signature-verified").get<bool>();

        out_claims.m_bios_rim_fetched = js.at("x-nvidia-switch-bios-rim-fetched").get<bool>();
        out_claims.m_bios_rim_cert_chain = js.at("x-nvidia-switch-bios-rim-cert-chain").get<SerializableCertChainClaims>();
        out_claims.m_bios_rim_signature_verified = js.at("x-nvidia-switch-bios-rim-signature-verified").get<bool>();
        out_claims.m_switch_bios_rim_version_match = js.at("x-nvidia-switch-bios-rim-version-match").get<bool>();
        out_claims.m_bios_rim_measurements_available = js.at("x-nvidia-switch-bios-rim-measurements-available").get<bool>();
    }

    void to_json(nlohmann::json& js, const SerializableSwitchClaimsV3& claims) {
        js["measres"] = claims.m_measurements_matching;
        js["secboot"] = serialize_optional_shared_ptr(claims.m_secure_boot.get());
        js["dbgstat"] = serialize_optional_shared_ptr(claims.m_debug_status.get());

        js["x-nvidia-device-type"] = "nvswitch";
        js["x-nvidia-mismatch-measurement-records"] = serialize_optional_shared_ptr(claims.m_mismatched_measurements.get());

        js["x-nvidia-switch-arch-check"] = claims.m_switch_arch_match;
        js["x-nvidia-switch-bios-version"] = claims.m_switch_bios_version;

        js["x-nvidia-switch-attestation-report-cert-chain"] = claims.m_ar_cert_chain_claims;
        js["x-nvidia-switch-attestation-report-cert-chain-fwid-match"] = claims.m_ar_cert_chain_fwid_match;
        js["x-nvidia-switch-attestation-report-parsed"] = claims.m_ar_parsed;
        js["x-nvidia-switch-attestation-report-nonce-match"] = claims.m_switch_ar_nonce_match;
        js["x-nvidia-switch-attestation-report-signature-verified"] = claims.m_ar_signature_verified;

        js["x-nvidia-switch-bios-rim-fetched"] = claims.m_bios_rim_fetched;
        js["x-nvidia-switch-bios-rim-cert-chain"] = claims.m_bios_rim_cert_chain;
        js["x-nvidia-switch-bios-rim-signature-verified"] = claims.m_bios_rim_signature_verified;
        js["x-nvidia-switch-bios-rim-version-match"] = claims.m_switch_bios_rim_version_match;
        js["x-nvidia-switch-bios-rim-measurements-available"] = claims.m_bios_rim_measurements_available;
    }


    nlohmann::json SerializableSwitchClaimsV3::to_json_object() const {
        nlohmann::json json = *this;
        return json;
    }

    bool operator==(const SerializableSwitchClaimsV3& lhs, const SerializableSwitchClaimsV3& rhs) {
        return lhs.m_measurements_matching == rhs.m_measurements_matching &&
               compare_shared_ptr(lhs.m_secure_boot, rhs.m_secure_boot) &&
               compare_shared_ptr(lhs.m_debug_status, rhs.m_debug_status) &&
               compare_shared_ptr(lhs.m_mismatched_measurements, rhs.m_mismatched_measurements) &&
               lhs.m_switch_arch_match == rhs.m_switch_arch_match &&
               lhs.m_switch_ar_nonce_match == rhs.m_switch_ar_nonce_match &&
               lhs.m_switch_bios_version == rhs.m_switch_bios_version &&
               lhs.m_ar_cert_chain_claims == rhs.m_ar_cert_chain_claims &&
               lhs.m_ar_cert_chain_fwid_match == rhs.m_ar_cert_chain_fwid_match &&
               lhs.m_ar_parsed == rhs.m_ar_parsed &&
               lhs.m_ar_signature_verified == rhs.m_ar_signature_verified &&
               lhs.m_bios_rim_fetched == rhs.m_bios_rim_fetched &&
               lhs.m_bios_rim_cert_chain == rhs.m_bios_rim_cert_chain &&
               lhs.m_bios_rim_signature_verified == rhs.m_bios_rim_signature_verified &&
               lhs.m_switch_bios_rim_version_match == rhs.m_switch_bios_rim_version_match &&
               lhs.m_bios_rim_measurements_available == rhs.m_bios_rim_measurements_available;
    }
}