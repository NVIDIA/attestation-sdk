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

#include <nlohmann/json.hpp>

#include "nv_attestation/gpu/claims.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"

namespace nvattestation
{

    std::string to_string(GpuClaimsVersion version) {
        switch (version) {
            case GpuClaimsVersion::V2:
                return "2.0";
            case GpuClaimsVersion::V3:
                return "3.0";
            case GpuClaimsVersion::V4:
                return "4.0";
            default:
                return "unknown";
        }
    }


    Error gpu_claims_version_from_c(uint8_t value, GpuClaimsVersion& out_version) {
        switch(value) {
            case NVAT_GPU_CLAIMS_VERSION_V4:
                out_version = GpuClaimsVersion::V4;
                return Error::Ok;
            case NVAT_GPU_CLAIMS_VERSION_V3:
                LOG_ERROR("GPU claims version 3 is no longer supported; use NVAT_GPU_CLAIMS_VERSION_V4 (4)");
                return Error::BadArgument;
            default:
                LOG_ERROR("Unknown gpu claims version: " << static_cast<int>(value));
                return Error::BadArgument;
        }
    }

    SerializableGpuClaimsV4::SerializableGpuClaimsV4()
        : m_measurements_matching(SerializableMeasresClaim::Failure)
        , m_gpu_arch_match(false)
        , m_secure_boot(nullptr)
        , m_debug_status(nullptr)
        , m_mismatched_measurements(nullptr)
        , m_mismatched_opaque_records(nullptr)
        , m_ar_cert_chain_fwid_match(false)
        , m_ar_parsed(false)
        , m_gpu_ar_nonce_match(false)
        , m_ar_signature_verified(false)
        , m_driver_rim_fetched(false)
        , m_driver_rim_signature_verified(false)
        , m_gpu_driver_rim_version_match(false)
        , m_driver_rim_measurements_available(false)
        , m_vbios_rim_fetched(false)
        , m_gpu_vbios_rim_version_match(false)
        , m_vbios_rim_signature_verified(false)
        , m_vbios_rim_measurements_available(false)
        , m_vbios_index_no_conflict(false)
        , m_version("4.0")
    {
    }

    Error SerializableGpuClaimsV4::serialize_json(std::string& out_string) const
    {
        return serialize_to_json(*this, out_string);
    }

    std::vector<std::uint8_t> SerializableGpuClaimsV4::to_cbor() const // NOLINT(readability-convert-member-functions-to-static): currently a stub. won't be static.
    {
        return std::vector<std::uint8_t>();
    }

    Error SerializableGpuClaimsV4::get_nonce(std::string& out_nonce) const {
        out_nonce = m_nonce;
        return Error::Ok;
    }

    Error SerializableGpuClaimsV4::get_version(std::string& out_version) const {
        out_version = m_version;
        return Error::Ok;
    }

    Error SerializableGpuClaimsV4::get_device_type(std::string& out_device_type) const {
        out_device_type = "gpu";
        return Error::Ok;
    }

    static bool opaque_mismatch_eq(const SerializableOpaqueDataMismatch& lhs, const SerializableOpaqueDataMismatch& rhs) {
        return lhs.opaque_data_id == rhs.opaque_data_id &&
               lhs.name == rhs.name &&
               lhs.golden_type == rhs.golden_type &&
               lhs.golden_value == rhs.golden_value &&
               compare_shared_ptr(lhs.runtime_type, rhs.runtime_type) &&
               compare_shared_ptr(lhs.runtime_value, rhs.runtime_value);
    }

    static bool operator==(const SerializableOpaqueDataMismatch& lhs, const SerializableOpaqueDataMismatch& rhs) {
        return opaque_mismatch_eq(lhs, rhs);
    }

    static void from_json_opaque_mismatch(const nlohmann::json& js, SerializableOpaqueDataMismatch& out_mm) {
        out_mm.opaque_data_id = js.at("id").get<uint16_t>();
        out_mm.name           = js.at("name").get<std::string>();
        out_mm.golden_type    = js.at("goldenType").get<std::string>();
        out_mm.golden_value   = js.at("goldenValue").get<uint64_t>();
        if (js.contains("runtimeType")) {
            out_mm.runtime_type  = std::make_shared<std::string>(js.at("runtimeType").get<std::string>());
            out_mm.runtime_value = std::make_shared<uint64_t>(js.at("runtimeValue").get<uint64_t>());
        }
    }

    void to_json(nlohmann::json& js, const SerializableOpaqueDataMismatch& mm) {
        js["id"]           = mm.opaque_data_id;
        js["name"]         = mm.name;
        js["goldenType"]   = mm.golden_type;
        js["goldenValue"]  = mm.golden_value;
        if (mm.runtime_type != nullptr) {
            js["runtimeType"]  = *mm.runtime_type;
            js["runtimeValue"] = *mm.runtime_value;
        }
    }

    void from_json(const nlohmann::json& js, SerializableGpuClaimsV4& out_claims)
    {
        // Top-level claims using exact keys from to_json
        out_claims.m_nonce = js.at("eat_nonce").get<std::string>();
        out_claims.m_measurements_matching = js.at("measres").get<SerializableMeasresClaim>();
        out_claims.m_secure_boot = deserialize_optional_shared_ptr<bool>(js, "secboot");
        out_claims.m_debug_status = deserialize_optional_shared_ptr<std::string>(js, "dbgstat");
        out_claims.m_mismatched_measurements = deserialize_optional_shared_ptr<std::vector<SerializableMismatchedMeasurements>>(js, "x-nvidia-mismatch-measurement-records");
        out_claims.m_gpu_arch_match = js.at("x-nvidia-gpu-arch-check").get<bool>();

        out_claims.m_hwmodel = js.at("hwmodel").get<std::string>();
        out_claims.m_ueid = js.at("ueid").get<std::string>();
        out_claims.m_oem_id = js.at("oemid").get<std::string>();

        out_claims.m_driver_version = js.at("x-nvidia-gpu-driver-version").get<std::string>();
        out_claims.m_vbios_version = js.at("x-nvidia-gpu-vbios-version").get<std::string>();

        if (js.contains("x-nvidia-gpu-switch-pdis")) {
            out_claims.m_gpu_switch_pdis = js.at("x-nvidia-gpu-switch-pdis").get<std::vector<std::string>>();
        }

        // Certificate chain claims - using new from_json function
        out_claims.m_ar_cert_chain = js.at("x-nvidia-gpu-attestation-report-cert-chain").get<SerializableCertChainClaims>();
        out_claims.m_ar_cert_chain_fwid_match = js.at("x-nvidia-gpu-attestation-report-cert-chain-fwid-match").get<bool>();
        out_claims.m_ar_parsed = js.at("x-nvidia-gpu-attestation-report-parsed").get<bool>();
        out_claims.m_gpu_ar_nonce_match = js.at("x-nvidia-gpu-attestation-report-nonce-match").get<bool>();
        out_claims.m_ar_signature_verified = js.at("x-nvidia-gpu-attestation-report-signature-verified").get<bool>();

        // Driver RIM claims
        out_claims.m_driver_rim_fetched = js.at("x-nvidia-gpu-driver-rim-fetched").get<bool>();
        out_claims.m_driver_rim_cert_chain = js.at("x-nvidia-gpu-driver-rim-cert-chain").get<SerializableCertChainClaims>();
        out_claims.m_driver_rim_signature_verified = js.at("x-nvidia-gpu-driver-rim-signature-verified").get<bool>();
        out_claims.m_gpu_driver_rim_version_match = js.at("x-nvidia-gpu-driver-rim-version-match").get<bool>();
        out_claims.m_driver_rim_measurements_available = js.at("x-nvidia-gpu-driver-rim-measurements-available").get<bool>();

        // VBIOS RIM claims
        out_claims.m_vbios_rim_fetched = js.at("x-nvidia-gpu-vbios-rim-fetched").get<bool>();
        out_claims.m_vbios_rim_cert_chain = js.at("x-nvidia-gpu-vbios-rim-cert-chain").get<SerializableCertChainClaims>();
        out_claims.m_gpu_vbios_rim_version_match = js.at("x-nvidia-gpu-vbios-rim-version-match").get<bool>();
        out_claims.m_vbios_rim_signature_verified = js.at("x-nvidia-gpu-vbios-rim-signature-verified").get<bool>();
        out_claims.m_vbios_rim_measurements_available = js.at("x-nvidia-gpu-vbios-rim-measurements-available").get<bool>();
        out_claims.m_vbios_index_no_conflict = js.at("x-nvidia-gpu-vbios-index-no-conflict").get<bool>();

        if (js.contains("x-nvidia-attester-claims")) {
            for (const auto& kv : js.at("x-nvidia-attester-claims").items()) {
                out_claims.m_attester_claims[kv.key()] = kv.value().get<uint64_t>();
            }
        }

        if (js.contains("x-nvidia-mismatch-opaque-data-records") &&
            !js.at("x-nvidia-mismatch-opaque-data-records").is_null()) {
            auto vec = std::make_shared<std::vector<SerializableOpaqueDataMismatch>>();
            for (const auto& item : js.at("x-nvidia-mismatch-opaque-data-records")) {
                SerializableOpaqueDataMismatch mm;
                from_json_opaque_mismatch(item, mm);
                vec->push_back(mm);
            }
            out_claims.m_mismatched_opaque_records = vec;
        }

        out_claims.m_version = "4.0";
    }

    void to_json(nlohmann::json& js, const SerializableGpuClaimsV4& claims) {
        js["eat_nonce"] = claims.m_nonce;
        js["measres"] = claims.m_measurements_matching;
        js["secboot"] = serialize_optional_shared_ptr(claims.m_secure_boot.get());
        js["dbgstat"] = serialize_optional_shared_ptr(claims.m_debug_status.get());

        js["hwmodel"] = claims.m_hwmodel;
        js["ueid"] = claims.m_ueid;
        js["oemid"] = claims.m_oem_id;

        js["x-nvidia-device-type"] = "gpu";
        js["x-nvidia-mismatch-measurement-records"] = serialize_optional_shared_ptr(claims.m_mismatched_measurements.get());
        js["x-nvidia-gpu-arch-check"] = claims.m_gpu_arch_match;
        js["x-nvidia-gpu-driver-version"] = claims.m_driver_version;
        js["x-nvidia-gpu-vbios-version"] = claims.m_vbios_version;

        if (!claims.m_gpu_switch_pdis.empty()) {
            js["x-nvidia-gpu-switch-pdis"] = claims.m_gpu_switch_pdis;
        }

        // Certificate chain claims - now using centralized serialization
        js["x-nvidia-gpu-attestation-report-cert-chain"] = claims.m_ar_cert_chain;
        js["x-nvidia-gpu-attestation-report-cert-chain-fwid-match"] = claims.m_ar_cert_chain_fwid_match;
        js["x-nvidia-gpu-attestation-report-parsed"] = claims.m_ar_parsed;
        js["x-nvidia-gpu-attestation-report-nonce-match"] = claims.m_gpu_ar_nonce_match;
        js["x-nvidia-gpu-attestation-report-signature-verified"] = claims.m_ar_signature_verified;

        // Driver RIM claims
        js["x-nvidia-gpu-driver-rim-fetched"] = claims.m_driver_rim_fetched;
        js["x-nvidia-gpu-driver-rim-cert-chain"] = claims.m_driver_rim_cert_chain;
        js["x-nvidia-gpu-driver-rim-signature-verified"] = claims.m_driver_rim_signature_verified;
        js["x-nvidia-gpu-driver-rim-version-match"] = claims.m_gpu_driver_rim_version_match;
        js["x-nvidia-gpu-driver-rim-measurements-available"] = claims.m_driver_rim_measurements_available;

        // VBIOS RIM claims
        js["x-nvidia-gpu-vbios-rim-fetched"] = claims.m_vbios_rim_fetched;
        js["x-nvidia-gpu-vbios-rim-cert-chain"] = claims.m_vbios_rim_cert_chain;
        js["x-nvidia-gpu-vbios-rim-version-match"] = claims.m_gpu_vbios_rim_version_match;
        js["x-nvidia-gpu-vbios-rim-signature-verified"] = claims.m_vbios_rim_signature_verified;
        js["x-nvidia-gpu-vbios-rim-measurements-available"] = claims.m_vbios_rim_measurements_available;
        js["x-nvidia-gpu-vbios-index-no-conflict"] = claims.m_vbios_index_no_conflict;

        js["x-nvidia-attester-claims"] = nlohmann::json::object();
        for (const auto& kv : claims.m_attester_claims) {
            js["x-nvidia-attester-claims"][kv.first] = kv.second;
        }

        js["x-nvidia-mismatch-opaque-data-records"] =
            serialize_optional_shared_ptr(claims.m_mismatched_opaque_records.get());

        js["x-nvidia-gpu-claims-version"] = "4.0";
    }

    nlohmann::json SerializableGpuClaimsV4::to_json_object() const {
        nlohmann::json json = *this;
        return json;
    }


    bool operator==(const SerializableGpuClaimsV4& lhs, const SerializableGpuClaimsV4& rhs) {
        return lhs.m_nonce == rhs.m_nonce &&
               lhs.m_hwmodel == rhs.m_hwmodel &&
               lhs.m_ueid == rhs.m_ueid &&
               lhs.m_oem_id == rhs.m_oem_id &&
               lhs.m_measurements_matching == rhs.m_measurements_matching &&
               lhs.m_gpu_arch_match == rhs.m_gpu_arch_match &&
               compare_shared_ptr(lhs.m_secure_boot, rhs.m_secure_boot) &&
               compare_shared_ptr(lhs.m_debug_status, rhs.m_debug_status) &&
               compare_shared_ptr(lhs.m_mismatched_measurements, rhs.m_mismatched_measurements) &&
               lhs.m_driver_version == rhs.m_driver_version &&
               lhs.m_vbios_version == rhs.m_vbios_version &&
               lhs.m_gpu_switch_pdis == rhs.m_gpu_switch_pdis &&
               lhs.m_ar_cert_chain == rhs.m_ar_cert_chain &&
               lhs.m_ar_cert_chain_fwid_match == rhs.m_ar_cert_chain_fwid_match &&
               lhs.m_ar_parsed == rhs.m_ar_parsed &&
               lhs.m_gpu_ar_nonce_match == rhs.m_gpu_ar_nonce_match &&
               lhs.m_ar_signature_verified == rhs.m_ar_signature_verified &&
               lhs.m_driver_rim_fetched == rhs.m_driver_rim_fetched &&
               lhs.m_driver_rim_cert_chain == rhs.m_driver_rim_cert_chain &&
               lhs.m_driver_rim_signature_verified == rhs.m_driver_rim_signature_verified &&
               lhs.m_gpu_driver_rim_version_match == rhs.m_gpu_driver_rim_version_match &&
               lhs.m_driver_rim_measurements_available == rhs.m_driver_rim_measurements_available &&
               lhs.m_vbios_rim_fetched == rhs.m_vbios_rim_fetched &&
               lhs.m_vbios_rim_cert_chain == rhs.m_vbios_rim_cert_chain &&
               lhs.m_gpu_vbios_rim_version_match == rhs.m_gpu_vbios_rim_version_match &&
               lhs.m_vbios_rim_signature_verified == rhs.m_vbios_rim_signature_verified &&
               lhs.m_vbios_rim_measurements_available == rhs.m_vbios_rim_measurements_available &&
               lhs.m_vbios_index_no_conflict == rhs.m_vbios_index_no_conflict &&
               lhs.m_attester_claims == rhs.m_attester_claims &&
               compare_shared_ptr(lhs.m_mismatched_opaque_records, rhs.m_mismatched_opaque_records) &&
               lhs.m_version == rhs.m_version;
    }

}
