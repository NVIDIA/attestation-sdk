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

#include "nv_attestation/gpu/verify.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/error.h"
#include "nv_attestation/gpu/claims.h"
#include "nv_attestation/log.h"
#include "nv_attestation/nv_jwt.h"
#include "nv_attestation/verify.h"
#include "nv_attestation/nv_http.h"
#include "nv_attestation/utils.h"

#include <set>
#include <unordered_map>

namespace nvattestation {

// MSR 35 validation constants for NVDEC0 status
// Used to conditionally skip measurement index 35 validation based on hardware status
static const uint8_t NVDEC_STATUS_ENABLED = 0xAA;   // NVDEC0 hardware enabled - validate MSR 35
static const uint8_t NVDEC_STATUS_DISABLED = 0x55;  // NVDEC0 hardware disabled - skip MSR 35 validation

    Error LocalGpuVerifier::create(LocalGpuVerifier& out_verifier, const std::shared_ptr<IRimStore>& rim_store, const std::shared_ptr<IOcspHttpClient>& ocsp_http_client) {
        if (rim_store == nullptr) {
            LOG_ERROR("rim_store is null");
            return Error::BadArgument;
        }
        if (ocsp_http_client == nullptr) {
            LOG_ERROR("ocsp_http_client is null");
            return Error::BadArgument;
        }
        out_verifier.m_rim_store = rim_store;
        out_verifier.m_ocsp_http_client = ocsp_http_client;
        return Error::Ok;
    }

    Error LocalGpuVerifier::verify_evidence(const std::vector<GpuEvidence>& evidence, const EvidencePolicy& evidence_policy, ClaimsCollection& out_claims) {
        if (evidence_policy.gpu_claims_version == GpuClaimsVersion::V3) {
            return generate_claims_v3(evidence, evidence_policy, out_claims);
        }
        return Error::Ok;
    }

    Error LocalGpuVerifier::generate_claims_v3(const std::vector<GpuEvidence>& evidence, const EvidencePolicy& policy, ClaimsCollection& out_claims) const {
        for (const auto& cur_evidence : evidence) {
            GpuEvidence::AttestationReport attestation_report;
            Error error = cur_evidence.get_parsed_attestation_report(attestation_report);
            if (error != Error::Ok) {
                return error;
            }
            GpuEvidenceClaims gpu_evidence_claims;
            LOG_DEBUG("Generating GPU evidence claims for GPU index " << cur_evidence.get_uuid());
            error = cur_evidence.generate_gpu_evidence_claims(attestation_report, policy.ocsp_options, *m_ocsp_http_client, gpu_evidence_claims);
            if (error != Error::Ok) {
                return error;
            }
            std::shared_ptr<SerializableGpuClaimsV3> serializable_claims = std::make_shared<SerializableGpuClaimsV3>();
            error = set_gpu_evidence_claims(gpu_evidence_claims, policy, *serializable_claims);
            if (error != Error::Ok) {
                return error;
            }
            
            std::string driver_rim_id;

            error = attestation_report.get_driver_rim_id(cur_evidence.get_gpu_architecture(), driver_rim_id);
            if (error != Error::Ok) {
                return error;
            }
            RimDocument driver_rim_document;
            error = m_rim_store->get_rim(driver_rim_id, driver_rim_document);
            if (error != Error::Ok) {
                return error;
            }

            std::string driver_version_from_rim;
            error = driver_rim_document.get_version(driver_version_from_rim);
            if (error != Error::Ok) {
                return error;
            }
            if (driver_version_from_rim != gpu_evidence_claims.m_driver_version) {
                LOG_ERROR("Driver RIM version mismatch: driver rim version: " << driver_version_from_rim << " != gpu evidence driver version: " << gpu_evidence_claims.m_driver_version);
                return Error::GpuEvidenceDriverRimVersionMismatch;
            }
            serializable_claims->m_gpu_driver_rim_version_match = true;

            error = set_driver_rim_claims(driver_rim_document, policy, *serializable_claims);
            if (error != Error::Ok) {
                return error;
            }

            std::string vbios_rim_id;
            error = attestation_report.get_vbios_rim_id(vbios_rim_id);
            if (error != Error::Ok) {
                return error;
            }
            RimDocument vbios_rim_document;
            error = m_rim_store->get_rim(vbios_rim_id, vbios_rim_document);
            if (error != Error::Ok) {
                return error;
            }

            std::string vbios_version_from_rim;
            error = vbios_rim_document.get_version(vbios_version_from_rim);
            if (error != Error::Ok) {
                return error;
            }
            if (vbios_version_from_rim != gpu_evidence_claims.m_vbios_version) {
                LOG_ERROR("VBIOS RIM version mismatch: vbios rim version: " << vbios_version_from_rim << " != gpu evidence vbios version: " << gpu_evidence_claims.m_vbios_version);
                return Error::GpuEvidenceVbiosRimVersionMismatch;
            }
            serializable_claims->m_gpu_vbios_rim_version_match = true;

            error = set_vbios_rim_claims(vbios_rim_document, policy, *serializable_claims);
            if (error != Error::Ok) {
                return error;
            }

            Measurements driver_measurements;
            error = driver_rim_document.get_measurements(driver_measurements);
            if (error != Error::Ok) {
                return error;
            }
            serializable_claims->m_driver_rim_measurements_available = true;

            Measurements vbios_measurements;
            error = vbios_rim_document.get_measurements(vbios_measurements);
            if (error != Error::Ok) {
                return error;
            }
            serializable_claims->m_vbios_rim_measurements_available = true;

            error = generate_set_measurement_claims(driver_measurements, vbios_measurements, attestation_report, policy, *serializable_claims);
            if (error != Error::Ok) {
                return error;
            }

            out_claims.append(serializable_claims);
        }

        return Error::Ok;
    }

    Error LocalGpuVerifier::set_driver_rim_claims(const RimDocument& driver_rim_document, const EvidencePolicy& policy, SerializableGpuClaimsV3& out_serializable_claims) const {
        RimClaims driver_rim_claims;
        out_serializable_claims.m_driver_rim_fetched = true;
        LOG_DEBUG("Generating driver RIM claims");
        Error error = driver_rim_document.generate_rim_claims(policy, *m_ocsp_http_client, driver_rim_claims);
        if (error != Error::Ok) {
            return error;
        }
        
        out_serializable_claims.m_driver_rim_cert_chain.m_cert_expiration_date = driver_rim_claims.m_cert_chain_claims.expiration_date;
        out_serializable_claims.m_driver_rim_cert_chain.m_cert_status = to_string(driver_rim_claims.m_cert_chain_claims.status);
        out_serializable_claims.m_driver_rim_cert_chain.m_cert_ocsp_status = to_string(driver_rim_claims.m_cert_chain_claims.ocsp_claims.status);
        out_serializable_claims.m_driver_rim_cert_chain.m_cert_revocation_reason = driver_rim_claims.m_cert_chain_claims.ocsp_claims.revocation_reason;
        out_serializable_claims.m_driver_rim_signature_verified = driver_rim_claims.m_signature_verified;

        return Error::Ok;
    }

    Error LocalGpuVerifier::set_vbios_rim_claims(const RimDocument& vbios_rim_document, const EvidencePolicy& policy, SerializableGpuClaimsV3& out_serializable_claims) const {
        out_serializable_claims.m_vbios_rim_fetched = true;
        LOG_DEBUG("Generating VBIOS RIM claims");

        RimClaims vbios_rim_claims;
        Error error = vbios_rim_document.generate_rim_claims(policy, *m_ocsp_http_client, vbios_rim_claims);
        if (error != Error::Ok) {
            return error;
        }
        
        out_serializable_claims.m_vbios_rim_cert_chain.m_cert_expiration_date = vbios_rim_claims.m_cert_chain_claims.expiration_date;
        out_serializable_claims.m_vbios_rim_cert_chain.m_cert_status = to_string(vbios_rim_claims.m_cert_chain_claims.status);
        out_serializable_claims.m_vbios_rim_cert_chain.m_cert_ocsp_status = to_string(vbios_rim_claims.m_cert_chain_claims.ocsp_claims.status);
        out_serializable_claims.m_vbios_rim_cert_chain.m_cert_revocation_reason = vbios_rim_claims.m_cert_chain_claims.ocsp_claims.revocation_reason;
        out_serializable_claims.m_vbios_rim_signature_verified = vbios_rim_claims.m_signature_verified;

        return Error::Ok;
    }

    Error LocalGpuVerifier::set_gpu_evidence_claims(const GpuEvidenceClaims& gpu_evidence_claims, const EvidencePolicy& policy, SerializableGpuClaimsV3& out_serializable_claims) {
        out_serializable_claims.m_gpu_arch_match = gpu_evidence_claims.m_gpu_ar_arch_match;
        out_serializable_claims.m_driver_version = gpu_evidence_claims.m_driver_version;
        out_serializable_claims.m_vbios_version = gpu_evidence_claims.m_vbios_version;

        out_serializable_claims.m_ar_cert_chain.m_cert_expiration_date = gpu_evidence_claims.m_attestation_report_claims.m_cert_chain_claims.expiration_date;
        out_serializable_claims.m_ar_cert_chain.m_cert_status = to_string(gpu_evidence_claims.m_attestation_report_claims.m_cert_chain_claims.status);
        out_serializable_claims.m_ar_cert_chain.m_cert_ocsp_status = to_string(gpu_evidence_claims.m_attestation_report_claims.m_cert_chain_claims.ocsp_claims.status);
        out_serializable_claims.m_ar_cert_chain.m_cert_revocation_reason = gpu_evidence_claims.m_attestation_report_claims.m_cert_chain_claims.ocsp_claims.revocation_reason;

        out_serializable_claims.m_ar_cert_chain_fwid_match = gpu_evidence_claims.m_attestation_report_claims.m_fwid_match;
        out_serializable_claims.m_ar_parsed = gpu_evidence_claims.m_attestation_report_claims.m_parsed;
        out_serializable_claims.m_ar_signature_verified = gpu_evidence_claims.m_attestation_report_claims.m_signature_verified;

        out_serializable_claims.m_gpu_ar_nonce_match = gpu_evidence_claims.m_gpu_ar_nonce_match;
        return Error::Ok;
    }

    Error LocalGpuVerifier::generate_set_measurement_claims(const Measurements& golden_driver_measurements, const Measurements& golden_vbios_measurements, const GpuEvidence::AttestationReport& attestation_report, const EvidencePolicy& policy, SerializableGpuClaimsV3& out_serializable_claims) {
        
        // make sure there is no index conflict between driver and vbios measurements

        // Get all indices from both measurement collections
        std::vector<int> driver_indices = golden_driver_measurements.get_all_indices();
        std::vector<int> vbios_indices = golden_vbios_measurements.get_all_indices();
        
        // Create a set of all unique indices
        std::set<int> all_indices;
        all_indices.insert(driver_indices.begin(), driver_indices.end());
        all_indices.insert(vbios_indices.begin(), vbios_indices.end());
        
        for (int index : all_indices) {
            bool has_driver = golden_driver_measurements.has_measurement_at_index(index);
            bool has_vbios = golden_vbios_measurements.has_measurement_at_index(index);
            
            if (has_driver && has_vbios) {
                out_serializable_claims.m_vbios_index_no_conflict = false;
                out_serializable_claims.m_measurements_matching = SerializableMeasresClaim::Failure;
                return Error::RimMeasurementConflict;
            }
        }

        out_serializable_claims.m_vbios_index_no_conflict = true;
        
        // Determine MSR 35 validation flag based on NVDEC0 status
        bool is_msr_35_valid = true;
        
        uint8_t nvdec0_status = 0;
        Error error = attestation_report.get_nvdec0_status(nvdec0_status);
        if (error != Error::Ok) {
            return error;
        }
                        
        if (nvdec0_status == NVDEC_STATUS_DISABLED) {
            is_msr_35_valid = false;
            LOG_DEBUG("NVDEC0 disabled (status: 0x" << std::hex << static_cast<int>(nvdec0_status) 
                                        << "), skipping MSR 35 validation");
        } else if (nvdec0_status == NVDEC_STATUS_ENABLED) {
            is_msr_35_valid = true;
            LOG_DEBUG("NVDEC0 enabled (status: 0x" << std::hex << static_cast<int>(nvdec0_status) 
                                        << "), validating MSR 35");
        } else {
            LOG_DEBUG("Unknown NVDEC0 status (0x" << std::hex << static_cast<int>(nvdec0_status) 
                                        << "), defaulting to validate MSR 35");
            return Error::InternalError;
        }
        
        // Get measurements from attestation report (i.e runt)
        std::unordered_map<int, std::vector<uint8_t>> runtime_measurements;
        error = attestation_report.get_measurements(runtime_measurements);
        if (error != Error::Ok) {
            LOG_ERROR("Failed to get measurements from attestation report");
            return error;
        }
        
        // Track overall match status
        bool all_measurements_match = true;

        // to track any mismatched measurements
        std::vector<SerializableMismatchedMeasurements> mismatched_measurements;

        // lambda function to compare measurements (used for comparing runtime measurements against both driver and vbios golden measurements)
        auto compare_measurements = [&](int index, const Measurement& golden_measurement, SerializableMismatchedMeasurements::MeasurementSource source) {
            const std::vector<std::vector<uint8_t>>& golden_alternatives = golden_measurement.get_values();
            auto runtime_measurements_it = runtime_measurements.find(index);
            if (runtime_measurements_it == runtime_measurements.end()) {
                LOG_DEBUG("No runtime measurement found at index corresponding to golden measurement " << index << ", considering as mismatch");
                all_measurements_match = false;
                mismatched_measurements.push_back(SerializableMismatchedMeasurements(index, golden_measurement.get_size(), to_hex_string(golden_measurement.get_values()[0]), 0, "NA", source));
                return;
            }

            bool found_match_in_alternatives = false;            
            const std::vector<uint8_t>& runtime_value = runtime_measurements_it->second;
            for (const std::vector<uint8_t>& golden_alternative : golden_alternatives) {
                if (runtime_value.size() == golden_alternative.size() && std::equal(runtime_value.begin(), runtime_value.end(), golden_alternative.begin())) {
                    found_match_in_alternatives = true;
                    break;
                }
            }
            
            if (!found_match_in_alternatives) {
                LOG_DEBUG("Golden measurement at index " << index << " does not match runtime measurement (at the same index)");
                LOG_DEBUG("Runtime measurement: " << to_hex_string(runtime_value));
                all_measurements_match = false;
                mismatched_measurements.push_back(SerializableMismatchedMeasurements(static_cast<uint32_t>(index), golden_measurement.get_size(), to_hex_string(golden_measurement.get_values()[0]), static_cast<uint32_t>(runtime_value.size()), to_hex_string(runtime_value), source));
            }

        };

        LOG_DEBUG("Comparing golden driver measurements against runtime measurements");

        // first compare golden driver measurements against runtime measurements
        for (int index : driver_indices) {
            // Skip index 35 if MSR 35 validation is disabled
            if (index == 35 && !is_msr_35_valid) { //NOLINT(readability-magic-numbers)
                LOG_DEBUG("Skipping measurement index 35 due to NVDEC0 disabled status");
                continue;
            }

            Measurement golden_driver_measurement;
            Error error = golden_driver_measurements.get_measurement_at_index(index, golden_driver_measurement);
            if (error != Error::Ok) {
                return error;
            }

            compare_measurements(index, golden_driver_measurement, SerializableMismatchedMeasurements::MeasurementSource::DRIVER);
        }

        LOG_DEBUG("Comparing golden vbios measurements against runtime measurements");

        // then compare golden vbios measurements against runtime measurements
        for (int index : vbios_indices) {
            if (index == 35 && !is_msr_35_valid) { //NOLINT(readability-magic-numbers)
                LOG_DEBUG("Skipping measurement index 35 due to NVDEC0 disabled status");
                continue;
            }

            Measurement golden_vbios_measurement;
            Error error = golden_vbios_measurements.get_measurement_at_index(index, golden_vbios_measurement);
            if (error != Error::Ok) {
                return error;
            }

            compare_measurements(index, golden_vbios_measurement, SerializableMismatchedMeasurements::MeasurementSource::VBIOS);
        }

        if (all_measurements_match) {
            out_serializable_claims.m_measurements_matching = SerializableMeasresClaim::Success;
            out_serializable_claims.m_secure_boot = std::make_shared<bool>(true);
            out_serializable_claims.m_debug_status = std::make_shared<std::string>("disabled");
            out_serializable_claims.m_mismatched_measurements = nullptr;
        } else {
            out_serializable_claims.m_measurements_matching = SerializableMeasresClaim::Failure;
            out_serializable_claims.m_secure_boot = nullptr;
            out_serializable_claims.m_debug_status = nullptr;
            // sanity check 
            if (mismatched_measurements.empty()) {
                LOG_ERROR("golden measurements (either driver or vbios) do not match runtime measurements, but mismatched records are empty");
                return Error::InternalError;
            }
            out_serializable_claims.m_mismatched_measurements = std::make_shared<std::vector<SerializableMismatchedMeasurements>>(mismatched_measurements);
        }

        return Error::Ok;
    }

    Error NvRemoteGpuVerifier::init_from_env(NvRemoteGpuVerifier& out_verifier, const char* nras_url, HttpOptions http_options) {
        std::string nras_url_str;
        if (nras_url == nullptr || strlen(nras_url) == 0) {
            nras_url_str = get_env_or_default("NVAT_NRAS_BASE_URL", DEFAULT_BASE_URL);
        } else {
            nras_url_str = std::string(nras_url);
        }

        out_verifier.m_nras_url = nras_url_str + "/v4/attest/gpu";
        out_verifier.m_eat_issuer = nras_url_str;

        Error err = NvHttpClient::create(out_verifier.m_http_client, http_options);
        if (err != Error::Ok) {
            return err;
        }

        // TODO(p1): JwkStore should be shared across thread and between verifiers
        std::string jwks_url = nras_url_str + "/.well-known/jwks.json";
        out_verifier.m_jwk_store = std::make_shared<JwkStore>();
        err = JwkStore::init_from_env(out_verifier.m_jwk_store, jwks_url, http_options);
        if (err != Error::Ok) {
            return err;
        }

        return Error::Ok;
    }

    Error NvRemoteGpuVerifier::verify_evidence(const std::vector<GpuEvidence>& evidence, const EvidencePolicy& evidence_policy, ClaimsCollection& out_claims) {
        if (evidence.empty()) {
            LOG_ERROR("No evidence provided");
            return Error::BadArgument;
        }
        Error error = Error::InternalError;

        NRASAttestRequestV4 attest_request;
        
        // todo: is this ok? getting nonce from the first evidence item?
        // all the evidence items should have the same nonce, right?
        attest_request.nonce = to_hex_string(evidence[0].get_nonce());
        attest_request.arch = to_string(evidence[0].get_gpu_architecture());
        // todo: get claims version from evidence policy. add evidence policy to remote verifier. 
        // will it need to send evidence policy to nras?
        attest_request.claims_version = to_string(GpuClaimsVersion::V3); 
        std::vector<std::pair<std::string, std::string>> evidence_list;
        for (const auto& evidence_item : evidence) {
            std::string evidence_b64;
            error = encode_base64(evidence_item.get_attestation_report(), evidence_b64);
            if (error != Error::Ok) {
                return error;
            }
            std::string cert_chain_b64;
            error = encode_base64(evidence_item.get_attestation_cert_chain(), cert_chain_b64);
            if (error != Error::Ok) {
                return error;
            }
            evidence_list.push_back({evidence_b64, cert_chain_b64});
        }
        attest_request.evidence_list = evidence_list;


        std::string request_payload;
        error = serialize_to_json(attest_request, request_payload);
        if (error != Error::Ok) {
            return error;
        }
        NvRequest request(m_nras_url, NvHttpMethod::HTTP_METHOD_POST, {{"Content-Type", "application/json"}}, request_payload);

        long status = 0;
        std::string attest_response_str;
        error = m_http_client.do_request_as_string(request, status, attest_response_str);
        if (error != Error::Ok) {
            return error;
        }

        if (status != NvHttpStatus::HTTP_STATUS_OK) {
            LOG_ERROR("NRAS attestation service returned non-200 status: " << static_cast<int>(status));
            return Error::NrasAttestationError;
        }

        NRASAttestResponseV4 attest_response;
        error = deserialize_from_json(attest_response_str, attest_response);
        if (error != Error::Ok) {
            return error;
        }

        std::vector<uint8_t> eat_nonce;
        std::unordered_map<std::string, std::string> claims;
        error = validate_and_decode_EAT(attest_response, m_jwk_store, m_eat_issuer, m_http_client, eat_nonce, claims);
        if (error != Error::Ok) {
            return error;
        }

        if (eat_nonce != evidence[0].get_nonce()) {
            LOG_ERROR("GPU evidence nonce and EAT nonce mismatch: " << to_hex_string(eat_nonce) << " != " << to_hex_string(evidence[0].get_nonce()));
            return Error::NrasTokenInvalid;
        }

        out_claims = std::vector<std::shared_ptr<Claims>>();
        for (const auto &item : claims) {
            SerializableGpuClaimsV3 claims_obj;
            error = deserialize_from_json<SerializableGpuClaimsV3>(item.second, claims_obj);
            if (error != Error::Ok) {
                return error;
            }
            out_claims.append(std::make_shared<SerializableGpuClaimsV3>(claims_obj));
        }

        // todo: validate the overall jwt token, the claims for each device, decoded them
        
        return Error::Ok;
    
    }
}