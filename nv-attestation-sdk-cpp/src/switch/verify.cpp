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

#include "nv_attestation/switch/verify.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/switch/evidence.h"
#include "nv_attestation/verify.h"

namespace nvattestation {

Error LocalSwitchVerifier::create(LocalSwitchVerifier& out_verifier, const std::shared_ptr<IRimStore>& rim_store, const std::shared_ptr<IOcspHttpClient>& ocsp_http_client) {
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

Error LocalSwitchVerifier::verify_evidence(const std::vector<std::shared_ptr<SwitchEvidence>>& evidence, const EvidencePolicy& evidence_policy, ClaimsCollection& out_claims) {
    if (evidence_policy.switch_claims_version == SwitchClaimsVersion::V3) {
        return generate_claims_v3(evidence, evidence_policy, out_claims);
    } 
    LOG_ERROR("Switch claims version not supported");
    return Error::BadArgument;
}

Error LocalSwitchVerifier::generate_claims_v3(const std::vector<std::shared_ptr<SwitchEvidence>>& evidence, const EvidencePolicy& evidence_policy, ClaimsCollection& out_claims) const {
    LOG_DEBUG("Generating switch evidence claims");
    for (const auto& cur_evidence : evidence) {
        SwitchEvidence::AttestationReport attestation_report;
        Error error = cur_evidence->get_parsed_attestation_report(attestation_report);
        if (error != Error::Ok) {
            return error;
        }
        LOG_DEBUG("Generating switch evidence claims for switch index " << cur_evidence->get_uuid());
        SwitchEvidenceClaims switch_evidence_claims;
        error = cur_evidence->generate_switch_evidence_claims(attestation_report, evidence_policy.ocsp_options, *m_ocsp_http_client, switch_evidence_claims);
        if (error != Error::Ok) {
            return error;
        }
        std::shared_ptr<SerializableSwitchClaimsV3> serializable_claims = std::make_shared<SerializableSwitchClaimsV3>();
        error = set_switch_evidence_claims(switch_evidence_claims, *serializable_claims);
        if (error != Error::Ok) {
            return error;
        }
        serializable_claims->m_nonce = to_hex_string(cur_evidence->get_nonce());
      
        std::string vbios_rim_id;
        error = attestation_report.get_vbios_rim_id(vbios_rim_id, cur_evidence->get_switch_architecture());
        if (error != Error::Ok) {
            return error;
        }
        LOG_DEBUG("VBIOS RIM ID: " << vbios_rim_id);
        RimDocument vbios_rim;
        error = m_rim_store->get_rim(vbios_rim_id, vbios_rim);
        if (error != Error::Ok) {
            return error;
        }
        std::string vbios_version_from_rim;
        error = vbios_rim.get_version(vbios_version_from_rim);
        if (error != Error::Ok) {
            return error;
        }
        if (vbios_version_from_rim != switch_evidence_claims.m_switch_bios_version) {
            LOG_ERROR("VBIOS RIM version mismatch: vbios rim version: " << vbios_version_from_rim << " != switch evidence vbios version: " << switch_evidence_claims.m_switch_bios_version);
            return Error::SwitchEvidenceVbiosRimVersionMismatch;
        }
        serializable_claims->m_switch_bios_rim_version_match = true;

        error = set_vbios_rim_claims(vbios_rim, evidence_policy, *serializable_claims);
        if (error != Error::Ok) {
            return error;
        }

        Measurements vbios_rim_measurements;
        LOG_DEBUG("Getting measurements from VBIOS RIM");
        error = vbios_rim.get_measurements(vbios_rim_measurements);
        if (error != Error::Ok) {
            return error;
        }
        serializable_claims->m_bios_rim_measurements_available = true;

        error = generate_set_measurement_claims(vbios_rim_measurements, attestation_report, *serializable_claims);
        if (error != Error::Ok) {
            return error;
        }

        out_claims.append(serializable_claims);
    }
    return Error::Ok;
}

Error LocalSwitchVerifier::set_switch_evidence_claims(const SwitchEvidenceClaims& switch_evidence_claims, SerializableSwitchClaimsV3& out_serializable_claims) {
    out_serializable_claims.m_switch_arch_match = switch_evidence_claims.m_switch_arch_match;
    out_serializable_claims.m_switch_ar_nonce_match = switch_evidence_claims.m_switch_ar_nonce_match;
    out_serializable_claims.m_switch_bios_version = switch_evidence_claims.m_switch_bios_version;

    out_serializable_claims.m_ar_cert_chain_claims.m_cert_expiration_date = switch_evidence_claims.m_attestation_report_claims.m_cert_chain_claims.expiration_date;
    out_serializable_claims.m_ar_cert_chain_claims.m_cert_status = to_string(switch_evidence_claims.m_attestation_report_claims.m_cert_chain_claims.status);
    out_serializable_claims.m_ar_cert_chain_claims.m_cert_ocsp_status = to_string(switch_evidence_claims.m_attestation_report_claims.m_cert_chain_claims.ocsp_claims.status);
    out_serializable_claims.m_ar_cert_chain_claims.m_cert_revocation_reason = switch_evidence_claims.m_attestation_report_claims.m_cert_chain_claims.ocsp_claims.revocation_reason;

    out_serializable_claims.m_ar_cert_chain_fwid_match = switch_evidence_claims.m_attestation_report_claims.m_fwid_match;
    out_serializable_claims.m_ar_parsed = switch_evidence_claims.m_attestation_report_claims.m_parsed;
    out_serializable_claims.m_ar_signature_verified = switch_evidence_claims.m_attestation_report_claims.m_signature_verified;
    out_serializable_claims.m_hwmodel = switch_evidence_claims.m_attestation_report_claims.m_hwmodel;
    out_serializable_claims.m_ueid = switch_evidence_claims.m_attestation_report_claims.m_ueid;

    return Error::Ok;
}

Error LocalSwitchVerifier::set_vbios_rim_claims(const RimDocument& vbios_rim, const EvidencePolicy& evidence_policy, SerializableSwitchClaimsV3& out_serializable_claims) const {
    LOG_DEBUG("Generating RIM claims");
    RimClaims vbios_rim_claims;
    Error error = vbios_rim.generate_rim_claims(evidence_policy, *m_ocsp_http_client, vbios_rim_claims);
    if (error != Error::Ok) {
        return error;
    }
    out_serializable_claims.m_bios_rim_fetched = true;
    out_serializable_claims.m_bios_rim_cert_chain.m_cert_expiration_date = vbios_rim_claims.m_cert_chain_claims.expiration_date;
    out_serializable_claims.m_bios_rim_cert_chain.m_cert_status = to_string(vbios_rim_claims.m_cert_chain_claims.status);
    out_serializable_claims.m_bios_rim_cert_chain.m_cert_ocsp_status = to_string(vbios_rim_claims.m_cert_chain_claims.ocsp_claims.status);
    out_serializable_claims.m_bios_rim_cert_chain.m_cert_revocation_reason = vbios_rim_claims.m_cert_chain_claims.ocsp_claims.revocation_reason;
    
    out_serializable_claims.m_bios_rim_signature_verified = vbios_rim_claims.m_signature_verified;

    return Error::Ok;
}

Error LocalSwitchVerifier::generate_set_measurement_claims(const Measurements& golden_measurements, const SwitchEvidence::AttestationReport& attestation_report, SerializableSwitchClaimsV3& out_serializable_claims) {
    std::unordered_map<int, std::vector<uint8_t>> runtime_measurements;
    Error error = attestation_report.get_measurements(runtime_measurements);
    if (error != Error::Ok) {
        return error;
    }

    // Track overall match status
    bool all_measurements_match = true;

    // to track any mismatched measurements
    std::vector<SerializableMismatchedMeasurements> mismatched_measurements;

    std::vector<int> golden_indices = golden_measurements.get_all_indices();
    for (int index : golden_indices) {
        Measurement golden_measurement;
        error = golden_measurements.get_measurement_at_index(index, golden_measurement);
        if (error != Error::Ok) {
            return error;
        }
        const std::vector<std::vector<uint8_t>>& golden_alternatives = golden_measurement.get_values();
        
        auto runtime_measurements_it = runtime_measurements.find(index);
        if (runtime_measurements_it == runtime_measurements.end()) {
            LOG_DEBUG("Measurement at index " << index << " not found in runtime measurements");
            all_measurements_match = false;
            mismatched_measurements.push_back(SerializableMismatchedMeasurements(index, golden_measurement.get_size(), to_hex_string(golden_measurement.get_values()[0]), 0, "NA", SerializableMismatchedMeasurements::MeasurementSource::VBIOS));
            continue;
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
            LOG_DEBUG("Golden measurement at index " << index << " not matching any measurement in runtime measurements");
            all_measurements_match = false;
            mismatched_measurements.push_back(SerializableMismatchedMeasurements(index, golden_measurement.get_size(), to_hex_string(golden_measurement.get_values()[0]), runtime_value.size(), to_hex_string(runtime_value), SerializableMismatchedMeasurements::MeasurementSource::VBIOS));
        }
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

Error NvRemoteSwitchVerifier::init_from_env(NvRemoteSwitchVerifier& out_verifier, const char* nras_url, HttpOptions http_options) {
    std::string nras_url_str;
    if (nras_url == nullptr || strlen(nras_url) == 0) {
        nras_url_str = get_env_or_default("NVAT_NRAS_BASE_URL", DEFAULT_BASE_URL);
    } else {
        nras_url_str = std::string(nras_url);
    }

    out_verifier.m_nras_url = nras_url_str + "/v4/attest/switch";
    out_verifier.m_eat_issuer = nras_url_str;

    Error err = NvHttpClient::create(out_verifier.m_http_client, http_options);
    if (err != Error::Ok) {
        return err;
    }

    std::string jwks_url = nras_url_str + "/.well-known/jwks.json";
    out_verifier.m_jwk_store = std::make_shared<JwkStore>();
    err = JwkStore::init_from_env(out_verifier.m_jwk_store, jwks_url, http_options);
    if (err != Error::Ok) {
        return err;
    }

    return Error::Ok;
}

Error NvRemoteSwitchVerifier::verify_evidence(const std::vector<std::shared_ptr<SwitchEvidence>>& evidence, const EvidencePolicy& evidence_policy, ClaimsCollection& out_claims) {
    // todo(p2): much of the functionality here and in the gpu remote verifier is the same.
    // can probably be refactored to use some common code using a evidence base class and generics for SerializableSwitchClaimsV3
    if (evidence.empty()) {
        LOG_ERROR("No evidence provided");
        return Error::BadArgument;
    }

    Error error = Error::InternalError;
    
    NRASAttestRequestV4 attest_request;
    attest_request.nonce = to_hex_string(evidence[0]->get_nonce());
    attest_request.arch = to_string(evidence[0]->get_switch_architecture());
    attest_request.claims_version = to_string(SwitchClaimsVersion::V3);
    std::vector<std::pair<std::string, std::string>> evidence_list;
    for (const auto& evidence_item : evidence) {
        std::string evidence_b64;
        error = encode_base64(evidence_item->get_attestation_report(), evidence_b64);
        if (error != Error::Ok) {
            return error;
        }
        std::string cert_chain_b64;
        error = encode_base64(evidence_item->get_attestation_cert_chain(), cert_chain_b64);
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
    
    SerializableDetachedEAT attest_response;
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

    if (eat_nonce != evidence[0]->get_nonce()) {
        LOG_ERROR("Switch evidence nonce and EAT nonce mismatch: " << to_hex_string(eat_nonce) << " != " << to_hex_string(evidence[0]->get_nonce()));
        return Error::NrasTokenInvalid;
    }

    out_claims = std::vector<std::shared_ptr<Claims>>();
    for(const auto&claim_item : claims) {
        SerializableSwitchClaimsV3 claims_obj;
        LOG_DEBUG("Deserializing claims: " << claim_item.second);
        error = deserialize_from_json<SerializableSwitchClaimsV3>(claim_item.second, claims_obj);
        if (error != Error::Ok) {
            return error;
        }
        out_claims.append(std::make_shared<SerializableSwitchClaimsV3>(claims_obj));
    }

    return Error::Ok;
    
}

}