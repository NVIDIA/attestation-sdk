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

#include <vector>
#include <string>
#include <memory>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <algorithm>

#ifdef ENABLE_NSCQ
#include "nv_attestation/switch/nscq_attestation.h"
#include "nv_attestation/switch/nscq_client.h"
#endif // ENABLE_NSCQ

#include "nv_attestation/switch/evidence.h"
#include "nv_attestation/log.h"
#include "nv_attestation/error.h"
#include <nlohmann/json.hpp>
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/spdm/spdm_req.hpp"
#include "nv_attestation/spdm/spdm_resp.hpp"
#include "nv_attestation/utils.h"
#include "internal/certs.h"

using json = nlohmann::json;

namespace nvattestation
{


const std::vector<SwitchArchitecture> SwitchArchitectureData::m_supported_architectures = {
    SwitchArchitecture::LS10,
};


Error SwitchArchitectureData::create(SwitchArchitecture arch, SwitchArchitectureData& out_arch_data) {
    if (std::find(m_supported_architectures.begin(), m_supported_architectures.end(), arch) == m_supported_architectures.end()) {
        LOG_ERROR("SWITCH architecture " + to_string(arch) + " is not supported.");
        return Error::NscqArchitectureError;
    }
    out_arch_data.m_arch = arch;
    switch (arch) {
        case SwitchArchitecture::LS10:
            out_arch_data.m_ar_signature_hash_algorithm = EVP_sha384();
            // NOLINTNEXTLINE(readability-magic-numbers)
            out_arch_data.m_ar_signature_length = 96; // bytes
            out_arch_data.project = "5612";
            out_arch_data.project_sku = "0002";
            out_arch_data.chip_sku = "890";
            out_arch_data.m_fwid_type = X509CertChain::FWIDType::FWID_2_23_133_5_4_1;
            break;
        default:
            LOG_ERROR("SWITCH architecture " + to_string(arch) + " is not supported.");
            return Error::NscqArchitectureError;
    }
    return Error::Ok;
}

void to_json(json& out_json, const SwitchEvidence& evidence) {
    std::string encoded_evidence;
    Error err = encode_base64(evidence.get_attestation_report(), encoded_evidence);
    if (err != Error::Ok) { 
        // to be caught by library wrapper. not for users.
        throw std::runtime_error("Failed to encode attestation report to base64");
    }
    std::string encoded_certificate;
    err = encode_base64(evidence.get_attestation_cert_chain(), encoded_certificate);
    if (err != Error::Ok) { 
        throw std::runtime_error("Failed to encode attestation cert chain to base64");
    }
    out_json = json{
        {"version", "1.0"},
        {"arch", to_string(evidence.get_switch_architecture())},
        {"nonce", evidence.get_hex_nonce()},
        {"evidence", encoded_evidence},
        {"certificate", encoded_certificate},
    };
}

void to_json(json& out_json, const std::shared_ptr<SwitchEvidence>& evidence) {
    if (evidence == nullptr) {
        throw std::runtime_error("Evidence cannot be null when serializing to JSON");
    }
    to_json(out_json, *evidence);
}

void from_json(const json& json, SwitchEvidence& out_evidence) {
    std::string version = json.at("version").get<std::string>();
    if (version != "1.0") {
        throw std::runtime_error("Unsupported version: " + version);
    }
    std::string arch_str = json.at("arch").get<std::string>();
    SwitchArchitecture architecture = SwitchArchitecture::Unknown;
    from_string(arch_str, architecture);
    if (architecture == SwitchArchitecture::Unknown) {
        throw std::runtime_error("Unknown switch architecture: " + arch_str);
    }
    out_evidence.set_switch_architecture(architecture);

    std::string nonce_str = json.at("nonce").get<std::string>();
    std::vector<uint8_t> nonce = hex_string_to_bytes(nonce_str);
    out_evidence.set_nonce(nonce);

    std::string evidence_base64 = json.at("evidence").get<std::string>();
    std::vector<uint8_t> evidence;
    Error err = decode_base64(evidence_base64, evidence);
    if (err != Error::Ok) {
        throw std::runtime_error("Failed to decode evidence: " + evidence_base64);
    }
    out_evidence.set_attestation_report(evidence);

    std::string certificate_base64 = json.at("certificate").get<std::string>();
    std::string certificate;
    err = decode_base64(certificate_base64, certificate);
    if (err != Error::Ok) {
        throw std::runtime_error("Failed to decode certificate: " + certificate_base64);
    }
    out_evidence.set_attestation_cert_chain(certificate);
}

void from_json(const json& json, std::shared_ptr<SwitchEvidence>& out_evidence) {
    out_evidence = std::make_shared<SwitchEvidence>();
    from_json(json, *out_evidence);
}

Error SwitchEvidence::to_json(std::string& out_string) const {
    return serialize_to_json(*this, out_string);
}

Error SwitchEvidence::collection_to_json(const std::vector<std::shared_ptr<SwitchEvidence>>& collection, std::string& out_string) {
    return serialize_to_json(collection, out_string);
}

Error SwitchEvidence::collection_from_json(const std::string& json_string, std::vector<std::shared_ptr<SwitchEvidence>>& out_collection) {
    return deserialize_from_json(json_string, out_collection);
}

std::string SwitchEvidence::get_hex_nonce() const {
    return to_hex_string(m_nonce);
}

std::string to_string(SwitchArchitecture arch) {
    switch (arch) {
        case SwitchArchitecture::LS10: return "LS10";
        case SwitchArchitecture::SV10: return "SV10";
        case SwitchArchitecture::LR10: return "LR10";
        default: return "UNKNOWN";
    }
}

void from_string(const std::string& arch_str, SwitchArchitecture& out_arch) {
    if (arch_str == "LS10") {
        out_arch = SwitchArchitecture::LS10;
        return;
    }
    if (arch_str == "SV10") {
        out_arch = SwitchArchitecture::SV10;
        return;
    }
    if (arch_str == "LR10") {
        out_arch = SwitchArchitecture::LR10;
        return;
    }
    out_arch = SwitchArchitecture::Unknown;
}

Error NscqEvidenceCollector::get_evidence(const std::vector<uint8_t>& nonce_input, std::vector<std::shared_ptr<SwitchEvidence>>& out_evidence_list) const
{
#ifdef ENABLE_NSCQ
    std::vector<std::string> uuids;
    Error error = get_all_switch_uuid(uuids);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to get switch UUIDs");
        return error;
    }

    if (uuids.empty()) {
        LOG_ERROR("No switch UUIDs found");
        return Error::NscqError;
    }

    auto arch = SwitchArchitecture::Unknown;
    error = get_switch_architecture(arch);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to get switch architecture");
        return error;
    }

    for (const auto& uuid : uuids) {
        std::vector<uint8_t> attestation_report;
        error = get_attestation_report(uuid, nonce_input, attestation_report);
        if (error != Error::Ok) {
            LOG_ERROR("Failed to get attestation report for UUID: " + uuid);
            return error;
        }

        std::string attestation_cert_chain;
        error = get_attestation_cert_chain(uuid, attestation_cert_chain);
        if (error != Error::Ok) {
            LOG_ERROR("Failed to get attestation certificate chain for UUID: " + uuid);
            return error;
        }

        auto tnvl_mode_status = SwitchTnvlMode::Unknown;
        error = get_switch_tnvl_status(uuid, tnvl_mode_status);
        if (error != Error::Ok) {
            LOG_ERROR("Failed to get TNVL mode for UUID: " + uuid);
            return error;
        }
        bool tnvl_mode = (tnvl_mode_status == SwitchTnvlMode::Enabled);
        bool lock_mode = (tnvl_mode_status == SwitchTnvlMode::Locked);

        out_evidence_list.emplace_back(std::make_shared<SwitchEvidence>(
            arch,
            uuid,
            attestation_report,
            attestation_cert_chain,
            tnvl_mode,
            lock_mode,
            nonce_input
        ));
    }
    
    return Error::Ok;
#else // ENABLE_NSCQ
    LOG_ERROR("ENABLE_NSCQ feature was not enabled during compilation");
    return Error::FeatureNotEnabled;
#endif // ENABLE_NSCQ
}

Error SwitchEvidence::generate_switch_evidence_claims(const AttestationReport& parsed_attestation_report, const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, SwitchEvidenceClaims& out_switch_evidence_claims) const {
    SwitchArchitectureData arch_data;
    Error error = SwitchArchitectureData::create(m_switch_architecture, arch_data);
    if (error != Error::Ok) {
        return error;
    }
    out_switch_evidence_claims.m_switch_arch_match = true;

    std::vector<uint8_t> nonce_from_ar;
    error = parsed_attestation_report.get_spdm_req_nonce(nonce_from_ar);
    if (error != Error::Ok) {
        return error;
    }
    if (nonce_from_ar.size() != m_nonce.size() || memcmp(nonce_from_ar.data(), m_nonce.data(), nonce_from_ar.size()) != 0) {
        LOG_ERROR("Nonce mismatch. nonce_from_ar: " + to_hex_string(nonce_from_ar) + " m_nonce: " + to_hex_string(m_nonce));
        return Error::SwitchEvidenceNonceMismatch;
    }
    out_switch_evidence_claims.m_switch_ar_nonce_match = true;

    std::string bios_version;
    error = parsed_attestation_report.get_vbios_version(bios_version);
    if (error != Error::Ok) {
        return error;
    }
    out_switch_evidence_claims.m_switch_bios_version = bios_version;

    error = parsed_attestation_report.generate_attestation_report_claims(ocsp_verify_options, ocsp_client, arch_data, out_switch_evidence_claims.m_attestation_report_claims);
    if (error != Error::Ok) {
        return error;
    }

    return Error::Ok;
}

Error SwitchEvidence::get_parsed_attestation_report(AttestationReport& out_attestation_report) const {
    return AttestationReport::create(m_attestation_report, m_attestation_cert_chain, m_switch_architecture, out_attestation_report);
}

Error SwitchEvidence::AttestationReport::get_spdm_response(const SpdmMeasurementResponseMessage11*& out_spdm_response) const {
    out_spdm_response = &m_spdm_response;
    return Error::Ok;
}

Error SwitchEvidence::AttestationReport::get_spdm_request(const SpdmMeasurementRequestMessage11*& out_spdm_request) const {
    out_spdm_request = &m_spdm_request;
    return Error::Ok;
}


Error SwitchEvidence::AttestationReport::create(const std::vector<uint8_t>& attestation_report_data, const std::string& ar_cert_chain, SwitchArchitecture architecture, AttestationReport& out_attestation_report) {

    Error error = X509CertChain::create_from_cert_chain_str(CertificateChainType::NVSWITCH_DEVICE_IDENTITY, DEVICE_ROOT_CERT, ar_cert_chain, out_attestation_report.m_attestation_cert_chain);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to parse attestation certificate chain.");
        return Error::InternalError;
    }

    // Ensure attestation_report_data is large enough before attempting to split
    SwitchArchitectureData arch_data;
    error = SwitchArchitectureData::create(architecture, arch_data);
    if (error != Error::Ok) {
        return error;
    }
    if (attestation_report_data.size() <= arch_data.get_ar_signature_length()) {
        LOG_ERROR("Attestation report data is too short.");
        return Error::InternalError;
    }

    std::ptrdiff_t ar_signature_length = static_cast<std::ptrdiff_t>(arch_data.get_ar_signature_length());
    std::vector<uint8_t> data_wo_signature(attestation_report_data.begin(), attestation_report_data.end() - ar_signature_length);
    std::vector<uint8_t> signature(attestation_report_data.end() - ar_signature_length, attestation_report_data.end());
    
    error = out_attestation_report.m_attestation_cert_chain.verify_signature_pkcs11(data_wo_signature, signature, arch_data.get_ar_signature_hash_algorithm());
    if (error != Error::Ok) { 
        LOG_ERROR("Failed to verify attestation report signature.");
        return Error::SwitchEvidenceInvalidSignature;
    }

    std::ptrdiff_t spdm_request_length = static_cast<std::ptrdiff_t>(SpdmMeasurementRequestMessage11::get_request_length());
    std::vector<uint8_t> spdm_request(attestation_report_data.begin(), attestation_report_data.begin() + spdm_request_length);
    error = SpdmMeasurementRequestMessage11::create(spdm_request, out_attestation_report.m_spdm_request);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to parse SPDM request.");
        return Error::InternalError;
    }

    std::vector<uint8_t> spdm_response(attestation_report_data.begin() + spdm_request_length, attestation_report_data.end());
    error = SpdmMeasurementResponseMessage11::create(spdm_response, arch_data.get_ar_signature_length(), out_attestation_report.m_spdm_response);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to parse SPDM response.");
        return Error::InternalError;
    }

    const std::vector<ParsedOpaqueFieldData>* parsed_opaque_data_ptr = nullptr;
    error = out_attestation_report.m_spdm_response.get_parsed_opaque_data(parsed_opaque_data_ptr);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to parse SWITCH opaque data.");
        return Error::InternalError;
    }

    error = SwitchOpaqueDataParser::create(*parsed_opaque_data_ptr, out_attestation_report.m_switch_opaque_data_parser);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to parse SWITCH opaque data.");
        return Error::InternalError;
    }

    return Error::Ok;
}

Error SwitchEvidence::AttestationReport::generate_attestation_report_claims(const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, const SwitchArchitectureData& arch_data, SwitchEvidenceClaims::AttestationReportClaims& out_attestation_report_claims) const {
    LOG_DEBUG("Generating attestation report claims");
    out_attestation_report_claims.m_parsed = true;
    out_attestation_report_claims.m_signature_verified = true;

    const std::vector<uint8_t>* fwid = nullptr;
    Error error = get_fwid(fwid);
    if (error != Error::Ok && error != Error::SpdmFieldNotFound) {
        return error;
    }
    if (error == Error::Ok) {
        std::vector<uint8_t> cert_fwid;
        error = m_attestation_cert_chain.get_fwid(0, arch_data.m_fwid_type, cert_fwid);
        if (error != Error::Ok) {
            return error;
        }
        LOG_DEBUG("Cert FWID: " << to_hex_string(cert_fwid));
        if (fwid->size() != cert_fwid.size() || memcmp(fwid->data(), cert_fwid.data(), fwid->size()) != 0) {
            LOG_ERROR("FWID mismatch. fwid: " + to_hex_string(*fwid) + " cert_fwid: " + to_hex_string(cert_fwid));
            out_attestation_report_claims.m_fwid_match = false;
            return Error::SwitchEvidenceFwidMismatch;
        }
        out_attestation_report_claims.m_fwid_match = true;
    } else if (error == Error::SpdmFieldNotFound) {
        out_attestation_report_claims.m_fwid_match = true;
    }

    error = m_attestation_cert_chain.generate_cert_chain_claims(ocsp_verify_options, ocsp_client, out_attestation_report_claims.m_cert_chain_claims);
    if (error != Error::Ok) {
        return error;
    }

    error = m_attestation_cert_chain.get_hwmodel(out_attestation_report_claims.m_hwmodel);
    if (error != Error::Ok) {
        return error;
    }

    error = m_attestation_cert_chain.get_ueid(out_attestation_report_claims.m_ueid);
    if (error != Error::Ok) {
        return error;
    }

    return Error::Ok;
}

Error SwitchEvidence::AttestationReport::get_fwid(const std::vector<uint8_t>*& out_fwid) const {
    const SwitchParsedOpaqueFieldData* fwid_field = nullptr;
    Error error = m_switch_opaque_data_parser.get_field(SwitchOpaqueDataType::FWID, fwid_field);
    if (error != Error::Ok) {
        return error;
    }
    const std::vector<uint8_t>* fwid_data = nullptr;
    error = fwid_field->get_byte_vector(fwid_data);
    if (error != Error::Ok) {
        return error;
    }
    out_fwid = fwid_data;
    return Error::Ok;
}

Error SwitchEvidence::AttestationReport::get_vbios_version(std::string& out_bios_version) const {
    const SwitchParsedOpaqueFieldData* bios_version_field = nullptr;
    Error error = m_switch_opaque_data_parser.get_field(SwitchOpaqueDataType::VBIOS_VERSION, bios_version_field);
    if (error != Error::Ok) {
        return error;
    }
    const std::vector<uint8_t>* bios_version_data = nullptr;
    error = bios_version_field->get_byte_vector(bios_version_data);
    if (error != Error::Ok) {
        return error;
    }
    out_bios_version = std::string(bios_version_data->begin(), bios_version_data->end());
    return Error::Ok;
}

Error SwitchEvidence::AttestationReport::get_vbios_rim_id(std::string& out_vbios_rim_id, SwitchArchitecture architecture) const {
    std::string vbios_version;
    Error error = get_vbios_version(vbios_version);
    if (error != Error::Ok) {
        return error;
    }

    // remove "." from vbios_version
    vbios_version.erase(std::remove(vbios_version.begin(), vbios_version.end(), '.'), vbios_version.end());
    // make it lowercase
    std::transform(vbios_version.begin(), vbios_version.end(), vbios_version.begin(), ::tolower);

    SwitchArchitectureData arch_data;
    error = SwitchArchitectureData::create(architecture, arch_data);
    if (error != Error::Ok) {
        return error;
    }
    std::string project = arch_data.project;
    std::string project_sku = arch_data.project_sku;
    std::string chip_sku = arch_data.chip_sku;

    std::string vbios_rim_id = "NV_SWITCH_BIOS_" + project + "_" + project_sku + "_" + chip_sku + "_" + vbios_version;
    out_vbios_rim_id = vbios_rim_id;
    return Error::Ok;
}

Error SwitchEvidence::AttestationReport::get_spdm_req_nonce(std::vector<uint8_t>& out_nonce) const {
    const SpdmMeasurementRequestMessage11* spdm_request = nullptr;
    Error error = get_spdm_request(spdm_request);
    if (error != Error::Ok) {
        return error;
    }
    out_nonce = std::vector<uint8_t>(spdm_request->get_nonce().begin(), spdm_request->get_nonce().end());
    return Error::Ok;
}

Error SwitchEvidence::AttestationReport::get_measurements(std::unordered_map<int, std::vector<uint8_t>>& out_measurements) const {
    const SpdmMeasurementResponseMessage11* spdm_response = nullptr;
    Error error = get_spdm_response(spdm_response);
    if (error != Error::Ok) {
        return error;
    }

    const SpdmMeasurementRecordParser& parsed_measurement_records = spdm_response->get_parsed_measurement_records();
    const std::unordered_map<uint8_t, std::shared_ptr<const DmtfMeasurementBlock>>& all_measurement_blocks = parsed_measurement_records.get_all_measurement_blocks();
    for (auto it = all_measurement_blocks.begin(); it != all_measurement_blocks.end(); ++it) {
        uint8_t index = it->first;
        const std::vector<uint8_t>& measurement_value = it->second->get_measurement_value();
        out_measurements[static_cast<int>(index)-1] = measurement_value;
    }

    return Error::Ok;
}

Error SwitchEvidenceSourceFromJsonFile::create(const std::string& file_path, SwitchEvidenceSourceFromJsonFile& out_source) {
    std::string file_contents;
    Error error = readFileIntoString(file_path, file_contents);
    if (error != Error::Ok) {
        return error;
    }
    LOG_DEBUG("Deserializing switch evidence from file: " << file_path);
    return SwitchEvidence::collection_from_json(file_contents, out_source.m_evidence);
}

Error SwitchEvidenceSourceFromJsonFile::get_evidence(const std::vector<uint8_t>& nonce_input, std::vector<std::shared_ptr<SwitchEvidence>>& out_evidence) const {
    for (const auto& evidence_item : m_evidence) {
        if (evidence_item->get_nonce() != nonce_input) {
            LOG_ERROR("Nonce from switch evidence does not match the nonce used for attestation.");
            LOG_ERROR("Nonce from switch evidence: " << to_hex_string(evidence_item->get_nonce()) << " Nonce used for attestation: " << to_hex_string(nonce_input));
            LOG_ERROR("Does the nonce from serialized evidence JSON file match the nonce used for attestation?");
            return Error::SwitchEvidenceNonceMismatch;
        }
    }
    out_evidence = m_evidence;
    return Error::Ok;
}

}