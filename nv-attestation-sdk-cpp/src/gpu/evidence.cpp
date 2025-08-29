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
#include <stdexcept>

#include "nv_attestation/gpu/evidence.h"
#include "nv_attestation/log.h"
#include "nv_attestation/error.h"
#include <nlohmann/json.hpp>

#ifdef ENABLE_NVML
#include "nv_attestation/gpu/nvml_client.h"
#include <nvml.h>
#endif // ENABLE_NVML

#include "nv_attestation/nv_x509.h"
#include "nv_attestation/spdm/spdm_req.hpp"
#include "nv_attestation/spdm/spdm_resp.hpp"
#include "nv_attestation/utils.h"
#include "internal/certs.h"

using json = nlohmann::json;

namespace nvattestation
{

const std::vector<GpuArchitecture> GpuArchitectureData::m_supported_architectures = {
    GpuArchitecture::Hopper,
    GpuArchitecture::Blackwell,
};

Error GpuArchitectureData::create(GpuArchitecture arch, GpuArchitectureData& out_arch_data) {
    if (std::find(m_supported_architectures.begin(), m_supported_architectures.end(), arch) == m_supported_architectures.end()) {
        LOG_PUSH_ERROR(Error::GpuArchitectureNotSupported, "GPU architecture " + to_string(arch) + " is not supported.");
        return Error::GpuArchitectureNotSupported;
    }
    out_arch_data.m_arch = arch;
    switch (arch) {
        case GpuArchitecture::Hopper:
            out_arch_data.m_ar_signature_hash_algorithm = EVP_sha384();
            // NOLINTNEXTLINE(readability-magic-numbers)
            out_arch_data.m_ar_signature_length = 96;
            out_arch_data.m_fwid_type = X509CertChain::FWIDType::FWID_2_23_133_5_4_1;
            break;
        case GpuArchitecture::Blackwell:
            out_arch_data.m_ar_signature_hash_algorithm = EVP_sha384();
            // NOLINTNEXTLINE(readability-magic-numbers)
            out_arch_data.m_ar_signature_length = 96;
            out_arch_data.m_fwid_type = X509CertChain::FWIDType::FWID_2_23_133_5_4_1_1;
            break;
        default:
            LOG_PUSH_ERROR(Error::GpuArchitectureNotSupported, "GPU architecture " + to_string(arch) + " is not supported.");
            return Error::GpuArchitectureNotSupported;
    }
    return Error::Ok;
}

void to_json(json& out_json, const GpuEvidence& evidence) {
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
        {"arch", to_string(evidence.get_gpu_architecture())},
        {"nonce", evidence.get_hex_nonce()},
        {"vbios_version", evidence.get_vbios_version()},
        {"driver_version", evidence.get_driver_version()},
        {"evidence", encoded_evidence},
        {"certificate", encoded_certificate},
    };
}

void from_json(const json& json, GpuEvidence& out_evidence) {
    std::string version = json.at("version").get<std::string>();
    if (version != "1.0") {
        throw std::runtime_error("Unsupported version: " + version);
    }
    std::string arch_str = json.at("arch").get<std::string>();
    GpuArchitecture architecture = GpuArchitecture::Unknown;
    from_string(arch_str, architecture);
    if (architecture == GpuArchitecture::Unknown) {
        throw std::runtime_error("Unknown GPU architecture: " + arch_str);
    }
    out_evidence.set_gpu_architecture(architecture);

    std::string nonce_str = json.at("nonce").get<std::string>();
    std::vector<uint8_t> nonce = hex_string_to_bytes(nonce_str);
    out_evidence.set_nonce(nonce);

    std::string vbios_version = json.at("vbios_version").get<std::string>();
    out_evidence.set_vbios_version(vbios_version);

    std::string driver_version = json.at("driver_version").get<std::string>();
    out_evidence.set_driver_version(driver_version);

    std::string evidence_base64 = json.at("evidence").get<std::string>();
    std::vector<uint8_t> attestation_report;
    Error error = decode_base64(evidence_base64, attestation_report);
    if (error != Error::Ok) {
        throw std::runtime_error("Failed to decode evidence: " + std::string(to_string(error)));
    }
    out_evidence.set_attestation_report(attestation_report);

    std::string certificate_base64 = json.at("certificate").get<std::string>();
    std::string certificate_str;
    error = decode_base64(certificate_base64, certificate_str);
    if (error != Error::Ok) {
        throw std::runtime_error("Failed to decode certificate: " + std::string(to_string(error)));
    }
    out_evidence.set_attestation_cert_chain(certificate_str);
}

Error GpuEvidence::to_json(std::string& out_string) const {
    return serialize_to_json(*this, out_string);
}

Error GpuEvidence::collection_to_json(const std::vector<GpuEvidence>& collection, std::string& out_string) {
    return serialize_to_json(collection, out_string);
}

Error GpuEvidence::collection_from_json(const std::string& json_string, std::vector<GpuEvidence>& out_collection) {
    return deserialize_from_json(json_string, out_collection);
}

std::string to_string(GpuArchitecture arch) {
    switch (arch) {
        case GpuArchitecture::Hopper: return "HOPPER";
        case GpuArchitecture::Blackwell: return "BLACKWELL";
        default: return "UNKNOWN";
    }
}

void from_string(const std::string& arch_str, GpuArchitecture& out_arch) {
    if (arch_str == "HOPPER") {
        out_arch = GpuArchitecture::Hopper;
        return;
    }
    if (arch_str == "BLACKWELL") {
        out_arch = GpuArchitecture::Blackwell;
        return;
    }
    LOG_ERROR("Unknown GPU architecture: " << arch_str);
    out_arch = GpuArchitecture::Unknown;
}

Error NvmlEvidenceCollector::get_evidence(const std::vector<uint8_t>& nonce_input, std::vector<GpuEvidence>& out_evidence) const // NOLINT(readability-function-cognitive-complexity)
{
#ifdef ENABLE_NVML
    // Calculate the number of devices
    unsigned int device_count = 0;
    nvmlReturn_t result = nvmlDeviceGetCount(&device_count);
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to get device count: " << std::string(nvmlErrorString(result)));
        return Error::NvmlError;
    }

    if (device_count == 0) {
        LOG_ERROR("No GPUs available");
        return Error::NvmlError;
    }

    auto evidence_list = std::make_unique<std::vector<GpuEvidence>>();

    // Driver version
    std::unique_ptr<std::string> driver_version_ptr = get_driver_version();
    if (!driver_version_ptr) {
        LOG_ERROR("Failed to get driver version");
        return Error::NvmlError;
    }

    for (unsigned int i = 0; i < device_count; ++i) {
        nvmlDevice_t device_handle{};
        result = nvmlDeviceGetHandleByIndex(i, &device_handle);
        if (result != NVML_SUCCESS) {
            LOG_ERROR("Failed to get handle for GPU index " << i << ": " << nvmlErrorString(result));
            return Error::NvmlError;
        }

        std::unique_ptr<GpuArchitecture> architecture_enum_ptr = get_gpu_architecture(device_handle);
        if (!architecture_enum_ptr) {
            LOG_ERROR("Failed to get GPU architecture for GPU index " << i);
            return Error::NvmlError;
        }

        unsigned int board_id = 0;
        result = nvmlDeviceGetBoardId(device_handle, &board_id);
        if (result != NVML_SUCCESS) {
                LOG_ERROR("Failed to get board ID for GPU index " << i << ": " << nvmlErrorString(result));
                return Error::NvmlError;
        }
        
        std::unique_ptr<std::string> uuid_ptr = get_uuid(device_handle);
        if (!uuid_ptr){
            LOG_ERROR("Failed to get UUID for GPU index " << i);
            return Error::NvmlError;
        }

        std::unique_ptr<std::string> vbios_version_ptr = get_vbios_version(device_handle);
        if (!vbios_version_ptr){
            LOG_ERROR("Failed to get VBIOS version for GPU index " << i);
            return Error::NvmlError;
        }
        
        std::unique_ptr<std::vector<uint8_t>> attestation_report_ptr = get_attestation_report(device_handle, nonce_input);
        if (!attestation_report_ptr) {
            LOG_ERROR("Failed to fetch attestation report for GPU index " << i);
            return Error::NvmlError;
        }

        std::unique_ptr<std::string> attestation_cert_chain_ptr = get_attestation_cert_chain(device_handle);
        if (!attestation_cert_chain_ptr) {
            LOG_ERROR("Failed to get GPU certificate for GPU index " << i);
            return Error::NvmlError;
        }
        
        out_evidence.emplace_back(
            *architecture_enum_ptr,
            board_id,
            *uuid_ptr,
            *vbios_version_ptr,
            *driver_version_ptr,
            *attestation_report_ptr,
            *attestation_cert_chain_ptr,
            nonce_input
        );
    }
    
    return Error::Ok;
#else
    LOG_ERROR("ENABLE_NVML feature was not enabled during compilation");
    return Error::FeatureNotEnabled;
#endif // ENABLE_NVML
}

Error GpuEvidence::get_parsed_attestation_report(GpuEvidence::AttestationReport& out_attestation_report) const {
    return AttestationReport::create(m_attestation_report, m_attestation_cert_chain, m_gpu_architecture, out_attestation_report);
}

Error GpuEvidence::generate_gpu_evidence_claims(const GpuEvidence::AttestationReport& attestation_report, const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, GpuEvidenceClaims& out_gpu_evidence_claims) const {
    LOG_DEBUG("Generating GPU evidence claims");
    Error error = attestation_report.get_driver_version(out_gpu_evidence_claims.m_driver_version);
    if (error != Error::Ok) {
        return error;
    }
    error = attestation_report.get_vbios_version(out_gpu_evidence_claims.m_vbios_version);
    if (error != Error::Ok) {
        return error;
    }

    std::string driver_version_from_nvml = get_driver_version();
    if (driver_version_from_nvml != out_gpu_evidence_claims.m_driver_version) {
        LOG_ERROR("Driver RIM version mismatch: driver rim version from NVML: " << driver_version_from_nvml << " != gpu evidence driver version: " << out_gpu_evidence_claims.m_driver_version);
        return Error::GpuEvidenceDriverRimVersionMismatch;
    }

    std::string vbios_version_from_nvml = get_vbios_version();
    if (vbios_version_from_nvml != out_gpu_evidence_claims.m_vbios_version) {
        LOG_ERROR("VBIOS RIM version mismatch: vbios rim version from NVML: " << vbios_version_from_nvml << " != gpu evidence vbios version: " << out_gpu_evidence_claims.m_vbios_version);
        return Error::GpuEvidenceVbiosRimVersionMismatch;
    }

    GpuArchitectureData arch_data;
    error = GpuArchitectureData::create(m_gpu_architecture, arch_data);
    if (error != Error::Ok) {
        return error;
    }

    out_gpu_evidence_claims.m_gpu_ar_arch_match = true;
    
    const SpdmMeasurementRequestMessage11* spdm_request = nullptr;
    error = attestation_report.get_spdm_request(spdm_request);
    if (error != Error::Ok) {
        return error;
    }
    LOG_TRACE("Nonce from attestation report: " << to_hex_string(spdm_request->get_nonce()));
    LOG_TRACE("Nonce from evidence: " << to_hex_string(m_nonce));
    auto nonce_from_ar = spdm_request->get_nonce();
    if (nonce_from_ar.size() != m_nonce.size()) {
        LOG_ERROR("Nonce size mismatch. nonce_from_ar: " + std::to_string(nonce_from_ar.size()) + " m_nonce: " + std::to_string(m_nonce.size()));
        return Error::GpuEvidenceNonceMismatch;
    }
    if (memcmp(nonce_from_ar.data(), m_nonce.data(), nonce_from_ar.size()) != 0) {
        std::vector<uint8_t> nonce_from_ar_vec(nonce_from_ar.begin(), nonce_from_ar.end());
        LOG_ERROR("Nonce mismatch. nonce_from_ar: " + to_hex_string(nonce_from_ar_vec) + " m_nonce: " + to_hex_string(m_nonce));
        return Error::GpuEvidenceNonceMismatch;
    }
    out_gpu_evidence_claims.m_gpu_ar_nonce_match = true;

    error = attestation_report.generate_attestation_report_claims(ocsp_verify_options, ocsp_client, arch_data, out_gpu_evidence_claims.m_attestation_report_claims);
    if (error != Error::Ok) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to generate attestation report claims.");
        return Error::InternalError;
    }
    return Error::Ok;
}

Error GpuEvidence::AttestationReport::generate_attestation_report_claims(const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, GpuArchitectureData arch_data, GpuEvidenceClaims::AttestationReportClaims& out_attestation_report_claims) const {
    // this will be always true since if the report was not parsed, the object would not have been created
    // happens in the create function
    out_attestation_report_claims.m_parsed = true;
    // this will be always true since the report signature is verified in the create function
    out_attestation_report_claims.m_signature_verified = true;

    const std::vector<uint8_t>* fwid = nullptr;
    Error error = get_fwid(fwid);
    if (error != Error::Ok && error != Error::SpdmFieldNotFound) {
        return error;
    }
    if (error == Error::Ok) {
        LOG_DEBUG("FWID found in attestation report " << to_hex_string(*fwid));
        std::vector<uint8_t> cert_fwid;
        error = m_attestation_cert_chain.get_fwid(0, arch_data.m_fwid_type, cert_fwid);
        if (error != Error::Ok) {
            return error;
        }
        if (fwid->size() != cert_fwid.size() || memcmp(fwid->data(), cert_fwid.data(), fwid->size()) != 0) {
            LOG_ERROR("FWID mismatch. fwid: " + to_hex_string(*fwid) + " cert_fwid: " + to_hex_string(cert_fwid));
            out_attestation_report_claims.m_fwid_match = false;
            return Error::GpuEvidenceFwidMismatch;
        }
        out_attestation_report_claims.m_fwid_match = true;
    } else if (error == Error::SpdmFieldNotFound) {
        out_attestation_report_claims.m_fwid_match = true;
    }

    error = m_attestation_cert_chain.generate_cert_chain_claims(ocsp_verify_options, ocsp_client, out_attestation_report_claims.m_cert_chain_claims);
    if (error != Error::Ok) {
        return error;
    }

    return Error::Ok;
}

Error GpuEvidence::AttestationReport::get_spdm_request(const SpdmMeasurementRequestMessage11*& out_spdm_request) const {
    out_spdm_request = &m_spdm_request;
    return Error::Ok;
}

Error GpuEvidence::AttestationReport::create(const std::vector<uint8_t>& attestation_report_data, const std::string& ar_cert_chain, GpuArchitecture architecture, AttestationReport& out_attestation_report) {

    Error error = X509CertChain::create_from_cert_chain_str(CertificateChainType::GPU_DEVICE_IDENTITY, DEVICE_ROOT_CERT, ar_cert_chain, out_attestation_report.m_attestation_cert_chain);
    if (error != Error::Ok) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to parse attestation certificate chain.");
        return Error::InternalError;
    }

    // Ensure attestation_report_data is large enough before attempting to split
    GpuArchitectureData arch_data;
    error = GpuArchitectureData::create(architecture, arch_data);
    if (error != Error::Ok) {
        return error;
    }
    if (attestation_report_data.size() <= arch_data.get_ar_signature_length()) {
        LOG_PUSH_ERROR(Error::InternalError, "Attestation report data is too short.");
        return Error::InternalError;
    }

    std::ptrdiff_t ar_signature_length = static_cast<std::ptrdiff_t>(arch_data.get_ar_signature_length());
    std::vector<uint8_t> data_wo_signature(attestation_report_data.begin(), attestation_report_data.end() - ar_signature_length);
    std::vector<uint8_t> signature(attestation_report_data.end() - ar_signature_length, attestation_report_data.end());
    
    error = out_attestation_report.m_attestation_cert_chain.verify_signature_pkcs11(data_wo_signature, signature, arch_data.get_ar_signature_hash_algorithm());
    if (error != Error::Ok) { 
        LOG_ERROR("Failed to verify attestation report signature.");
        return Error::GpuEvidenceInvalidSignature;
    }

    std::ptrdiff_t spdm_request_length = static_cast<std::ptrdiff_t>(SpdmMeasurementRequestMessage11::get_request_length());
    std::vector<uint8_t> spdm_request(attestation_report_data.begin(), attestation_report_data.begin() + spdm_request_length);
    error = SpdmMeasurementRequestMessage11::create(spdm_request, out_attestation_report.m_spdm_request);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to parse SPDM request.");
        return Error::GpuEvidenceInvalid;
    }

    std::vector<uint8_t> spdm_response(attestation_report_data.begin() + spdm_request_length, attestation_report_data.end());
    error = SpdmMeasurementResponseMessage11::create(spdm_response, arch_data.get_ar_signature_length(), out_attestation_report.m_spdm_response);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to parse SPDM response.");
        return Error::GpuEvidenceInvalid;
    }

    const std::vector<ParsedOpaqueFieldData>* parsed_opaque_data_ptr = nullptr;
    error = out_attestation_report.m_spdm_response.get_parsed_opaque_data(parsed_opaque_data_ptr);
    if (error != Error::Ok) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to parse GPU opaque data.");
        return Error::InternalError;
    }

    error = GpuOpaqueDataParser::create(*parsed_opaque_data_ptr, out_attestation_report.m_gpu_opaque_data_parser);
    if (error != Error::Ok) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to parse GPU opaque data.");
        return Error::InternalError;
    }

    return Error::Ok;
}

Error GpuEvidence::AttestationReport::get_driver_version(std::string& out_driver_version) const {
    const GpuParsedOpaqueFieldData* driver_version_field = nullptr;
    Error error = m_gpu_opaque_data_parser.get_field(GpuOpaqueDataType::DRIVER_VERSION, driver_version_field);
    if (error != Error::Ok) {
        return error;
    }
    const std::vector<uint8_t>* driver_version_data = nullptr;
    error = driver_version_field->get_byte_vector(driver_version_data);
    if (error != Error::Ok) {
        return error;
    }
    out_driver_version = std::string(driver_version_data->begin(), driver_version_data->end());
    remove_null_terminators(out_driver_version);
    return Error::Ok;
}

Error GpuEvidence::AttestationReport::get_vbios_version(std::string& out_vbios_version) const {
    const GpuParsedOpaqueFieldData* vbios_version_field = nullptr;
    Error error = m_gpu_opaque_data_parser.get_field(GpuOpaqueDataType::VBIOS_VERSION, vbios_version_field);
    if (error != Error::Ok) {
        return error;
    }
    const std::vector<uint8_t>* vbios_version_data = nullptr;
    error = vbios_version_field->get_byte_vector(vbios_version_data);
    if (error != Error::Ok) {
        return error;
    }

    std::vector<uint8_t> vbios_version_data_vec(*vbios_version_data);
    //reverse the vector
    std::reverse(vbios_version_data_vec.begin(), vbios_version_data_vec.end());
    std::string hex_value = to_hex_string(vbios_version_data_vec);
    
    // why is this done? if someone ever finds out, pls update this comment
    size_t half_len = hex_value.length() / 2;
    std::string second_half = hex_value.substr(half_len);  
    std::string before_middle = hex_value.substr(half_len - 2, 2);  
    std::string temp = second_half + before_middle;
    
    // Format as xx.xx.xx.xx.xx by taking pairs and adding dots
    std::string result;
    size_t hex_pair_idx = 0;
    for (hex_pair_idx = 0; hex_pair_idx < temp.length(); hex_pair_idx += 2) {
        if (!result.empty()) {
            result += ".";
        }
        result += temp.substr(hex_pair_idx, 2);
    }
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    remove_null_terminators(result);
    out_vbios_version = result;
    return Error::Ok;
}

Error GpuEvidence::AttestationReport::get_fwid(const std::vector<uint8_t>*& out_fwid) const {
    const GpuParsedOpaqueFieldData* fwid_field = nullptr;
    Error error = m_gpu_opaque_data_parser.get_field(GpuOpaqueDataType::FWID, fwid_field);
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

Error GpuEvidence::AttestationReport::get_driver_rim_id(GpuArchitecture architecture, std::string& out_driver_rim_id) const {
    std::string driver_version;
    Error error = get_driver_version(driver_version);
    if (error != Error::Ok) {
        return error;
    }

    // todo(p0): take the chip type
    if (architecture == GpuArchitecture::Hopper) {
        out_driver_rim_id = "NV_GPU_DRIVER_GH100_" + driver_version;
    } else if (architecture == GpuArchitecture::Blackwell) {
        out_driver_rim_id = "NV_GPU_CC_DRIVER_GB100_" + driver_version;
    } else {
        LOG_ERROR("Unsupported GPU architecture: ");
        return Error::InternalError;
    }

    return Error::Ok;
}

Error GpuEvidence::AttestationReport::get_vbios_rim_id(std::string& out_vbios_rim_id) const {
    const GpuParsedOpaqueFieldData* project_id_field = nullptr;
    Error error = m_gpu_opaque_data_parser.get_field(GpuOpaqueDataType::PROJECT, project_id_field);
    if (error != Error::Ok) {
        return error;
    }

    const std::vector<uint8_t>* project_id_data = nullptr;
    error = project_id_field->get_byte_vector(project_id_data);
    if (error != Error::Ok) {
        return error;
    }

    std::string project_id(project_id_data->begin(), project_id_data->end());
    remove_null_terminators(project_id);

    const GpuParsedOpaqueFieldData* project_sku_field = nullptr;
    error = m_gpu_opaque_data_parser.get_field(GpuOpaqueDataType::PROJECT_SKU, project_sku_field);
    if (error != Error::Ok) {
        return error;
    }

    const std::vector<uint8_t>* project_sku_data = nullptr;

    error = project_sku_field->get_byte_vector(project_sku_data);
    if (error != Error::Ok) {
        return error;
    }

    std::string project_sku(project_sku_data->begin(), project_sku_data->end());
    remove_null_terminators(project_sku);

    const GpuParsedOpaqueFieldData* chip_sku_field = nullptr;
    error = m_gpu_opaque_data_parser.get_field(GpuOpaqueDataType::CHIP_SKU, chip_sku_field);
    if (error != Error::Ok) {
        return error;
    }

    const std::vector<uint8_t>* chip_sku_data = nullptr;
    error = chip_sku_field->get_byte_vector(chip_sku_data);
    if (error != Error::Ok) {
        return error;
    }

    std::string chip_sku(chip_sku_data->begin(), chip_sku_data->end());
    remove_null_terminators(chip_sku);

    std::string vbios_version;
    error = get_vbios_version(vbios_version);
    if (error != Error::Ok) {
        return error;
    }

    //replce "." with "" in vbio version and make it uppercase
    vbios_version.erase(std::remove(vbios_version.begin(), vbios_version.end(), '.'), vbios_version.end());

    out_vbios_rim_id = "NV_GPU_VBIOS_" + project_id + "_" + project_sku + "_" + chip_sku + "_" + vbios_version;
    return Error::Ok;
}

Error GpuEvidence::AttestationReport::get_nvdec0_status(uint8_t& out_nvdec0_status) const {

    const GpuParsedOpaqueFieldData* nvdec0_field = nullptr;
    Error error = m_gpu_opaque_data_parser.get_field(GpuOpaqueDataType::NVDEC0_STATUS, nvdec0_field);
    if (error != Error::Ok) {
        return error;
    }
    const std::vector<uint8_t>* nvdec0_data = nullptr;
    error = nvdec0_field->get_byte_vector(nvdec0_data);
    if (error != Error::Ok) {
        return error;
    }
    out_nvdec0_status = nvdec0_data->at(0);
    return Error::Ok;
}

Error GpuEvidence::AttestationReport::get_measurements(std::unordered_map<int, std::vector<uint8_t>>& out_measurements) const {
    const SpdmMeasurementRecordParser& parsed_measurement_records = m_spdm_response.get_parsed_measurement_records();

    // Get all available measurement indices
    const std::unordered_map<uint8_t, std::shared_ptr<const DmtfMeasurementBlock>>& all_measurement_blocks = parsed_measurement_records.get_all_measurement_blocks();
    // Extract measurement value for each index
    for (auto it = all_measurement_blocks.begin(); it != all_measurement_blocks.end(); ++it) {
        uint8_t index = it->first;
        const std::vector<uint8_t>& measurement_value = it->second->get_measurement_value();
        out_measurements[static_cast<int>(index)-1] = measurement_value;
    }
    
    return Error::Ok;
}

std::string GpuEvidence::get_hex_nonce() const {
    return to_hex_string(m_nonce);
}

Error GpuEvidenceSourceFromJsonFile::create(const std::string& file_path, GpuEvidenceSourceFromJsonFile& out_source) {
    // read all the contents of the file into a string
    if (file_path.empty()) {
        LOG_ERROR("File to read evidence is empty.");
        return Error::BadArgument;
    }

    std::string file_contents;
    Error error = readFileIntoString(file_path, file_contents);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to read file: " << file_path);
        return error;
    }

    // deserialize the evidence from the string
    LOG_DEBUG("Deserializing gpu evidence from file: " << file_path);
    return GpuEvidence::collection_from_json(file_contents, out_source.m_evidence);

}

Error GpuEvidenceSourceFromJsonFile::get_evidence(const std::vector<uint8_t>& nonce_input, std::vector<GpuEvidence>& out_evidence) const {
    out_evidence = m_evidence;
    return Error::Ok;
}


// << operator for GpuEvidenceClaims::AttestationReportClaims
std::ostream& operator<<(std::ostream& os, const GpuEvidenceClaims::AttestationReportClaims& claims) {
    os << "--- Attestation Report Claims ---" << std::endl;
    os << "Parsed: " << (claims.m_parsed ? "true" : "false") << std::endl;
    os << "Signature Verified: " << (claims.m_signature_verified ? "true" : "false") << std::endl;
    os << "FWID Match: " << (claims.m_fwid_match ? "true" : "false") << std::endl;
    os << std::endl;
    os << claims.m_cert_chain_claims;
    return os;
}

// << operator for GpuEvidenceClaims
std::ostream& operator<<(std::ostream& os, const GpuEvidenceClaims& claims) {
    os << "\n=== GPU Evidence Claims Debug Output ===" << std::endl;
    
    // Basic string fields
    os << "Driver Version: " << claims.m_driver_version << std::endl;
    os << "VBios Version: " << claims.m_vbios_version << std::endl;
    
    // Boolean match fields
    os << "Architecture Match: " << (claims.m_gpu_ar_arch_match ? "true" : "false") << std::endl;
    os << "Nonce Match: " << (claims.m_gpu_ar_nonce_match ? "true" : "false") << std::endl;
    
    os << std::endl;
    os << claims.m_attestation_report_claims;
    
    os << "========================================\n" << std::endl;
    
    return os;
}

std::ostream& operator<<(std::ostream& os, const GpuEvidence& evidence) {
    os << "--- GPU Evidence ---" << std::endl;
    os << "GPU Architecture: " << to_string(evidence.get_gpu_architecture()) << std::endl;
    os << "Nonce: " << evidence.get_hex_nonce() << std::endl;
    os << "VBios Version: " << evidence.get_vbios_version() << std::endl;
    os << "Driver Version: " << evidence.get_driver_version() << std::endl;
    os << "Attestation Report: " << to_hex_string(evidence.get_attestation_report()) << std::endl;
    os << "Attestation Cert Chain: " << evidence.get_attestation_cert_chain() << std::endl;
    return os;
}
}
