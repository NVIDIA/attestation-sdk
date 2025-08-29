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

#include <string>
#include <cstring>
#include <vector>
#include <iostream>
#include <memory>

#ifdef ENABLE_NSCQ
#include "nv_attestation/switch/nscq_attestation.h"
#endif // ENABLE_NSCQ

#include "nv_attestation/log.h"
#include "nv_attestation/error.h"
#include "nv_attestation/switch/nscq_client.h"
#include "nv_attestation/switch/evidence.h"
#include "nv_attestation/nv_types.h"

namespace nvattestation {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
bool g_nscq_initialized = false;

#ifdef ENABLE_NSCQ
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static nv_shared_ptr<nscq_session_st> g_nscq_session;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static std::once_flag g_nscq_initialized_flag;

static std::string nscq_rc_to_string(nscq_rc_t rc) {
    switch (rc) {
        case NSCQ_RC_SUCCESS: return "NSCQ_RC_SUCCESS";
        case NSCQ_RC_WARNING_RDT_INIT_FAILURE: return "NSCQ_RC_WARNING_RDT_INIT_FAILURE";
        case NSCQ_RC_ERROR_NOT_IMPLEMENTED: return "NSCQ_RC_ERROR_NOT_IMPLEMENTED";
        case NSCQ_RC_ERROR_INVALID_UUID: return "NSCQ_RC_ERROR_INVALID_UUID";
        case NSCQ_RC_ERROR_RESOURCE_NOT_MOUNTABLE: return "NSCQ_RC_ERROR_RESOURCE_NOT_MOUNTABLE";
        case NSCQ_RC_ERROR_OVERFLOW: return "NSCQ_RC_ERROR_OVERFLOW";
        case NSCQ_RC_ERROR_UNEXPECTED_VALUE: return "NSCQ_RC_ERROR_UNEXPECTED_VALUE";
        case NSCQ_RC_ERROR_UNSUPPORTED_DRV: return "NSCQ_RC_ERROR_UNSUPPORTED_DRV";
        case NSCQ_RC_ERROR_DRV: return "NSCQ_RC_ERROR_DRV";
        case NSCQ_RC_ERROR_TIMEOUT: return "NSCQ_RC_ERROR_TIMEOUT";
        case NSCQ_RC_ERROR_EXT: return "NSCQ_RC_ERROR_EXT";
        case NSCQ_RC_ERROR_UNSPECIFIED: return "NSCQ_RC_ERROR_UNSPECIFIED";
        default: return "Unknown NSCQ error code: " + std::to_string(rc);
    }
}

#endif // ENABLE_NSCQ

Error init_nscq() {
#ifdef ENABLE_NSCQ
    Error init_result = Error::NscqInitFailed;
    std::call_once(g_nscq_initialized_flag, [&init_result]() {
        LOG_DEBUG("Initializing NSCQ");
        nscq_session_result_t result = nscq_session_create(NSCQ_SESSION_CREATE_MOUNT_DEVICES);
        if (!NSCQ_SUCCESS(result.rc)) {
            LOG_ERROR("Failed to create NSCQ session, error code: " << nscq_rc_to_string(result.rc));
            init_result = Error::NscqInitFailed;
        }
        g_nscq_session = nv_shared_ptr<nscq_session_st>(result.session, DeleterOf<nscq_session_st>{});
        LOG_DEBUG("Succesfully initialized NSCQ");
        g_nscq_initialized = true;
        init_result = Error::Ok;
    });
    return init_result;
#else // ENABLE_NSCQ
    LOG_ERROR("ENABLE_NSCQ feature was not enabled during compilation");
    return Error::FeatureNotEnabled;
#endif // ENABLE_NSCQ
}

void shutdown_nscq() {
#ifdef ENABLE_NSCQ
    if (!g_nscq_session) {
        LOG_WARN("NSCQ session not initialized or already shut down.");
        return;
    }
    LOG_DEBUG("Shutting down NSCQ");
    g_nscq_session.reset();
#endif // ENABLE_NSCQ
}

#ifdef ENABLE_NSCQ

//UUID
static void uuid_callback(const nscq_uuid_t* device, nscq_rc_t rc, const nscq_uuid_t* uuid, void* user_data)
{
    if (!NSCQ_SUCCESS(rc)) {
        LOG_ERROR("Error in UUID callback: " + nscq_rc_to_string(rc));
        return;
    }

    if (user_data == nullptr || uuid == nullptr) {
        LOG_ERROR("NSCQ callback received null user_data or uuid.");
        return;
    }

    auto* uuids = static_cast<std::vector<std::string>*>(user_data);
    nscq_label_t label{};

    nscq_rc_t label_rc = nscq_uuid_to_label(uuid, &label, 0);
    if (!NSCQ_SUCCESS(label_rc)) {
        LOG_ERROR("Failed to convert NSCQ UUID to label: " + nscq_rc_to_string(label_rc));
        return;
    }

    uuids->emplace_back(std::string(label.data));
}

Error get_all_switch_uuid(std::vector<std::string>& out_uuids) {
    if (!g_nscq_session) {
        LOG_ERROR("NSCQ session not initialized");
        return Error::NscqError;
    }

    out_uuids.clear();
    const char* path = "/drv/nvswitch/{device}/uuid";

    nscq_rc_t observe_rc = nscq_session_path_observe(g_nscq_session.get(), path, NSCQ_FN(uuid_callback), static_cast<void*>(&out_uuids), 0);

    if (!NSCQ_SUCCESS(observe_rc)) {
        LOG_ERROR("nscq_session_path_observe failed for switch UUIDs, error code: " + nscq_rc_to_string(observe_rc));
        return Error::NscqUuidError;
    }
    return Error::Ok;
}

//TNVL status
static void tnvl_status_callback(const nscq_uuid_t* device, nscq_rc_t rc, nscq_tnvl_status_t tnvl_status, void* user_data) {
    if (!NSCQ_SUCCESS(rc)) {
        LOG_ERROR("TNVL status callback error: " + nscq_rc_to_string(rc));
        return;
    }

    if (user_data == nullptr) {
        LOG_ERROR("Null user_data in TNVL status callback");
        return;
    }

    *static_cast<SwitchTnvlMode*>(user_data) = static_cast<SwitchTnvlMode>(tnvl_status);
}

Error get_switch_tnvl_status(const std::string& uuid, SwitchTnvlMode& out_tnvl_mode) {
    if (!g_nscq_session) {
        LOG_ERROR("NSCQ session not initialized");
        return Error::NscqError;
    }

    if (uuid.empty()) {
        LOG_ERROR("Empty UUID provided");
        return Error::NscqTnvlError;
    }

    out_tnvl_mode = SwitchTnvlMode::Unknown;
    std::string path_str = "/" + uuid + "/config/pcie_mode";

    nscq_rc_t observe_rc = nscq_session_path_observe(g_nscq_session.get(), path_str.c_str(), NSCQ_FN(tnvl_status_callback), &out_tnvl_mode, 0);

    if (!NSCQ_SUCCESS(observe_rc)) {
        LOG_ERROR("nscq_session_path_observe failed for TNVL status, error code: " + nscq_rc_to_string(observe_rc));
        return Error::NscqTnvlError;
    }
    return Error::Ok;
}

//Attestation cert chain
static void attestation_cert_chain_callback(const nscq_uuid_t* device, nscq_rc_t rc, const nscq_attestation_certificate_t cert, void* user_data) {
    if (!NSCQ_SUCCESS(rc)) {
        LOG_ERROR("Cert chain callback error: " + nscq_rc_to_string(rc));
        return;
    }

    if (user_data == nullptr) {
        LOG_ERROR("Null user_data in cert chain callback");
        return;
    }

    std::string* cert_chain = static_cast<std::string*>(user_data);
    *cert_chain = std::string(reinterpret_cast<const char*>(cert.cert_chain), cert.cert_chain_size);
}

Error get_attestation_cert_chain(const std::string& uuid, std::string& out_cert_chain) {
    if (!g_nscq_session) {
        LOG_ERROR("NSCQ session not initialized");
        return Error::NscqError;
    }

    if (uuid.empty()) {
        LOG_ERROR("Empty UUID provided");
        return Error::NscqCertChainError;
    }

    out_cert_chain.clear();
    std::string path = "/" + uuid + "/config/certificate";

    nscq_rc_t observe_rc = nscq_session_path_observe(g_nscq_session.get(), path.c_str(), NSCQ_FN(attestation_cert_chain_callback), &out_cert_chain, 0);

    if (!NSCQ_SUCCESS(observe_rc)) {
        LOG_ERROR("Observe failed for cert chain: " + nscq_rc_to_string(observe_rc));
        return Error::NscqCertChainError;
    }

    if (out_cert_chain.empty()) {
        LOG_ERROR("Empty certificate chain received");
        return Error::NscqCertChainError;
    }

    return Error::Ok;
}

//Attestation report
static void attestation_report_callback(const nscq_uuid_t* device, nscq_rc_t rc, const nscq_attestation_report_t report, void* user_data) {
    if (!NSCQ_SUCCESS(rc)) {
        LOG_ERROR("Attestation report callback error: " + nscq_rc_to_string(rc));
        return;
    }

    if (user_data == nullptr) {
        LOG_ERROR("Null user_data in attestation report callback");
        return;
    }

    auto* report_data = static_cast<std::vector<uint8_t>*>(user_data);
    report_data->assign(report.report, report.report + report.report_size);
}

Error get_attestation_report(const std::string& uuid, const std::vector<uint8_t>& nonce_input, std::vector<uint8_t>& out_attestation_report) {
    if (!g_nscq_session) {
        LOG_ERROR("NSCQ session not initialized");
        return Error::NscqError;
    }

    if (uuid.empty()) {
        LOG_ERROR("Empty UUID provided for attestation report");
        return Error::NscqAttestationReportError;
    }

    if (nonce_input.size() != NSCQ_ATTESTATION_REPORT_NONCE_SIZE) {
        LOG_ERROR("Nonce size is not " + std::to_string(NSCQ_ATTESTATION_REPORT_NONCE_SIZE));
        return Error::NscqAttestationReportError;
    }

    nscq_rc_t set_input_rc = nscq_session_set_input(g_nscq_session.get(), 0, const_cast<uint8_t*>(nonce_input.data()), nonce_input.size());
    if (!NSCQ_SUCCESS(set_input_rc)) {
        LOG_ERROR("nscq_session_set_input failed for attestation report nonce, error code: " + nscq_rc_to_string(set_input_rc));
        return Error::NscqAttestationReportError;
    }
    
    out_attestation_report.clear();
    std::string path = "/" + uuid + "/config/attestation_report";

    nscq_rc_t observe_rc = nscq_session_path_observe(g_nscq_session.get(), path.c_str(), NSCQ_FN(attestation_report_callback), &out_attestation_report, 0);

    if (!NSCQ_SUCCESS(observe_rc)) {
        LOG_ERROR("nscq_session_path_observe failed for attestation report, error code: " + nscq_rc_to_string(observe_rc));
        return Error::NscqAttestationReportError;
    }
    
    if (out_attestation_report.empty()) {
        LOG_ERROR("Attestation report is empty.");
        return Error::NscqAttestationReportError;
    }

    return Error::Ok;
}

//Architecture
static void architecture_callback(const nscq_uuid_t* device, nscq_rc_t rc, nscq_arch_t arch, void* user_data) {
    if (!NSCQ_SUCCESS(rc)) {
        LOG_ERROR("Architecture callback error: " + nscq_rc_to_string(rc));
        return;
    }

    if (user_data == nullptr) {
        LOG_ERROR("Null user_data in architecture callback");
        return;
    }

    *static_cast<nscq_arch_t*>(user_data) = arch;
}

Error get_switch_architecture(SwitchArchitecture& out_arch) {
    if (!g_nscq_session) {
        LOG_ERROR("NSCQ session not initialized");
        return Error::NscqError;
    }

    nscq_arch_t arch_val = static_cast<nscq_arch_t>(-1);
    const char* path = "/{nvswitch}/id/arch"; 

    nscq_rc_t observe_rc = nscq_session_path_observe(g_nscq_session.get(), path, NSCQ_FN(architecture_callback), &arch_val, 0);

    if (!NSCQ_SUCCESS(observe_rc)) {
        LOG_ERROR("nscq_session_path_observe failed for switch architecture, error code: " + nscq_rc_to_string(observe_rc));
        return Error::NscqArchitectureError;
    }

    switch (arch_val) {
        case NSCQ_ARCH_SV10: 
            out_arch = SwitchArchitecture::SV10;
            return Error::Ok;
        case NSCQ_ARCH_LR10: 
            out_arch = SwitchArchitecture::LR10;
            return Error::Ok;
        case NSCQ_ARCH_LS10: 
            out_arch = SwitchArchitecture::LS10;
            return Error::Ok;
        default: 
            LOG_ERROR("Unknown switch architecture: " + std::to_string(arch_val));
            return Error::NscqArchitectureError;
    }
}

#endif // ENABLE_NSCQ

}
