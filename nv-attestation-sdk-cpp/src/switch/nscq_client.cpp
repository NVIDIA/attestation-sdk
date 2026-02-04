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
#include <mutex>
#include <dlfcn.h>

#include "nv_attestation/log.h"
#include "nv_attestation/error.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/switch/nscq_client.h"
#include "nv_attestation/switch/evidence.h"

namespace nvattestation {

using nscq_rc_t = int8_t;

constexpr nscq_rc_t NSCQ_RC_SUCCESS = 0;

struct nscq_session_st;
using nscq_session_t = nscq_session_st*;

using nscq_fn_t = void (*)(void);

constexpr unsigned int NSCQ_UUID_SIZE = 16;

struct nscq_uuid_t {
    uint8_t bytes[NSCQ_UUID_SIZE];
};

using nscq_arch_t = int8_t;

constexpr nscq_arch_t NSCQ_ARCH_SV10 = 0;
constexpr nscq_arch_t NSCQ_ARCH_LR10 = 1;
constexpr nscq_arch_t NSCQ_ARCH_LS10 = 2;

constexpr unsigned int NSCQ_LABEL_SIZE = 64;

struct nscq_label_t {
    char data[NSCQ_LABEL_SIZE];
};

using nscq_tnvl_status_t = int8_t;

constexpr nscq_tnvl_status_t NSCQ_DEVICE_TNVL_MODE_UNKNOWN = -1;
constexpr nscq_tnvl_status_t NSCQ_DEVICE_TNVL_MODE_DISABLED = 0;
constexpr nscq_tnvl_status_t NSCQ_DEVICE_TNVL_MODE_ENABLED = 1;
constexpr nscq_tnvl_status_t NSCQ_DEVICE_TNVL_MODE_FAILURE = 2;
constexpr nscq_tnvl_status_t NSCQ_DEVICE_TNVL_MODE_LOCKED = 3;

constexpr unsigned int NSCQ_ATTESTATION_REPORT_SIZE = 0x2000;

struct nscq_attestation_report_t {
    uint32_t report_size;
    uint8_t report[NSCQ_ATTESTATION_REPORT_SIZE];
};

constexpr unsigned int NSCQ_CERTIFICATE_CERT_CHAIN_MAX_SIZE = 0x1400;

struct nscq_attestation_certificate_t {
    uint8_t cert_chain[NSCQ_CERTIFICATE_CERT_CHAIN_MAX_SIZE];
    uint32_t cert_chain_size;
};

struct nscq_session_result_t {
    nscq_rc_t rc;
    nscq_session_t session;
};

constexpr uint32_t NSCQ_SESSION_CREATE_MOUNT_DEVICES = 0x1U;

constexpr const char* NSCQ_PATH_NVSWITCH_UUID = "/drv/nvswitch/{device}/uuid";
constexpr const char* NSCQ_PATH_NVSWITCH_ARCH = "/{nvswitch}/id/arch";
constexpr const char* NSCQ_PATH_PCIE_MODE = "/config/pcie_mode";
constexpr const char* NSCQ_PATH_CERTIFICATE = "/config/certificate";
constexpr const char* NSCQ_PATH_ATTESTATION_REPORT = "/config/attestation_report";

using nscq_session_create_t = nscq_session_result_t (*)(uint32_t);
using nscq_session_destroy_t = void (*)(nscq_session_t);
using nscq_session_path_observe_t = nscq_rc_t (*)(nscq_session_t, const char*, nscq_fn_t, void*, uint32_t);
using nscq_session_set_input_t = nscq_rc_t (*)(nscq_session_t, uint32_t, void*, uint32_t);
using nscq_uuid_to_label_t = nscq_rc_t (*)(const nscq_uuid_t*, nscq_label_t*, uint32_t);

struct NscqFunctions {
    void* library_handle = nullptr;

    nscq_session_create_t session_create = nullptr;
    nscq_session_destroy_t session_destroy = nullptr;
    nscq_session_path_observe_t session_path_observe = nullptr;
    nscq_session_set_input_t session_set_input = nullptr;
    nscq_uuid_to_label_t uuid_to_label = nullptr;

    NscqFunctions() = default;
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static NscqFunctions g_nscq_funcs;

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
bool g_nscq_initialized = false;

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static std::once_flag g_nscq_initialized_flag;

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static nscq_session_t g_nscq_session = nullptr;

static std::string nscq_rc_to_string(nscq_rc_t rc) {
    if (rc == NSCQ_RC_SUCCESS) {
        return "NSCQ_RC_SUCCESS";
    }
    if (rc > 0) {
        std::string desc = (rc == 1) ? "RDT init failure" : "Unknown";
        return "NSCQ_RC_WARNING: " + desc + " (Code " + std::to_string(rc) + ")";
    }
    std::string desc;
    // NOLINTBEGIN(readability-magic-numbers)
    switch (rc) {
        case -1:   desc = "Not implemented"; break;
        case -2:   desc = "Invalid UUID"; break;
        case -3:   desc = "Resource not mountable"; break;
        case -4:   desc = "Overflow"; break;
        case -5:   desc = "Unexpected value"; break;
        case -6:   desc = "Unsupported driver"; break;
        case -7:   desc = "Driver error"; break;
        case -8:   desc = "Timeout"; break;
        case -127: desc = "External error"; break;
        case -128: desc = "Unspecified"; break;
        default:   desc = "Unknown"; break;
    }
    // NOLINTEND(readability-magic-numbers)
    return "NSCQ_RC_ERROR: " + desc + " (Code " + std::to_string(rc) + ")";
}

static bool load_all_symbols(void* handle) {
    bool success = true;

    success = load_symbol(handle, "nscq_session_create", g_nscq_funcs.session_create) && success;
    success = load_symbol(handle, "nscq_session_destroy", g_nscq_funcs.session_destroy) && success;
    success = load_symbol(handle, "nscq_session_path_observe", g_nscq_funcs.session_path_observe) && success;
    success = load_symbol(handle, "nscq_session_set_input", g_nscq_funcs.session_set_input) && success;
    success = load_symbol(handle, "nscq_uuid_to_label", g_nscq_funcs.uuid_to_label) && success;
    
    return success;
}

Error init_nscq()
{
    // If already initialized, return Ok
    if (g_nscq_initialized) {
        return Error::Ok;
    }
    
    Error init_result = Error::NscqInitFailed;
    std::call_once(g_nscq_initialized_flag, [&init_result]() {
        LOG_DEBUG("Initializing NSCQ with dlopen");

        const std::string nscq_so = "libnvidia-nscq.so.2";
        g_nscq_funcs.library_handle = dlopen(nscq_so.c_str(), RTLD_LAZY | RTLD_LOCAL);
        if (g_nscq_funcs.library_handle == nullptr) {
            const char* error = dlerror();
            LOG_TRACE("Failed to load NSCQ library: " << nscq_so << "': " << (error ? error : "unknown error"));
            init_result = Error::NscqInitFailed;
            return;
        }
        LOG_TRACE("Successfully loaded NSCQ library: " << nscq_so);

        if (!load_all_symbols(g_nscq_funcs.library_handle)) {
            LOG_ERROR("Failed to load required NSCQ symbols");
            dlclose(g_nscq_funcs.library_handle);
            g_nscq_funcs.library_handle = nullptr;
            init_result = Error::NscqInitFailed;
            return;
        }
        LOG_TRACE("Successfully loaded all NSCQ symbols");
        
        nscq_session_result_t result = g_nscq_funcs.session_create(NSCQ_SESSION_CREATE_MOUNT_DEVICES);
        if (result.rc != NSCQ_RC_SUCCESS) {
            LOG_ERROR("Failed to create NSCQ session: " << nscq_rc_to_string(result.rc));
            dlclose(g_nscq_funcs.library_handle);
            g_nscq_funcs.library_handle = nullptr;
            init_result = Error::NscqInitFailed;
            return;
        }
        
        g_nscq_session = result.session;
        LOG_DEBUG("Successfully initialized NSCQ");
        g_nscq_initialized = true;
        init_result = Error::Ok;
    });
    
    return init_result;
}

void shutdown_nscq()
{
    if (!g_nscq_initialized || g_nscq_funcs.library_handle == nullptr) {
        return;
    }
    
    LOG_DEBUG("Shutting down NSCQ");
    
    g_nscq_funcs.session_destroy(g_nscq_session);
    g_nscq_session = nullptr;
    
    if (dlclose(g_nscq_funcs.library_handle) != 0) {
        const char* error = dlerror();
        LOG_ERROR("Failed to close NSCQ library: " << (error != nullptr ? error : "unknown error"));
    }
    
    g_nscq_funcs = NscqFunctions();
    g_nscq_initialized = false;
    LOG_DEBUG("Successfully shut down NSCQ");
}

static void uuid_callback(const nscq_uuid_t* device, nscq_rc_t rc, const nscq_uuid_t* uuid, void* user_data)
{
    if (rc != NSCQ_RC_SUCCESS) {
        LOG_ERROR("Error in UUID callback: " + nscq_rc_to_string(rc));
        return;
    }

    if (user_data == nullptr || uuid == nullptr) {
        LOG_ERROR("NSCQ callback received null user_data or uuid.");
        return;
    }

    auto* uuids = static_cast<std::vector<std::string>*>(user_data);
    nscq_label_t label{};

    nscq_rc_t label_rc = g_nscq_funcs.uuid_to_label(uuid, &label, 0);
    if (label_rc != NSCQ_RC_SUCCESS) {
        LOG_ERROR("Failed to convert NSCQ UUID to label: " + nscq_rc_to_string(label_rc));
        return;
    }

    uuids->emplace_back(std::string(label.data));
}

static void tnvl_status_callback(const nscq_uuid_t* device, nscq_rc_t rc, nscq_tnvl_status_t tnvl_status, void* user_data) {
    if (rc != NSCQ_RC_SUCCESS) {
        LOG_ERROR("TNVL status callback error: " + nscq_rc_to_string(rc));
        return;
    }

    if (user_data == nullptr) {
        LOG_ERROR("Null user_data in TNVL status callback");
        return;
    }

    *static_cast<SwitchTnvlMode*>(user_data) = static_cast<SwitchTnvlMode>(tnvl_status);
}

static void attestation_cert_chain_callback(const nscq_uuid_t* device, nscq_rc_t rc, const nscq_attestation_certificate_t cert, void* user_data) {
    if (rc != NSCQ_RC_SUCCESS) {
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

static void attestation_report_callback(const nscq_uuid_t* device, nscq_rc_t rc, const nscq_attestation_report_t report, void* user_data) {
    if (rc != NSCQ_RC_SUCCESS) {
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

static void architecture_callback(const nscq_uuid_t* device, nscq_rc_t rc, nscq_arch_t arch, void* user_data) {
    if (rc != NSCQ_RC_SUCCESS) {
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
    if (g_nscq_session == nullptr || g_nscq_funcs.session_path_observe == nullptr) {
        LOG_ERROR("NSCQ session not initialized");
        return Error::NscqError;
    }

    nscq_arch_t arch_val = static_cast<nscq_arch_t>(-1);

    nscq_rc_t observe_rc = g_nscq_funcs.session_path_observe(g_nscq_session, NSCQ_PATH_NVSWITCH_ARCH, reinterpret_cast<nscq_fn_t>(architecture_callback), &arch_val, 0);

    if (observe_rc != NSCQ_RC_SUCCESS) {
        LOG_ERROR("nscq_session_path_observe failed for switch architecture, error code: " + nscq_rc_to_string(observe_rc));
        return Error::NscqError;
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
            return Error::NscqError;
    }
}

Error get_all_switch_uuid(std::vector<std::string>& out_uuids) {
    if (g_nscq_session == nullptr || g_nscq_funcs.session_path_observe == nullptr) {
        LOG_ERROR("NSCQ session not initialized");
        return Error::NscqError;
    }

    out_uuids.clear();

    nscq_rc_t observe_rc = g_nscq_funcs.session_path_observe(g_nscq_session, NSCQ_PATH_NVSWITCH_UUID, reinterpret_cast<nscq_fn_t>(uuid_callback), static_cast<void*>(&out_uuids), 0);

    if (observe_rc != NSCQ_RC_SUCCESS) {
        LOG_ERROR("nscq_session_path_observe failed for switch UUIDs, error code: " + nscq_rc_to_string(observe_rc));
        return Error::NscqError;
    }
    return Error::Ok;
}

Error get_switch_tnvl_status(const std::string& uuid, SwitchTnvlMode& out_tnvl_mode) {
    if (g_nscq_session == nullptr || g_nscq_funcs.session_path_observe == nullptr) {
        LOG_ERROR("NSCQ session not initialized");
        return Error::NscqError;
    }

    if (uuid.empty()) {
        LOG_ERROR("Empty UUID provided");
        return Error::NscqError;
    }

    out_tnvl_mode = SwitchTnvlMode::Unknown;
    std::string path_str = "/" + uuid + NSCQ_PATH_PCIE_MODE;

    nscq_rc_t observe_rc = g_nscq_funcs.session_path_observe(g_nscq_session, path_str.c_str(), reinterpret_cast<nscq_fn_t>(tnvl_status_callback), &out_tnvl_mode, 0);

    if (observe_rc != NSCQ_RC_SUCCESS) {
        LOG_ERROR("nscq_session_path_observe failed for TNVL status, error code: " + nscq_rc_to_string(observe_rc));
        return Error::NscqError;
    }
    return Error::Ok;
}

Error get_attestation_cert_chain(const std::string& uuid, std::string& out_cert_chain) {
    if (g_nscq_session == nullptr || g_nscq_funcs.session_path_observe == nullptr) {
        LOG_ERROR("NSCQ session not initialized");
        return Error::NscqError;
    }

    if (uuid.empty()) {
        LOG_ERROR("Empty UUID provided");
        return Error::NscqError;
    }

    out_cert_chain.clear();
    std::string path = "/" + uuid + NSCQ_PATH_CERTIFICATE;

    nscq_rc_t observe_rc = g_nscq_funcs.session_path_observe(g_nscq_session, path.c_str(), reinterpret_cast<nscq_fn_t>(attestation_cert_chain_callback), &out_cert_chain, 0);

    if (observe_rc != NSCQ_RC_SUCCESS) {
        LOG_ERROR("Observe failed for cert chain: " + nscq_rc_to_string(observe_rc));
        return Error::NscqError;
    }

    if (out_cert_chain.empty()) {
        LOG_ERROR("Empty certificate chain received");
        return Error::NscqError;
    }

    return Error::Ok;
}

Error get_attestation_report(const std::string& uuid, const std::vector<uint8_t>& nonce_input, std::vector<uint8_t>& out_attestation_report) {
    if (g_nscq_session == nullptr || g_nscq_funcs.session_set_input == nullptr || g_nscq_funcs.session_path_observe == nullptr) {
        LOG_ERROR("NSCQ session not initialized");
        return Error::NscqError;
    }

    if (uuid.empty()) {
        LOG_ERROR("Empty UUID provided for attestation report");
        return Error::NscqError;
    }

    if (nonce_input.size() != NSCQ_ATTESTATION_REPORT_NONCE_SIZE) {
        LOG_ERROR("Nonce size is not " + std::to_string(NSCQ_ATTESTATION_REPORT_NONCE_SIZE));
        return Error::NscqError;
    }

    nscq_rc_t set_input_rc = g_nscq_funcs.session_set_input(g_nscq_session, 0, const_cast<uint8_t*>(nonce_input.data()), nonce_input.size());
    if (set_input_rc != NSCQ_RC_SUCCESS) {
        LOG_ERROR("nscq_session_set_input failed for attestation report nonce, error code: " + nscq_rc_to_string(set_input_rc));
        return Error::NscqError;
    }
    
    out_attestation_report.clear();
    std::string path = "/" + uuid + NSCQ_PATH_ATTESTATION_REPORT;

    nscq_rc_t observe_rc = g_nscq_funcs.session_path_observe(g_nscq_session, path.c_str(), reinterpret_cast<nscq_fn_t>(attestation_report_callback), &out_attestation_report, 0);

    if (observe_rc != NSCQ_RC_SUCCESS) {
        LOG_ERROR("nscq_session_path_observe failed for attestation report, error code: " + nscq_rc_to_string(observe_rc));
        return Error::NscqError;
    }
    
    if (out_attestation_report.empty()) {
        LOG_ERROR("Attestation report is empty.");
        return Error::NscqError;
    }

    return Error::Ok;
}

Error collect_evidence_nscq(const std::vector<uint8_t>& nonce_input, std::vector<std::shared_ptr<SwitchEvidence>>& out_evidence) {
    if (!g_nscq_initialized) {
        LOG_ERROR("NSCQ is not initialized");
        return Error::NscqError;
    }

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

        LOG_DEBUG("Collected evidence for switch with UUID: " << uuid);

        auto evidence = std::make_shared<SwitchEvidence>(
            arch,
            uuid,
            attestation_report,
            attestation_cert_chain,
            tnvl_mode,
            lock_mode,
            nonce_input
        );
        out_evidence.push_back(evidence);
    }

    return Error::Ok;
}

} // namespace nvattestation
