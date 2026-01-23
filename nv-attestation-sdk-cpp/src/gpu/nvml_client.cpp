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
#include <memory>
#include <algorithm>
#include <mutex>
#include <dlfcn.h>

#include "nv_attestation/log.h"
#include "nv_attestation/error.h"
#include "nv_attestation/gpu/nvml_client.h"
#include "nv_attestation/gpu/evidence.h"

namespace nvattestation {

using nvmlReturn_t = int;

constexpr nvmlReturn_t NVML_SUCCESS = 0;

using nvmlDevice_t = void*;

#define NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE 80
#define NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE 32
#define NVML_DEVICE_UUID_BUFFER_SIZE 80

#define NVML_CC_SYSTEM_FEATURE_DISABLED 0
#define NVML_CC_SYSTEM_FEATURE_ENABLED  1

typedef struct {
    unsigned int environment;
    unsigned int ccFeature;
    unsigned int devToolsMode;
} nvmlConfComputeSystemState_t;

#define NVML_GPU_CERT_CHAIN_SIZE 0x1000
#define NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE 0x1400
typedef struct {
    unsigned int certChainSize;
    unsigned int attestationCertChainSize;
    unsigned char certChain[NVML_GPU_CERT_CHAIN_SIZE];
    unsigned char attestationCertChain[NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE];
} nvmlConfComputeGpuCertificate_t;

#define NVML_CC_GPU_CEC_NONCE_SIZE 0x20
#define NVML_CC_GPU_ATTESTATION_REPORT_SIZE 0x2000
#define NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE 0x1000
#define NVML_CONF_COMPUTE_GPU_NONCE_SIZE 32
typedef struct {
    unsigned int isCecAttestationReportPresent;
    unsigned int attestationReportSize;
    unsigned int cecAttestationReportSize;
    unsigned char nonce[NVML_CC_GPU_CEC_NONCE_SIZE];
    unsigned char attestationReport[NVML_CC_GPU_ATTESTATION_REPORT_SIZE ];
    unsigned char cecAttestationReport[NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE ];
} nvmlConfComputeGpuAttestationReport_t;

using nvmlDeviceArchitecture_t = unsigned int;
constexpr unsigned int NVML_DEVICE_ARCH_AMPERE = 7;
constexpr unsigned int NVML_DEVICE_ARCH_HOPPER = 9;
constexpr unsigned int NVML_DEVICE_ARCH_BLACKWELL = 10;
constexpr unsigned int NVML_DEVICE_ARCH_UNKNOWN = 0xffffffff;

using nvmlInit_t = nvmlReturn_t (*)(void);
using nvmlShutdown_t = nvmlReturn_t (*)(void);
using nvmlErrorString_t = const char* (*)(nvmlReturn_t result);

using nvmlSystemGetConfComputeState_t = nvmlReturn_t (*)(nvmlConfComputeSystemState_t* state);
using nvmlSystemSetConfComputeGpusReadyState_t = nvmlReturn_t (*)(unsigned int state);
using nvmlSystemGetConfComputeGpusReadyState_t = nvmlReturn_t (*)(unsigned int* state);
using nvmlSystemGetDriverVersion_t = nvmlReturn_t (*)(char* version, unsigned int length);

using nvmlDeviceGetCount_t = nvmlReturn_t (*)(unsigned int* count);
using nvmlDeviceGetHandleByIndex_t = nvmlReturn_t (*)(unsigned int index, nvmlDevice_t* device);
using nvmlDeviceGetConfComputeGpuCertificate_t = nvmlReturn_t (*)(nvmlDevice_t device, nvmlConfComputeGpuCertificate_t* cert);
using nvmlDeviceGetConfComputeGpuAttestationReport_t = nvmlReturn_t (*)(nvmlDevice_t device, nvmlConfComputeGpuAttestationReport_t* report);
using nvmlDeviceGetVbiosVersion_t = nvmlReturn_t (*)(nvmlDevice_t device, char* version, unsigned int length);
using nvmlDeviceGetUUID_t = nvmlReturn_t (*)(nvmlDevice_t device, char* uuid, unsigned int length);
using nvmlDeviceGetArchitecture_t = nvmlReturn_t (*)(nvmlDevice_t device, nvmlDeviceArchitecture_t* arch);
using nvmlDeviceGetBoardId_t = nvmlReturn_t (*)(nvmlDevice_t device, unsigned int* board_id);

struct NvmlFunctions {
    void* library_handle = nullptr;

    nvmlInit_t init = nullptr;
    nvmlShutdown_t shutdown = nullptr;
    nvmlErrorString_t error_string = nullptr;

    nvmlSystemGetConfComputeState_t system_get_conf_compute_state = nullptr;
    nvmlSystemSetConfComputeGpusReadyState_t system_set_conf_compute_gpus_ready_state = nullptr;
    nvmlSystemGetConfComputeGpusReadyState_t system_get_conf_compute_gpus_ready_state = nullptr;
    nvmlSystemGetDriverVersion_t system_get_driver_version = nullptr;

    nvmlDeviceGetCount_t device_get_count = nullptr;
    nvmlDeviceGetHandleByIndex_t device_get_handle_by_index = nullptr;
    nvmlDeviceGetConfComputeGpuCertificate_t device_get_conf_compute_gpu_certificate = nullptr;
    nvmlDeviceGetConfComputeGpuAttestationReport_t device_get_conf_compute_gpu_attestation_report = nullptr;
    nvmlDeviceGetVbiosVersion_t device_get_vbios_version = nullptr;
    nvmlDeviceGetUUID_t device_get_uuid = nullptr;
    nvmlDeviceGetArchitecture_t device_get_architecture = nullptr;
    nvmlDeviceGetBoardId_t device_get_board_id = nullptr;

    NvmlFunctions() = default;
};

// Global instance
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static NvmlFunctions g_nvml_funcs;

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
bool g_nvml_initialized = false;

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static std::once_flag g_nvml_initialized_flag;

static const char* get_error_string(nvmlReturn_t result) {
    if (g_nvml_funcs.error_string != nullptr) {
        return g_nvml_funcs.error_string(result);
    }
    return "Unknown NVML error (error_string function not loaded)";
}

template<typename T>
static bool load_symbol(void* handle, const char* name, T& func_ptr) {
    dlerror();
    
    void* symbol = dlsym(handle, name);
    const char* error = dlerror();
    
    if (error != nullptr || symbol == nullptr) {
        LOG_ERROR("Failed to load symbol '" << name << "': " << (error ? error : "symbol not found"));
        return false;
    }
    
    func_ptr = reinterpret_cast<T>(symbol);
    return true;
}

static bool load_all_symbols(void* handle) {
    bool success = true;
    
    success = load_symbol(handle, "nvmlInit_v2", g_nvml_funcs.init) && success;
    success = load_symbol(handle, "nvmlShutdown", g_nvml_funcs.shutdown) && success;
    success = load_symbol(handle, "nvmlErrorString", g_nvml_funcs.error_string) && success;
    
    success = load_symbol(handle, "nvmlSystemGetConfComputeState", g_nvml_funcs.system_get_conf_compute_state) && success;
    success = load_symbol(handle, "nvmlSystemSetConfComputeGpusReadyState", g_nvml_funcs.system_set_conf_compute_gpus_ready_state) && success;
    success = load_symbol(handle, "nvmlSystemGetConfComputeGpusReadyState", g_nvml_funcs.system_get_conf_compute_gpus_ready_state) && success;
    success = load_symbol(handle, "nvmlSystemGetDriverVersion", g_nvml_funcs.system_get_driver_version) && success;
    
    success = load_symbol(handle, "nvmlDeviceGetCount", g_nvml_funcs.device_get_count) && success;
    success = load_symbol(handle, "nvmlDeviceGetHandleByIndex", g_nvml_funcs.device_get_handle_by_index) && success;
    success = load_symbol(handle, "nvmlDeviceGetConfComputeGpuCertificate", g_nvml_funcs.device_get_conf_compute_gpu_certificate) && success;
    success = load_symbol(handle, "nvmlDeviceGetConfComputeGpuAttestationReport", g_nvml_funcs.device_get_conf_compute_gpu_attestation_report) && success;
    success = load_symbol(handle, "nvmlDeviceGetVbiosVersion", g_nvml_funcs.device_get_vbios_version) && success;
    success = load_symbol(handle, "nvmlDeviceGetUUID", g_nvml_funcs.device_get_uuid) && success;
    success = load_symbol(handle, "nvmlDeviceGetArchitecture", g_nvml_funcs.device_get_architecture) && success;
    success = load_symbol(handle, "nvmlDeviceGetBoardId", g_nvml_funcs.device_get_board_id) && success;
    
    return success;
}


Error init_nvml()
{
    // If already initialized, return Ok
    if (g_nvml_initialized) {
        return Error::Ok;
    }
    
    Error init_result = Error::NvmlInitFailed;
    
    std::call_once(g_nvml_initialized_flag, [&init_result]() {
        LOG_DEBUG("Initializing NVML with dlopen");

        const std::string nvml_so = "libnvidia-ml.so.1";
        g_nvml_funcs.library_handle = dlopen(nvml_so.c_str(), RTLD_LAZY | RTLD_LOCAL);
        if (g_nvml_funcs.library_handle == nullptr) {
            const char* error = dlerror();
            LOG_TRACE("Failed to load NVML library: " << nvml_so << "': " << (error ? error : "unknown error"));
            init_result = Error::NvmlInitFailed;
            return;
        }
        LOG_TRACE("Successfully loaded NVML library: " << nvml_so);

        if (!load_all_symbols(g_nvml_funcs.library_handle)) {
            LOG_ERROR("Failed to load required NVML symbols");
            dlclose(g_nvml_funcs.library_handle);
            g_nvml_funcs.library_handle = nullptr;
            init_result = Error::NvmlInitFailed;
            return;
        }
        LOG_TRACE("Successfully loaded all NVML symbols");
        
        nvmlReturn_t result = g_nvml_funcs.init();
        if (result != NVML_SUCCESS) {
            LOG_ERROR("Failed to initialize NVML: " << std::string(get_error_string(result)) << " (NVML code " << result << ")");
            dlclose(g_nvml_funcs.library_handle);
            g_nvml_funcs.library_handle = nullptr;
            init_result = Error::NvmlInitFailed;
            return;
        }
        
        LOG_DEBUG("Successfully initialized NVML");
        g_nvml_initialized = true;
        init_result = Error::Ok;
    });
    
    return init_result;
}

void shutdown_nvml()
{
    if (!g_nvml_initialized || g_nvml_funcs.library_handle == nullptr) {
        return;
    }
    
    LOG_DEBUG("Shutting down NVML");
    
    nvmlReturn_t result = g_nvml_funcs.shutdown();
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to shutdown NVML: " << std::string(get_error_string(result)));
    }
    if (dlclose(g_nvml_funcs.library_handle) != 0) {
        const char* error = dlerror();
        LOG_ERROR("Failed to close NVML library: " << (error != nullptr ? error : "unknown error"));
    }
    g_nvml_funcs = NvmlFunctions();
    g_nvml_initialized = false;
    LOG_DEBUG("Successfully shut down NVML");
}

Error is_cc_enabled(bool& out_is_enabled)
{
    nvmlConfComputeSystemState_t state{};
    nvmlReturn_t result = g_nvml_funcs.system_get_conf_compute_state(&state);
    if (result != NVML_SUCCESS) {
        LOG_ERROR("CC feature error: " << std::string(get_error_string(result)));
        return Error::NvmlError;
    }
    out_is_enabled = (state.ccFeature != 0);
    return Error::Ok;
}

Error get_device_count(unsigned int& out_result) {
    nvmlReturn_t result = g_nvml_funcs.device_get_count(&out_result);
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to get NVML device count: " << std::string(get_error_string(result)));
        return Error::NvmlError;
    }
    return Error::Ok;
}

Error get_gpu_ready_state(unsigned int& out_ready_state)
{
    if (!g_nvml_initialized || g_nvml_funcs.system_get_conf_compute_gpus_ready_state == nullptr) {
        LOG_ERROR("NVML not initialized or function not available");
        return Error::NvmlError;
    }
    
    nvmlReturn_t result = g_nvml_funcs.system_get_conf_compute_gpus_ready_state(&out_ready_state);
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to get GPU ready state: " << std::string(get_error_string(result)));
        return Error::NvmlError;
    }
    return Error::Ok;
}

Error get_attestation_cert_chain(nvmlDevice_t device_handle, std::string& out_attestation_cert_chain)
{
    nvmlConfComputeGpuCertificate_t cert_data{};
    nvmlReturn_t result = g_nvml_funcs.device_get_conf_compute_gpu_certificate(device_handle, &cert_data);
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to get GPU certificate: " << std::string(get_error_string(result)));
        return Error::NvmlError;
    }

    out_attestation_cert_chain.assign(reinterpret_cast<char*>(cert_data.attestationCertChain), cert_data.attestationCertChainSize);
    return Error::Ok;
}

Error get_attestation_report(
    nvmlDevice_t device_handle,
    const std::vector<uint8_t>& nonce_input,
    std::vector<uint8_t>& out_attestation_report)
{
    nvmlConfComputeGpuAttestationReport_t report{};

    if (!nonce_input.empty()) {
        size_t nonce_byte_size = sizeof(report.nonce);
        if (nonce_input.size() != nonce_byte_size) {
            LOG_ERROR("Provided nonce size (" << nonce_input.size() <<
                      ") does not match required size (" << nonce_byte_size << ").");
            return Error::NvmlError;
        }
        std::memcpy(report.nonce, nonce_input.data(), nonce_byte_size);
    }

    nvmlReturn_t result = g_nvml_funcs.device_get_conf_compute_gpu_attestation_report(device_handle, &report);
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to fetch attestation report: " << std::string(get_error_string(result)));
        return Error::NvmlError;
    }
    
    const uint8_t* report_start = reinterpret_cast<const uint8_t*>(report.attestationReport);
    out_attestation_report.assign(report_start, report_start + report.attestationReportSize);
    if (out_attestation_report.empty()) {
        LOG_ERROR("Fetched attestation report is empty.");
        return Error::NvmlError;
    }
    return Error::Ok;
}

Error get_driver_version(std::string& out_driver_version) {
    char version[NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE] = {};
    nvmlReturn_t result = g_nvml_funcs.system_get_driver_version(version, NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE);
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to get driver version: " << std::string(get_error_string(result)));
        return Error::NvmlError;
    }
    out_driver_version = std::string(version);
    return Error::Ok;
}

Error get_device_handle_by_index(unsigned int index, nvmlDevice_t* out_handle) {
    nvmlReturn_t result = g_nvml_funcs.device_get_handle_by_index(index, out_handle);
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to get handle for GPU index " << index << ": " << std::string(get_error_string(result)));
        return Error::NvmlError;
    }
    return Error::Ok;
}

Error get_vbios_version(nvmlDevice_t device_handle, std::string& out_vbios_version) {
    char vbios[NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE] = {};
    nvmlReturn_t result = g_nvml_funcs.device_get_vbios_version(
        device_handle, vbios, NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE);
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to get VBIOS version: " << std::string(get_error_string(result)));
        return Error::NvmlError;
    }
    std::string vbios_str(vbios);
    std::transform(vbios_str.begin(), vbios_str.end(), vbios_str.begin(), ::toupper);
    out_vbios_version = vbios_str;
    return Error::Ok;
}

Error get_uuid(nvmlDevice_t device_handle, std::string& out_uuid) {
    char uuid[NVML_DEVICE_UUID_BUFFER_SIZE] = {};
    nvmlReturn_t result = g_nvml_funcs.device_get_uuid(device_handle, uuid, NVML_DEVICE_UUID_BUFFER_SIZE);
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to get UUID: " << std::string(get_error_string(result)));
        return Error::NvmlError;
    }
    out_uuid = std::string(uuid);
    return Error::Ok;
}

Error get_gpu_architecture(nvmlDevice_t device_handle, GpuArchitecture& out_architecture)
{
    nvmlDeviceArchitecture_t arch = NVML_DEVICE_ARCH_UNKNOWN;
    nvmlReturn_t result = g_nvml_funcs.device_get_architecture(device_handle, &arch);
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to get GPU architecture: " << std::string(get_error_string(result)));
        return Error::NvmlError;
    }
    switch (arch) {
        case NVML_DEVICE_ARCH_AMPERE:
            out_architecture = GpuArchitecture::Ampere;
            break;
        case NVML_DEVICE_ARCH_HOPPER:
            out_architecture = GpuArchitecture::Hopper;
            break;
        case NVML_DEVICE_ARCH_BLACKWELL:
            out_architecture = GpuArchitecture::Blackwell;
            break;
        default:
            out_architecture = GpuArchitecture::Unknown;
            break;
    }
    return Error::Ok;
}

Error get_gpu_board_id(nvmlDevice_t device_handle, unsigned int& out_board_id)
{
    nvmlReturn_t result = g_nvml_funcs.device_get_board_id(device_handle, &out_board_id);
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to get board ID: " << std::string(get_error_string(result)));
        return Error::NvmlError;
    }
    return Error::Ok;
}


Error collect_evidence_nvml(const std::vector<uint8_t>& nonce_input, std::vector<std::shared_ptr<GpuEvidence>>& out_evidence) {
    if (!g_nvml_initialized) {
        LOG_ERROR("NVML is not initialized");
        return Error::NvmlError;
    }

    unsigned int device_count = 0;
    Error err = get_device_count(device_count);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to get GPU device count");
        return err;
    }

    if (device_count == 0) {
        LOG_ERROR("No GPUs available");
        return Error::NvmlError;
    }


    for (unsigned int i = 0; i < device_count; ++i) {
        nvmlDevice_t device_handle{};
        err = get_device_handle_by_index(i, &device_handle);
        if (err != Error::Ok) {
            LOG_ERROR("Failed to get handle for GPU index " << i);
            return err;
        }

        GpuArchitecture architecture = GpuArchitecture::Unknown;
        err = get_gpu_architecture(device_handle, architecture);
        if (err != Error::Ok) {
            LOG_ERROR("Failed to get GPU architecture for GPU index " << i);
            return err;
        }

        unsigned int board_id = 0;
        err = get_gpu_board_id(device_handle, board_id);
        if (err != Error::Ok) {
            LOG_ERROR("Failed to get board ID for GPU index " << i);
            return err;
        }

        std::string uuid;
        err = get_uuid(device_handle, uuid);
        if (err != Error::Ok) {
            LOG_ERROR("Failed to get UUID for GPU index " << i);
            return err;
        }

        std::vector<uint8_t> attestation_report;
        err = get_attestation_report(device_handle, nonce_input, attestation_report);
        if (err != Error::Ok) {
            LOG_ERROR("Failed to fetch attestation report for GPU index " << i);
            return err;
        }

        std::string attestation_cert_chain;
        err = get_attestation_cert_chain(device_handle, attestation_cert_chain);
        if (err != Error::Ok) {
            LOG_ERROR("Failed to get GPU certificate for GPU index " << i);
            return err;
        }

        LOG_DEBUG("Collected evidence for GPU with uuid: " << uuid);

        auto evidence = std::make_shared<GpuEvidence>(
            architecture,
            board_id,
            uuid,
            attestation_report,
            attestation_cert_chain,
            nonce_input
        );
        out_evidence.push_back(evidence);
    }

    return Error::Ok;
}

} // namespace nvattestation

