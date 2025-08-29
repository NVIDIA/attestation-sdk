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
#include <algorithm>

#ifdef ENABLE_NVML
#include <nvml.h>
#endif // ENABLE_NVML

#include "nv_attestation/log.h"
#include "nv_attestation/error.h"
#include "nv_attestation/gpu/nvml_client.h"
#include "nv_attestation/gpu/evidence.h"
namespace nvattestation {

Error init_nvml()
{
#ifdef ENABLE_NVML
    LOG_DEBUG("Initializing NVML");
    nvmlReturn_t result = nvmlInit();
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to initialize NVML: " << std::string(nvmlErrorString(result)) << " (NVML code " << result << ")");
        return Error::NvmlInitFailed;
    }
    LOG_DEBUG("Successfully initialized NVML");
    return Error::Ok;
#else
    LOG_ERROR("ENABLE_NVML feature was not enabled during compilation");
    return Error::FeatureNotEnabled;
#endif // ENABLE_NVML
}

void shutdown_nvml()
{
#ifdef ENABLE_NVML
    LOG_DEBUG("Shutting down NVML");
    nvmlReturn_t result = nvmlShutdown();
    if (result != NVML_SUCCESS) {
        LOG_ERROR("Failed to shutdown NVML: " + std::string(nvmlErrorString(result)));
    }
#endif // ENABLE_NVML
}

#ifdef ENABLE_NVML

bool set_gpu_ready_state(bool ready)
{
    unsigned int state = ready ? NVML_CC_ACCEPTING_CLIENT_REQUESTS_TRUE : NVML_CC_ACCEPTING_CLIENT_REQUESTS_FALSE;
    nvmlReturn_t result = nvmlSystemSetConfComputeGpusReadyState(state);
    if (result != NVML_SUCCESS) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to set GPU ready state: " + std::string(nvmlErrorString(result)));
        return false;
    }
    return true;
}

std::unique_ptr<bool> is_cc_enabled()
{
    nvmlConfComputeSystemState_t state{};
    nvmlReturn_t result = nvmlSystemGetConfComputeState(&state);
    if (result != NVML_SUCCESS) {
        LOG_PUSH_ERROR(Error::InternalError, "CC feature error: " + std::string(nvmlErrorString(result)));
        return nullptr;
    }
    return std::make_unique<bool>(state.ccFeature != 0);
}

std::unique_ptr<bool> is_cc_dev_mode()
{
    nvmlConfComputeSystemState_t state{};
    nvmlReturn_t result = nvmlSystemGetConfComputeState(&state);
    if (result != NVML_SUCCESS) {
        LOG_PUSH_ERROR(Error::InternalError, "CC DEV mode error: " + std::string(nvmlErrorString(result)));
        return nullptr;
    }
    return std::make_unique<bool>(state.devToolsMode != 0);
}

std::unique_ptr<int> get_gpu_ready_state()
{
    unsigned int state = 0;
    nvmlReturn_t result = nvmlSystemGetConfComputeGpusReadyState(&state);
    if (result != NVML_SUCCESS) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to get GPU ready state: " + std::string(nvmlErrorString(result)));
        return nullptr;
    }
    return std::make_unique<int>(static_cast<int>(state));
}


std::unique_ptr<std::string> get_attestation_cert_chain(nvmlDevice_t device_handle)
{
    nvmlConfComputeGpuCertificate_t cert_data{};
    nvmlReturn_t result = nvmlDeviceGetConfComputeGpuCertificate(device_handle, &cert_data);
    if (result != NVML_SUCCESS) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to get GPU certificate: " + std::string(nvmlErrorString(result)));
        return nullptr;
    }

    std::string pem_chain(reinterpret_cast<char *>(cert_data.attestationCertChain), cert_data.attestationCertChainSize);
    return std::make_unique<std::string>(pem_chain);
}

std::unique_ptr<std::vector<uint8_t>> get_attestation_report(nvmlDevice_t device_handle, const std::vector<uint8_t>& nonce_input)
{
    nvmlConfComputeGpuAttestationReport_t report{};

    if (!nonce_input.empty()) {
        if (nonce_input.size() != sizeof(report.nonce)) {
            LOG_PUSH_ERROR(Error::InternalError, "Provided nonce size (" + std::to_string(nonce_input.size()) +
                                                  ") does not match required size (" + std::to_string(sizeof(report.nonce)) + ").");
            return nullptr;
        }
        std::memcpy(report.nonce, nonce_input.data(), sizeof(report.nonce));
    }

    nvmlReturn_t result = nvmlDeviceGetConfComputeGpuAttestationReport(device_handle, &report);
    if (result != NVML_SUCCESS) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to fetch attestation report: " + std::string(nvmlErrorString(result)));
        return nullptr;
    }
    std::vector<uint8_t> attestation_report_vec;
    attestation_report_vec.assign(report.attestationReport, report.attestationReport + report.attestationReportSize);
    if (attestation_report_vec.empty()) {
        LOG_PUSH_ERROR(Error::InternalError, "Fetched attestation report is empty.");
        return nullptr;
    }
    return std::make_unique<std::vector<uint8_t>>(attestation_report_vec);
}

std::unique_ptr<std::string> get_driver_version() {
    char version[NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE] = {};
    nvmlReturn_t result = nvmlSystemGetDriverVersion(version, NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE);
    if (result != NVML_SUCCESS) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to get driver version: " + std::string(nvmlErrorString(result)));
        return nullptr;
    }
    return std::make_unique<std::string>(version);
}

std::unique_ptr<std::string> get_vbios_version(nvmlDevice_t device_handle) {
    char vbios[NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE] = {};
    nvmlReturn_t result = nvmlDeviceGetVbiosVersion(device_handle, vbios, NVML_DEVICE_VBIOS_VERSION_BUFFER_SIZE);
    if (result != NVML_SUCCESS) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to get VBIOS version: " + std::string(nvmlErrorString(result)));
        return nullptr;
    }
    std::string vbios_str(vbios);
    std::transform(vbios_str.begin(), vbios_str.end(), vbios_str.begin(), ::toupper);
    return std::make_unique<std::string>(vbios_str);
}

std::unique_ptr<std::string> get_uuid(nvmlDevice_t device_handle) {
    char uuid[NVML_DEVICE_UUID_BUFFER_SIZE] = {};
    nvmlReturn_t result = nvmlDeviceGetUUID(device_handle, uuid, NVML_DEVICE_UUID_BUFFER_SIZE);
    if (result != NVML_SUCCESS) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to get UUID: " + std::string(nvmlErrorString(result)));
        return nullptr;
    }
    return std::make_unique<std::string>(uuid);
}

std::unique_ptr<GpuArchitecture> get_gpu_architecture(nvmlDevice_t device_handle) {
    nvmlDeviceArchitecture_t arch = NVML_DEVICE_ARCH_UNKNOWN;
    nvmlReturn_t result = nvmlDeviceGetArchitecture(device_handle, &arch);
    if (result != NVML_SUCCESS) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to get GPU architecture: " + std::string(nvmlErrorString(result)));
        return nullptr;
    }
    switch (arch) {
        case NVML_DEVICE_ARCH_AMPERE: return std::make_unique<GpuArchitecture>(GpuArchitecture::Ampere);
        case NVML_DEVICE_ARCH_HOPPER: return std::make_unique<GpuArchitecture>(GpuArchitecture::Hopper);
        case NVML_DEVICE_ARCH_BLACKWELL: return std::make_unique<GpuArchitecture>(GpuArchitecture::Blackwell);
        default: return std::make_unique<GpuArchitecture>(GpuArchitecture::Unknown);
    }
}
#endif // ENABLE_NVML

} // namespace nvattestation

