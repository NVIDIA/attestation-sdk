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

#ifdef ENABLE_NVML
#include <gtest/gtest.h>
#include <nvml.h>
#include <vector>
#include <memory>
#include <string>
#include "nv_attestation/gpu/nvml_client.h"
#include "nv_attestation/gpu/evidence.h"

using namespace nvattestation;

TEST(NvmlIntegration, InitAndShutdown) {
    ASSERT_EQ(init_nvml(), Error::Ok);
    shutdown_nvml();
}

TEST(NvmlIntegration, GetDriverVersion) {
    ASSERT_EQ(init_nvml(), Error::Ok);
    auto version = get_driver_version();
    ASSERT_NE(version, nullptr);
    ASSERT_FALSE(version->empty());
    shutdown_nvml();
}

TEST(NvmlIntegration, DeviceMethods) {
    ASSERT_EQ(init_nvml(), Error::Ok);
    unsigned int device_count = 0;
    nvmlReturn_t result = nvmlDeviceGetCount(&device_count);
    ASSERT_EQ(result, NVML_SUCCESS);
    ASSERT_GT(device_count, 0u);
    for (unsigned int i = 0; i < device_count; ++i) {
        nvmlDevice_t device;
        result = nvmlDeviceGetHandleByIndex(i, &device);
        ASSERT_EQ(result, NVML_SUCCESS);
        auto uuid = get_uuid(device);
        ASSERT_NE(uuid, nullptr);
        ASSERT_FALSE(uuid->empty());
        auto vbios = get_vbios_version(device);
        ASSERT_NE(vbios, nullptr);
        ASSERT_FALSE(vbios->empty());
        auto arch = get_gpu_architecture(device);
        ASSERT_NE(arch, nullptr);
        auto arch_str = to_string(*arch);
        ASSERT_FALSE(arch_str.empty());
        auto cert_chain = get_attestation_cert_chain(device);
        ASSERT_NE(cert_chain, nullptr);
        ASSERT_FALSE(cert_chain->empty());
        std::vector<uint8_t> nonce(32, 0);
        auto report = get_attestation_report(device, nonce);
        ASSERT_NE(report, nullptr);
        ASSERT_FALSE(report->empty());
    }
    shutdown_nvml();
}

TEST(NvmlIntegration, ReadyStateAndCC) {
    ASSERT_EQ(init_nvml(), Error::Ok);
    auto ready_state = get_gpu_ready_state();
    ASSERT_NE(ready_state, nullptr);
    auto cc_enabled = is_cc_enabled();
    ASSERT_NE(cc_enabled, nullptr);
    auto cc_dev_mode = is_cc_dev_mode();
    ASSERT_NE(cc_dev_mode, nullptr);
    shutdown_nvml();
}

TEST(NvmlIntegration, NvmlEvidenceCollectorGetEvidence) {
    ASSERT_EQ(init_nvml(), Error::Ok);
    NvmlEvidenceCollector collector;
    std::vector<uint8_t> nonce(32, 0);
    std::vector<GpuEvidence> evidence;
    Error error = collector.get_evidence(nonce, evidence);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(evidence.empty());
    for (const auto& ev : evidence) {
        ASSERT_FALSE(to_string(ev.get_gpu_architecture()).empty());
        ASSERT_GT(ev.get_board_id(), 0u);
        ASSERT_FALSE(ev.get_uuid().empty());
        ASSERT_FALSE(ev.get_vbios_version().empty());
        ASSERT_FALSE(ev.get_driver_version().empty());
        ASSERT_FALSE(ev.get_attestation_report().empty());
    }
    shutdown_nvml();
}
#endif
