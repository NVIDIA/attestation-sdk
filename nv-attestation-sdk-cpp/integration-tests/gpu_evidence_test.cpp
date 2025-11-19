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

#include <gtest/gtest.h>
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
    std::string driver_version{};
    ASSERT_EQ(get_driver_version(driver_version), Error::Ok);
    ASSERT_FALSE(driver_version.empty());
    shutdown_nvml();
}

TEST(NvmlIntegration, NvmlEvidenceCollectorGetEvidence) {
    ASSERT_EQ(init_nvml(), Error::Ok);
    NvmlEvidenceCollector collector;
    std::vector<uint8_t> nonce(32, 0);
    std::vector<std::shared_ptr<GpuEvidence>> evidence;
    Error error = collector.get_evidence(nonce, evidence);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(evidence.empty());
    for (const auto& ev : evidence) {
        ASSERT_FALSE(to_string(ev->get_gpu_architecture()).empty());
        ASSERT_GT(ev->get_board_id(), 0u);
        ASSERT_FALSE(ev->get_uuid().empty());
        ASSERT_FALSE(ev->get_vbios_version().empty());
        ASSERT_FALSE(ev->get_driver_version().empty());
        ASSERT_FALSE(ev->get_attestation_report().empty());
    }
    shutdown_nvml();
}
