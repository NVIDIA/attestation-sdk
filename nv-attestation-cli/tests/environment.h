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

#pragma once

#include <algorithm>
#include <cctype>
#include <gtest/gtest.h>
#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>

inline std::string get_env_or_default(const char* name, const char* default_value) {
    const char* env_val = std::getenv(name);
    if (env_val == nullptr || *env_val == '\0') {
        return std::string(default_value);
    }
    return std::string(env_val);
}

inline int get_git_repo_root(std::string& out_git_repo_root) {
    std::string git_cmd = "git rev-parse --show-toplevel 2>/dev/null";
    FILE* pipe = popen(git_cmd.c_str(), "r");
    if (pipe) {
        char buffer[1024];
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            std::string repo_root = std::string(buffer);
            if (!repo_root.empty() && repo_root.back() == '\n') {
                repo_root.pop_back();
            }
            out_git_repo_root = repo_root;
            return 0;
        }
    }
    return -1;
}

class Environment : public ::testing::Environment {
    public:
        std::string test_mode=""; // "unit" or "integration"
        bool test_device_gpu=false;
        bool test_device_switch=false;
        std::string service_key = "";
        std::string rim_url = "";
        std::string ocsp_url = "";
        std::string nras_url = "";
        std::string nvattest_bin = "";
        std::string test_label = "";
        std::string git_repo_root = "";
        std::string expected_gpu_arch = "";
        std::string expected_mode = "";

        ~Environment() override = default;
        
        void SetUp() override {
            nvattest_bin = get_env_or_default("NVATTEST_BIN", "../nvattest");
            test_mode = get_env_or_default("TEST_MODE", "unit");
            test_label = get_env_or_default("NVAT_CLI_TEST_LABEL", "");
            if (test_label.empty()) {
                std::cerr << "NVAT_CLI_TEST_LABEL environment variable is not set or empty" << std::endl;
                exit(1);
            }
            std::string test_devices_env = get_env_or_default("TEST_DEVICES", "");
            std::stringstream ss(test_devices_env);
            std::string device;
            std::cout << "TEST_MODE: " << test_mode << std::endl;
            if (test_mode != "integration" && test_mode != "unit") {
                std::cerr << "Invalid test mode: " << test_mode << std::endl;
                exit(1);
            }

            while (std::getline(ss, device, ',')) {
                std::cout << "TEST_DEVICE: " << device << std::endl;
                if (test_mode == "integration" && (device != "gpu" && device != "nvswitch")) {
                    std::cerr << "Invalid test device: " << device << std::endl;
                    exit(1);
                }
                if (device == "gpu") {
                    test_device_gpu = true;
                }
                if (device == "nvswitch") {
                    test_device_switch = true;
                }
            }
            expected_gpu_arch = get_env_or_default("TEST_EXPECTED_GPU_ARCH", "");
            expected_mode = get_env_or_default("TEST_EXPECTED_MODE", "");
            const auto to_ascii_lower = [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            };
            std::transform(expected_gpu_arch.begin(), expected_gpu_arch.end(),
                           expected_gpu_arch.begin(), to_ascii_lower);
            std::transform(expected_mode.begin(), expected_mode.end(),
                           expected_mode.begin(), to_ascii_lower);

            const bool require_gpu_arch = test_mode == "integration" && test_device_gpu &&
                                          test_label == "requires-working-driver";
            const bool require_mode = require_gpu_arch || expects_gpu_v2_attestation();

            if (require_gpu_arch) {
                if (expected_gpu_arch != "hopper" && expected_gpu_arch != "blackwell" &&
                    expected_gpu_arch != "rubin") {
                    std::cerr << "TEST_EXPECTED_GPU_ARCH must be hopper, blackwell, or rubin (got '"
                              << expected_gpu_arch << "')" << std::endl;
                    exit(1);
                }
            }
            if (require_mode) {
                if (expected_mode != "spt" && expected_mode != "mpt" &&
                    expected_mode != "tdisp") {
                    std::cerr << "TEST_EXPECTED_MODE must be spt, mpt, or tdisp (got '"
                              << expected_mode << "')" << std::endl;
                    exit(1);
                }
            }

            service_key = get_env_or_default("NVAT_C_SDK_TEST_SERVICE_KEY", "");
            ASSERT_FALSE(service_key.empty()) << "Service key is empty, please set NVAT_C_SDK_TEST_SERVICE_KEY environment variable";

            rim_url = get_env_or_default("NVAT_RIM_SERVICE_BASE_URL", "https://rim-internal.attestation.nvidia.com/internal");
            ocsp_url = get_env_or_default("NVAT_OCSP_BASE_URL", "https://ocsp.ndis-stg.nvidia.com");
            nras_url = get_env_or_default("NVAT_NRAS_BASE_URL", "https://nras.attestation-stg.nvidia.com");

            if (get_git_repo_root(git_repo_root) != 0) {
                std::cerr << "Failed to get git repository root" << std::endl;
                exit(1);
            }
        }

        bool expects_gpu_v2_attestation() const {
            return test_mode == "integration" &&
                   (test_label == "rubin-nvml" ||
                    (test_label == "requires-working-driver" && test_device_gpu &&
                     expected_gpu_arch == "rubin"));
        }
        void TearDown() override {
            // no teardown required
        }
};

extern Environment* g_cli_env;
