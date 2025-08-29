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

class Environment : public ::testing::Environment {
    public:
        std::string test_mode; // "unit" or "integration"
        bool test_device_gpu;
        bool test_device_switch;

        ~Environment() override = default;
        
        void SetUp() override {
            test_mode = get_env_or_default("TEST_MODE", "unit");
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
        }

        void TearDown() override {
            // no teardown required
        }
};

extern Environment* g_cli_env;
