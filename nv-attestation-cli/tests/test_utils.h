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

#include <string>
#include <cstdio>
#include <array>
#include <map>
#include <algorithm>
#include <sys/wait.h>
#include "gtest/gtest.h"
#include "environment.h"
#include <nlohmann/json.hpp>

class CliTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (g_cli_env->test_label != "requires-working-driver") {
            GTEST_SKIP() << "Skipping: test_label is not 'requires_working_driver'";
        }
    }
};

inline std::string exec_and_capture_output(const std::string& command, int& exit_code) {
    std::array<char, 4096> buffer{};
    std::string result;
    FILE* pipe = popen((command + " 2>&1").c_str(), "r");
    if (!pipe) {
        exit_code = -1;
        return result;
    }
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        result.append(buffer.data());
    }
    int status = pclose(pipe);
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else {
        exit_code = -1;
    }
    return result;
}

inline bool extract_json_object(const std::string& input, std::string& json_out) {
    // Find the last balanced JSON object by scanning from the end and matching braces
    if (input.empty()) return false;
    std::size_t end_pos = std::string::npos;
    int depth = 0;
    for (std::size_t i = input.size(); i-- > 0;) {
        const char c = input[i];
        if (c == '}') {
            if (end_pos == std::string::npos) {
                end_pos = i;
            }
            depth++;
        } else if (c == '{' && depth > 0) {
            depth--;
            if (depth == 0 && end_pos != std::string::npos) {
                json_out = input.substr(i, end_pos - i + 1);
                return true;
            }
        }
    }
    return false;
}

inline std::map<std::string, nlohmann::json> index_claims_by_ueid(const nlohmann::json& claims_array) {
    std::map<std::string, nlohmann::json> result;
    if (!claims_array.is_array()) {
        return result;
    }
    for (const auto& claim : claims_array) {
        if (claim.contains("ueid") && claim["ueid"].is_string()) {
            result[claim["ueid"].get<std::string>()] = claim;
        }
    }
    return result;
}

inline void sort_json_array(nlohmann::json& j, const std::string& key) {
    if (j.contains(key) && j[key].is_array()) {
        std::sort(j[key].begin(), j[key].end());
    }
}
