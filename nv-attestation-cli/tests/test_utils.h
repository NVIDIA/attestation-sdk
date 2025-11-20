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
#include <sys/wait.h>
#include "gtest/gtest.h"

class CliTest : public ::testing::Test {};

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
