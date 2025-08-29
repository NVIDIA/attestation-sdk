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

//stdlibs
#include <fstream>
#include <thread>

//third party
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "nlohmann/json.hpp"

//this sdk
#include "../src/internal/rego_engine/rego_engine.h"

using namespace nvattestation;
using ::testing::Return;
using ::testing::_;

class RegorusRegoEngineTest : public ::testing::Test {
    protected:
        static constexpr const char* VALID_POLICY = R"(
            package test
            default allow := false
            allow {
                input.user == "admin"
            }
            )";

        static constexpr const char* INVALID_POLICY = R"(
            package test
            default allow := false
            allow {
                this is not valid Rego
            }
            )";
            
        static constexpr const char* VALID_INPUT = R"(
        {
            "user": "admin"
        }
        )";

        static constexpr const char* VALID_ENTRY_POINT = "data.test.allow";
    };

    TEST_F(RegorusRegoEngineTest, SuccessfullyEvaluatePolicy) {
        RegorusRegoEngine engine;
        auto result = engine.evaluate_policy(
            VALID_POLICY, VALID_INPUT, VALID_ENTRY_POINT);
        
        // Regorus returns results as JSON array.    
        auto j = nlohmann::json::parse(*result);
        auto evaluation_result = j["result"][0]["expressions"][0]["value"];

        EXPECT_EQ(evaluation_result, true);
    }