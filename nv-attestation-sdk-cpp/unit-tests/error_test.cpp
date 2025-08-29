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
#include <set>

//third party
#include "gtest/gtest.h"
#include "gmock/gmock.h"

//this sdk
#include "nv_attestation/error.h"

using namespace nvattestation;

class ErrorTest : public ::testing::Test {
    
};

TEST_F(ErrorTest, ErrorEnumValuesAreUnique) {
    std::set<int> values;
    for (Error e : ErrorValues) {
        int val = static_cast<int>(e);
        EXPECT_TRUE(values.insert(val).second) << "Duplicate enum value: " << val;
    }
}

TEST_F(ErrorTest, EnumValuesHaveAToString) {
    for (Error e : ErrorValues) {
        std::string message = nvattestation::to_string(e);
        EXPECT_NE(message, "Undefined");
    }
}