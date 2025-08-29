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
#include "nv_attestation/init.h"
#include "nv_attestation/error.h"

using namespace nvattestation;

// this is currently duplicated in unit-tests/main.cpp
// todo(p3): if this does not change signficantly between unit-tests and integration-tests,
// move it to a common test folder (that folder would have to included in the 
// target include directories for both unit-tests and integration-tests in cmakelists file)
class Environment : public ::testing::Environment {
 public:
  ~Environment() override {
  }

  // Override this to define how to set up the environment.
  void SetUp() override {
    auto options = new SdkOptions();
    options -> logger = std::make_unique<SpdLogLogger>(LogLevel::DEBUG);
    ASSERT_EQ(init(options), Error::Ok);
  }

  // Override this to define how to tear down the environment.
  void TearDown() override {
    shutdown();
  }
};


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new Environment);
    return RUN_ALL_TESTS();
}