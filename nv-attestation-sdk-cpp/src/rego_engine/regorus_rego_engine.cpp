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

#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>

#include "regorus.ffi.hpp"

#include "nv_attestation/log.h"

#include "internal/rego_engine/regorus.hpp"
#include "internal/rego_engine/rego_engine.h"

namespace nvattestation {

std::unique_ptr<std::string> RegorusRegoEngine::evaluate_policy(
    const std::string &policy, 
    const std::string &input,
    const std::string &entrypoint) {

        regorus::Engine engine;
        
        regorus::Result set_rego_v0_result = engine.set_rego_v0(true);
        if (!set_rego_v0_result) {
            LOG_PUSH_ERROR(Error::PolicyEvaluationError, std::string("Failed to set the Rego version: ") + set_rego_v0_result.error());
            return nullptr;
        }

        regorus::Result add_policy_result = engine.add_policy("policy.rego", policy.c_str());
        if (!add_policy_result) {
            LOG_PUSH_ERROR(Error::PolicyEvaluationError, std::string("Failed to add the policy: ") + add_policy_result.error());
            return nullptr;
        }

        regorus::Result set_input_json_result = engine.set_input_json(input.c_str());
        if (!set_input_json_result) {
            LOG_PUSH_ERROR(Error::PolicyEvaluationError, std::string("Failed to set the input json: ") + set_input_json_result.error());
            return nullptr;
        }
        
        regorus::Result evaluate_query_result = engine.eval_query(entrypoint.c_str());
        if (!evaluate_query_result) {
            LOG_PUSH_ERROR(Error::PolicyEvaluationError, std::string("Failed to evaluate the policy: ") + evaluate_query_result.error());
            return nullptr;
        } 

        return std::make_unique<std::string>(evaluate_query_result.output());
    }

}