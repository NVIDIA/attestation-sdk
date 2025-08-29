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

#include <memory>
#include "error.h"

#include "claims.h"

namespace nvattestation {

/**
 * @brief Abstract class for evaluating claims.
 * 
 * This class contains functions to evaluate [Claims](@ref Claims)
 */
class IClaimsEvaluator {
    public:
        virtual ~IClaimsEvaluator() = default;
        
        /**
         * @brief Evaluates GPU_DEVICE_IDENTITY claims.
         * 
         * @param claims The claims to evaluate.
         * @return A boolean value indicating whether the claims are valid.  True if claims are valid, false 
         * if invalid.  Returns nullptr if there was an error during evaluation
         */
        virtual Error evaluate_claims(const ClaimsCollection& claims, bool& out_match) = 0;
};


/**
 * @brief Factory class for creating [IClaimsEvaluator](@ref IClaimsEvaluator) instances.
 */
class ClaimsEvaluatorFactory {
    public:

        /**
         * @brief Creates a claims evaluator that uses a Rego policy.
         * 
         * This evaluator uses the Open Policy Agent (OPA) Rego engine to evaluate claims. When 
         * `evaluate_gpu_claims` is called, the evaluator will use this policy to determine
         * whether the claims are valid. The result depends on the logic defined by the user in the policy.
         * 
         * @param policy The provided `policy` must meet the following requirements:
         * 
         * | Requirement         | Description                                                                                          |
         * |---------------------|------------------------------------------------------------------------------------------------------|
         * | Package Declaration | The policy must declare the `package policy` namespace.                                              |
         * | Match Rule          | Must contain a rule named `nv_match` at path `policy.nv_match`.                                      |
         * | Output Format       | The policy must produce a boolean `nv_match` attribute at the JSON root in the evaluation result.    |
         * 
         * **Rule Details:**
         * - The `nv_match` rule determines claim validity and should return `true` or `false` based on the input.
         * - Rule names starting with nv_ and nvidia_ are reserved for future use. Do not create rules using these naming conventions 
         *   unless a usage is documented in the table above.
         * 
         * **Example valid policy:**
         * ```
         * package policy
         * default nv_match := false
         * nv_match := true {
         *    input.role == "admin"
         * }
         * ```
         * 
         * **Example output:**
         * ```
         * { "nv_match" : false }
         * ```
         * 
         * @return A unique pointer to a [IClaimsEvaluator](@ref IClaimsEvaluator) instance that evaluates claims using the given Rego policy.
         */
        static std::shared_ptr<IClaimsEvaluator> create_rego_claims_evaluator(const std::string &policy);
};

}