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
#include <vector>
#include <memory>

namespace nvattestation {

/**
 * Models a Rego evaluation engine by exposing functions to operate on Rego policy documents
 */
class RegoEngine {
    public: 
        virtual ~RegoEngine() = default;

        /**
         * @brief Evaluates a given Rego policy with the provided input and entrypoint.
         *
         * This function takes a Rego policy, an input JSON string, and an entrypoint.
         * It evaluates the policy against the input using the specified entrypoint and 
         * returns the result as a JSON-formatted string wrapped in an `EvaluationResult` object.
         *
         * @param policy A string containing the Rego policy to be evaluated. 
         * @param input A string containing the input data in JSON format. 
         *              This input is passed to the policy during evaluation.
         * @param entrypoint A string specifying the entrypoint for evaluation.  This
         *                   determines which part of the policy is evaluated.
         *
         * @return A JSON-formatted string containing the evaluation result, if successful. nullptr if
         *         the policy failed to evaluate then the 
         */
        virtual std::unique_ptr<std::string> evaluate_policy(const std::string &policy, const std::string &input, const std::string& entrypoint) = 0;
};


/**
 * Facade of the [regorus](https://github.com/microsoft/regorus/) Rego interpreter library
 */
class RegorusRegoEngine : public RegoEngine{
    public:
        std::unique_ptr<std::string> evaluate_policy(const std::string &policy, const std::string &input, const std::string& entrypoint);
};

}
