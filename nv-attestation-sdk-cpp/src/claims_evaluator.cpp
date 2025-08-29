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
#include <ostream>

//third party
#include <nlohmann/json.hpp>

//this SDK
#include "nv_attestation/log.h"
#include "nv_attestation/claims_evaluator.h"
#include "internal/rego_engine/rego_engine.h"

namespace nvattestation {


class RegoClaimsEvaluator : public IClaimsEvaluator {
    private:
        std::string m_policy;
        RegorusRegoEngine m_engine;

        static constexpr const char* ENTRYPOINT = "data.policy.nv_match";

    public:
        RegoClaimsEvaluator(const std::string& policy) : m_policy(policy) {}

        Error evaluate_claims(const ClaimsCollection& claims, bool& out_match) override {
            std::string json;
            Error error = claims.serialize_json(json);
            if (error != Error::Ok) {
                LOG_ERROR("Failed to serialize claims");
                return error;
            }
            LOG_TRACE("--- Rego Policy ---" << std::endl << m_policy << "--- End Rego Policy ---");
            auto evaluation_result = m_engine.evaluate_policy(m_policy, json, ENTRYPOINT);
            if (evaluation_result == nullptr) {
                return Error::PolicyEvaluationError;
            }

            try {
                LOG_TRACE("--- Policy evaluation result ---" << std::endl << *evaluation_result << "--- End Policy Evaluation Result ---");
                auto json = nlohmann::json::parse(*evaluation_result);
                // Safely access nested members using .at() to throw if missing/wrong type
                out_match = json.at("result").at(0).at("expressions").at(0).at("value");
                return Error::Ok;
            } catch (const nlohmann::json::exception& e) {
                LOG_ERROR(std::string("Failed to evaluate policy: ") + e.what());
                // Even if JSON parsing fails, default to false instead of error
                out_match = false;
                return Error::Ok;
            }
        }
};


std::shared_ptr<IClaimsEvaluator> ClaimsEvaluatorFactory::create_default_claims_evaluator() {
    std::string default_policy = R"(
    package policy
    import future.keywords.every
    default nv_match := false
    
    # Check if all certificate chain claims have valid status for GPU devices
    gpu_certs_valid(result) {
        result["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-status"] == "valid"
        result["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-status"] == "valid"
        result["x-nvidia-gpu-vbios-rim-cert-chain"]["x-nvidia-cert-status"] == "valid"
    }
    
    # Check if all certificate chain claims have valid status for Switch devices
    switch_certs_valid(result) {
        result["x-nvidia-switch-attestation-report-cert-chain"]["x-nvidia-cert-status"] == "valid"
        result["x-nvidia-switch-bios-rim-cert-chain"]["x-nvidia-cert-status"] == "valid"
    }

    nv_match_device(result) {
        result["x-nvidia-device-type"] == "gpu"
        gpu_certs_valid(result)
    }

    nv_match_device(result) {
        result["x-nvidia-device-type"] == "nvswitch"
        switch_certs_valid(result)
    }
    
    nv_match {
        every result in input {
            result["measres"] == "success"
            
            nv_match_device(result)
        }
    }
    )";
    return std::make_shared<RegoClaimsEvaluator>(default_policy);
}

std::shared_ptr<IClaimsEvaluator> ClaimsEvaluatorFactory::create_rego_claims_evaluator(const std::string &policy) {
    return std::make_shared<RegoClaimsEvaluator>(policy);
}


}