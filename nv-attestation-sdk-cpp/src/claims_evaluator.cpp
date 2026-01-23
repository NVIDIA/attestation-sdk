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
            LOG_TRACE("--- Claims ---" << std::endl << json << "--- End Claims ---");
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

std::shared_ptr<IClaimsEvaluator> ClaimsEvaluatorFactory::create_rego_claims_evaluator(const std::string &policy) {
    return std::make_shared<RegoClaimsEvaluator>(policy);
}

std::shared_ptr<IClaimsEvaluator> ClaimsEvaluatorFactory::create_overall_result_evaluator() {
    std::string policy_str = R"(
        package policy
        import future.keywords.every

        default nv_match := false

        nv_match {
            count(input) > 0
            every claim in input {
                validate_claim_by_device_type(claim)
            }
        }

        validate_claim_by_device_type(claim) {
            claim["x-nvidia-device-type"] == "gpu"
            validate_gpu_claims(claim)
        }

        validate_claim_by_device_type(claim) {
            claim["x-nvidia-device-type"] == "nvswitch"
            validate_switch_claims(claim)
        }

        validate_gpu_claims(claims) {
            check_measurements_match(claims)
            check_gpu_ar_cert_chain(claims)
            check_gpu_driver_rim_cert_chain(claims)
            check_gpu_vbios_rim_cert_chain(claims)
        }

        validate_switch_claims(claims) {
            check_measurements_match(claims)
            check_switch_ar_cert_chain(claims)
            check_switch_bios_rim_cert_chain(claims)
        }

        check_measurements_match(claims) {
            claims.measres == "success"
        }

        check_gpu_ar_cert_chain(claims) {
            cert_chain := claims["x-nvidia-gpu-attestation-report-cert-chain"]
            cert_chain["x-nvidia-cert-status"] == "valid"
            cert_chain["x-nvidia-cert-ocsp-status"] == "good"
            cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
            cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
        }

        check_gpu_driver_rim_cert_chain(claims) {
            cert_chain := claims["x-nvidia-gpu-driver-rim-cert-chain"]
            cert_chain["x-nvidia-cert-status"] == "valid"
            cert_chain["x-nvidia-cert-ocsp-status"] == "good"
            cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
            cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
        }

        check_gpu_vbios_rim_cert_chain(claims) {
            cert_chain := claims["x-nvidia-gpu-vbios-rim-cert-chain"]
            cert_chain["x-nvidia-cert-status"] == "valid"
            cert_chain["x-nvidia-cert-ocsp-status"] == "good"
            cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
            cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
        }

        check_switch_ar_cert_chain(claims) {
            cert_chain := claims["x-nvidia-switch-attestation-report-cert-chain"]
            cert_chain["x-nvidia-cert-status"] == "valid"
            cert_chain["x-nvidia-cert-ocsp-status"] == "good"
            cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
            cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
        }

        check_switch_bios_rim_cert_chain(claims) {
            cert_chain := claims["x-nvidia-switch-bios-rim-cert-chain"]
            cert_chain["x-nvidia-cert-status"] == "valid"
            cert_chain["x-nvidia-cert-ocsp-status"] == "good"
            cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
            cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
        }

    )";
    return std::make_shared<RegoClaimsEvaluator>(policy_str);
}


}