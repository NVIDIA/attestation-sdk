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
#include <string>
#include <set>
#include <cstdlib>

#include "attest.h"
#include "nvat.h"
#include "nvattest_types.h"
#include "spdlog/spdlog.h"
#include "utils.h"

namespace nvattest {

    AttestOutput::AttestOutput(const int result_code)
        : result_code(result_code), claims(""), detached_eat("") {}

    AttestOutput::AttestOutput(const int result_code, const std::string& claims, const std::string& detached_eat)
        : result_code(result_code), claims(claims), detached_eat(detached_eat) {}
    
    nlohmann::json AttestOutput::to_json() const {
        nlohmann::json claims_json = nlohmann::json::object();
        nlohmann::json detached_eat_json = nlohmann::json::object();
        if (result_code == NVAT_RC_OK || result_code == NVAT_RC_RP_POLICY_MISMATCH || result_code == NVAT_RC_OVERALL_RESULT_FALSE) {
            try {
                claims_json = nlohmann::json::parse(claims);
            } catch (const nlohmann::json::parse_error& e) {
                SPDLOG_ERROR("Failed to parse claims as JSON: {}. Claims: {}", e.what(), claims);
                claims_json = nlohmann::json::object();
            } catch (...) {
                SPDLOG_ERROR("Failed to parse claims as JSON. Claims: {}", claims);
                claims_json = nlohmann::json::object();
            }

            try {
                detached_eat_json = nlohmann::json::parse(detached_eat);
            } catch (const nlohmann::json::parse_error& e) {
                SPDLOG_ERROR("Failed to parse detached EAT as JSON: {}. Detached EAT: {}", e.what(), detached_eat);
                detached_eat_json = nlohmann::json::object();
            } catch (...) {
                SPDLOG_ERROR("Failed to parse detached EAT as JSON. Detached EAT: {}", detached_eat);
                detached_eat_json = nlohmann::json::object();
            }
            
        }
    
        nlohmann::json attest_output = nlohmann::json::object();
        attest_output["result_code"] = result_code;
        attest_output["result_message"] = nvat_rc_to_string(result_code);
        attest_output["claims"] = claims_json;
        attest_output["detached_eat"] = detached_eat_json;
        return attest_output;
    }

    CLI::App* create_attest_subcommand(
        CLI::App& app,
        EvidenceCollectionOptions& evidence_collection_options,
        EvidenceVerificationOptions& evidence_verification_options,
        EvidencePolicyOptions& evidence_policy_options) {

        auto* subcommand = app.add_subcommand("attest", "Run attestation and print results as JSON");

        add_evidence_collection_options(subcommand, evidence_collection_options);
        add_evidence_verification_options(subcommand, evidence_verification_options);
        add_evidence_policy_options(subcommand, evidence_policy_options);
        
        return subcommand;
    }

    /**
     * @brief Reads and sets the relying party policy from file on the attestation context.
     * 
     * @param ctx The NVAT SDK context object.
     * @param relying_party_policy_filename Path to a local file which contains a Relying Party Rego policy
     * @return 0 if ok, 1 if otherwise
     */
    static nvat_rc_t set_relying_party_policy(
        nvat_attestation_ctx_t ctx, 
        const std::string& relying_party_policy_filename) {
        if (relying_party_policy_filename.empty()) {
            return NVAT_RC_OK;
        }

        std::ifstream file(relying_party_policy_filename);
        if (!file) {
            std::cerr << "Failed to open relying party policy file: " << relying_party_policy_filename << std::endl;
            return NVAT_RC_BAD_ARGUMENT;
        }

        std::ostringstream ss;
        ss << file.rdbuf();
        std::string rego_str = ss.str();

        nv_unique_ptr<nvat_relying_party_policy_t> rp_policy;
        nvat_relying_party_policy_t rp_raw = nullptr;
        nvat_rc_t err = nvat_relying_party_policy_create_rego_from_str(&rp_raw, rego_str.c_str());
        if (err != NVAT_RC_OK) {
            return err;
        }
        rp_policy.reset(&rp_raw);

        err = nvat_attestation_ctx_set_relying_party_policy(ctx, *(rp_policy.get()));
        if (err != NVAT_RC_OK) {
            return err;
        }

        return NVAT_RC_OK;
    }


    AttestOutput attest(
        const EvidenceCollectionOptions& evidence_collection_options,
        const EvidenceVerificationOptions& evidence_verification_options,
        const EvidencePolicyOptions& evidence_policy_options,
        const CommonOptions& common_options) {

        nvat_rc_t err;


        nv_unique_ptr<nvat_sdk_opts_t> opts;
        nvat_sdk_opts_t raw_opts = nullptr;
        err = nvat_sdk_opts_create(&raw_opts);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }
        opts.reset(&raw_opts);

        nvat_logger_t logger = nullptr;
        nvat_log_level_t log_level_nvat = NVAT_LOG_LEVEL_OFF;
        if (common_options.log_level == "trace") {
            log_level_nvat = NVAT_LOG_LEVEL_TRACE;
        } else if (common_options.log_level == "debug") {
            log_level_nvat = NVAT_LOG_LEVEL_DEBUG;
        } else if (common_options.log_level == "info") {
            log_level_nvat = NVAT_LOG_LEVEL_INFO;
        } else if (common_options.log_level == "warn") {
            log_level_nvat = NVAT_LOG_LEVEL_WARN;
        } else if (common_options.log_level == "error") {
            log_level_nvat = NVAT_LOG_LEVEL_ERROR;
        }
        err = nvat_logger_spdlog_create(&logger, "nvattest", log_level_nvat);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }
        nvat_sdk_opts_set_logger(*(opts.get()), logger);
        nvat_logger_free(&logger);

        // todo (p1): in case more subcommands are added which required SDK init, 
        // refactor this whole thing to a common function
        err = nvat_sdk_init(*(opts.get()));
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }

        nv_unique_ptr<nvat_attestation_ctx_t> ctx;
        nvat_attestation_ctx_t raw_ctx = nullptr;
        err = nvat_attestation_ctx_create(&raw_ctx);
        if (err != NVAT_RC_OK) return AttestOutput(err);
        ctx.reset(&raw_ctx);

        nv_unique_ptr<nvat_evidence_policy_t> evidence_policy;
        nvat_evidence_policy_t raw_policy = nullptr;
        err = nvat_evidence_policy_create_default(&raw_policy);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }
        evidence_policy.reset(raw_policy);
        nvat_evidence_policy_t policy_handle = evidence_policy.release();
        err = nvat_attestation_ctx_set_evidence_policy(*(ctx.get()), &policy_handle);
        if (err != NVAT_RC_OK) {
            nvat_evidence_policy_free(&policy_handle);
            return AttestOutput(err);
        }

        if (evidence_collection_options.device == "gpu") {
            err = nvat_attestation_ctx_set_device_type(*(ctx.get()), NVAT_DEVICE_GPU);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        } else if (evidence_collection_options.device == "nvswitch") {
            err = nvat_attestation_ctx_set_device_type(*(ctx.get()), NVAT_DEVICE_NVSWITCH);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }

        if (!evidence_verification_options.gpu_evidence.empty()) {
            err = nvat_attestation_ctx_set_gpu_evidence_source_json_file(*(ctx.get()), evidence_verification_options.gpu_evidence.c_str());
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }

        if (!evidence_verification_options.switch_evidence.empty()) {
            err = nvat_attestation_ctx_set_switch_evidence_source_json_file(*(ctx.get()), evidence_verification_options.switch_evidence.c_str());
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }

        if (!evidence_verification_options.service_key.empty()) {
            err = nvat_attestation_ctx_set_service_key(*(ctx.get()), evidence_verification_options.service_key.c_str());
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }

        // Configure service endpoints if provided
        if (!evidence_verification_options.rim_url.empty()) {
            std::string rim_base = evidence_verification_options.rim_url;
            nv_unique_ptr<nvat_rim_store_t> rim_store;
            nvat_rim_store_t rim_store_raw = nullptr;
            const char* service_key_cstr = evidence_verification_options.service_key.empty() ? nullptr : evidence_verification_options.service_key.c_str();
            err = nvat_rim_store_create_remote(&rim_store_raw, rim_base.c_str(), service_key_cstr, nullptr);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
            rim_store.reset(&rim_store_raw);
            err = nvat_attestation_ctx_set_default_rim_store(*(ctx.get()), *(rim_store.get()));
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }

        if (!evidence_verification_options.ocsp_url.empty()) {
            std::string ocsp_base = evidence_verification_options.ocsp_url;
            nv_unique_ptr<nvat_ocsp_client_t> ocsp_client;
            nvat_ocsp_client_t ocsp_client_raw = nullptr;
            const char* service_key_cstr = evidence_verification_options.service_key.empty() ? nullptr : evidence_verification_options.service_key.c_str();
            err = nvat_ocsp_client_create_default(&ocsp_client_raw, ocsp_base.c_str(), service_key_cstr, nullptr);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
            ocsp_client.reset(&ocsp_client_raw);
            err = nvat_attestation_ctx_set_default_ocsp_client(*(ctx.get()), *(ocsp_client.get()));
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }

        if (!evidence_verification_options.nras_url.empty()) {
            std::string nras_base = evidence_verification_options.nras_url;
            // Ensure remote verifiers use the user-specified NRAS base URL
            setenv("NVAT_NRAS_BASE_URL", nras_base.c_str(), 1);
        }

        err = set_relying_party_policy(*(ctx.get()), evidence_verification_options.relying_party_policy);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }

        if (evidence_verification_options.verifier == "local") {
            err = nvat_attestation_ctx_set_verifier_type(*(ctx.get()), NVAT_VERIFY_LOCAL);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        } else if (evidence_verification_options.verifier == "remote") {
            err = nvat_attestation_ctx_set_verifier_type(*(ctx.get()), NVAT_VERIFY_REMOTE);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        } else {
            return AttestOutput(NVAT_RC_BAD_ARGUMENT);
        }

        nv_unique_ptr<nvat_claims_collection_t> claims;
        nvat_claims_collection_t raw_claims = nullptr;
        nv_unique_ptr<nvat_str_t> detached_eat;
        nvat_str_t raw_detached_eat = nullptr;
        nvat_nonce_t nonce = nullptr; 
        if (!evidence_collection_options.nonce.empty()) {
            err = nvat_nonce_from_hex(&nonce, evidence_collection_options.nonce.c_str());
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }
        err = nvat_attest_device(*(ctx.get()), nonce, &raw_detached_eat, &raw_claims);
        if (err != NVAT_RC_OK && err != NVAT_RC_RP_POLICY_MISMATCH && err != NVAT_RC_OVERALL_RESULT_FALSE) {
            return AttestOutput(err);
        }
        detached_eat.reset(&raw_detached_eat);
        claims.reset(&raw_claims);

        AttestOutput final_output(err);

        nv_unique_ptr<nvat_str_t> serialized_claims;
        nvat_str_t raw_serialized_claims;
        err = nvat_claims_collection_serialize_json(*(claims.get()), &raw_serialized_claims);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }
        serialized_claims.reset(&raw_serialized_claims);

        char * serialized_claims_data = nullptr;
        err = nvat_str_get_data(*serialized_claims.get(), &serialized_claims_data);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }
        final_output.claims = std::string(serialized_claims_data);

        char * detached_eat_data = nullptr;
        err = nvat_str_get_data(*detached_eat.get(), &detached_eat_data);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }
        final_output.detached_eat = std::string(detached_eat_data);

        return final_output;

    }


    int handle_attest_subcommand(
        const EvidenceCollectionOptions& evidence_collection_options,
        const EvidenceVerificationOptions& evidence_verification_options,
        const EvidencePolicyOptions& evidence_policy_options,
        const CommonOptions& common_options) {

        AttestOutput attest_output = attest(evidence_collection_options, evidence_verification_options, evidence_policy_options, common_options);
        nvat_sdk_shutdown();

        auto json = attest_output.to_json();
        std::cout << json.dump(4) << std::endl;
        return attest_output.result_code;
    }
}
