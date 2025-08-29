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
        std::string& nonce,
        std::string& device, 
        std::string& verifier, 
        std::string& gpu_evidence, 
        std::string& switch_evidence, 
        std::string& relying_party_policy,
        std::string& rim_url,
        std::string& ocsp_url,
        std::string& nras_url, 
        std::string& log_level) {

        auto* subcommand = app.add_subcommand("attest", "Run attestation and print results as JSON");
        subcommand->add_option("--nonce", nonce, "Nonce for the attestation (in hex format). If not provided, a nonce will be generated.")
                    ->default_val("");
        subcommand->add_option("--device", device, "Device to attest ('gpu', 'nvswitch')")
                  ->check(CLI::IsMember({"gpu", "nvswitch"}))
                  ->default_val("gpu");
        

        subcommand->add_option("--verifier", verifier, "Verifier type ('local' or 'remote')")
                  ->check(CLI::IsMember({"local", "remote"}))
                  ->default_val("local");

        subcommand->add_option("--gpu-evidence", gpu_evidence, "Path to a local file which contains GPU evidence. Used instead of calling NVML")->default_val("");
        subcommand->add_option("--switch-evidence", switch_evidence, "Path to a local file which contains Switch evidence. Used instead of calling NSCQ")->default_val("");
        subcommand->add_option("--relying-party-policy", relying_party_policy, "Path to a local file which contains a Relying Party Rego policy")->default_val("");
        // TODO: If these params are reused, move them to the common options
        subcommand->add_option("--rim-url", rim_url, "Base URL for the NVIDIA RIM service")->default_val("https://rim.attestation.nvidia.com");
        subcommand->add_option("--ocsp-url", ocsp_url, "Base URL for the OCSP responder")->default_val("https://ocsp.ndis.nvidia.com");
        subcommand->add_option("--nras-url", nras_url, "Base URL for the NVIDIA Remote Attestation Service")->default_val("https://nras.attestation.nvidia.com");
        subcommand->add_option("--log-level", log_level, "Log level ('trace', 'debug', 'info', 'warn', 'error', 'off')")
                  ->check(CLI::IsMember({"trace", "debug", "info", "warn", "error", "off"}))
                  ->default_val("warn");
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
        const std::string& nonce,
        const std::string& device, 
        const std::string& verifier, 
        const std::string& gpu_evidence, 
        const std::string& switch_evidence,
        const std::string& relying_party_policy,
        const std::string& rim_url,
        const std::string& ocsp_url,
        const std::string& nras_url,
        const std::string& log_level) {

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
        if (log_level == "trace") {
            log_level_nvat = NVAT_LOG_LEVEL_TRACE;
        } else if (log_level == "debug") {
            log_level_nvat = NVAT_LOG_LEVEL_DEBUG;
        } else if (log_level == "info") {
            log_level_nvat = NVAT_LOG_LEVEL_INFO;
        } else if (log_level == "warn") {
            log_level_nvat = NVAT_LOG_LEVEL_WARN;
        } else if (log_level == "error") {
            log_level_nvat = NVAT_LOG_LEVEL_ERROR;
        }
        err = nvat_logger_spdlog_create(&logger, "nvattest", log_level_nvat);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }
        nvat_sdk_opts_set_logger(*(opts.get()), logger);

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

        if (device == "gpu") {
            err = nvat_attestation_ctx_set_device_type(*(ctx.get()), NVAT_DEVICE_GPU);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        } else if (device == "nvswitch") {
            err = nvat_attestation_ctx_set_device_type(*(ctx.get()), NVAT_DEVICE_NVSWITCH);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }

        if (!gpu_evidence.empty()) {
            err = nvat_attestation_ctx_set_gpu_evidence_source_json_file(*(ctx.get()), gpu_evidence.c_str());
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }

        if (!switch_evidence.empty()) {
            err = nvat_attestation_ctx_set_switch_evidence_source_json_file(*(ctx.get()), switch_evidence.c_str());
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }

        // Configure service endpoints if provided
        if (!rim_url.empty()) {
            std::string rim_base = rim_url;
            nv_unique_ptr<nvat_rim_store_t> rim_store;
            nvat_rim_store_t rim_store_raw = nullptr;
            err = nvat_rim_store_create_remote(&rim_store_raw, rim_base.c_str(), nullptr);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
            rim_store.reset(&rim_store_raw);
            err = nvat_attestation_ctx_set_default_rim_store(*(ctx.get()), *(rim_store.get()));
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }

        if (!ocsp_url.empty()) {
            std::string ocsp_base = ocsp_url;
            nv_unique_ptr<nvat_ocsp_client_t> ocsp_client;
            nvat_ocsp_client_t ocsp_client_raw = nullptr;
            err = nvat_ocsp_client_create_default(&ocsp_client_raw, ocsp_base.c_str(), nullptr);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
            ocsp_client.reset(&ocsp_client_raw);
            err = nvat_attestation_ctx_set_default_ocsp_client(*(ctx.get()), *(ocsp_client.get()));
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }

        if (!nras_url.empty()) {
            std::string nras_base = nras_url;
            // Ensure remote verifiers use the user-specified NRAS base URL
            setenv("NVAT_NRAS_BASE_URL", nras_base.c_str(), 1);
        }

        err = set_relying_party_policy(*(ctx.get()), relying_party_policy);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }

        if (verifier == "local") {
            err = nvat_attestation_ctx_set_verifier_type(*(ctx.get()), NVAT_VERIFY_LOCAL);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        } else if (verifier == "remote") {
            err = nvat_attestation_ctx_set_verifier_type(*(ctx.get()), NVAT_VERIFY_REMOTE);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        } else {
            return AttestOutput(NVAT_RC_BAD_ARGUMENT);
        }

        nv_unique_ptr<nvat_claims_collection_t> claims;
        nvat_claims_collection_t raw_claims = nullptr;
        nvat_str_t detached_eat = nullptr;
        nvat_nonce_t nonce_ptr = nullptr; 
        if (!nonce.empty()) {
            err = nvat_nonce_from_hex(&nonce_ptr, nonce.c_str());
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }
        err = nvat_attest_device(*(ctx.get()), nonce_ptr, &detached_eat, &raw_claims);
        if (err != NVAT_RC_OK && err != NVAT_RC_RP_POLICY_MISMATCH && err != NVAT_RC_OVERALL_RESULT_FALSE) {
            return AttestOutput(err);
        }

        if (raw_claims == nullptr) {
            SPDLOG_ERROR("Failed to get claims");
            return AttestOutput(NVAT_RC_INTERNAL_ERROR);
        }

        if (detached_eat == nullptr) {
            SPDLOG_ERROR("Failed to get detached EAT");
            return AttestOutput(NVAT_RC_INTERNAL_ERROR);
        }

        AttestOutput final_output(err);

        nvat_str_t serialized_claims;
        claims.reset(&raw_claims);
        err = nvat_claims_collection_serialize_json(*(claims.get()), &serialized_claims);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }

        char * serialized_claims_data = nullptr;
        err = nvat_str_get_data(serialized_claims, &serialized_claims_data);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }

        char * detached_eat_data = nullptr;
        err = nvat_str_get_data(detached_eat, &detached_eat_data);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }

        final_output.claims = std::string(serialized_claims_data);
        final_output.detached_eat = std::string(detached_eat_data);
        return final_output;

    }


    int handle_attest_subcommand(
        std::string& nonce,
        std::string& device,
        std::string& verifier,
        std::string& gpu_evidence, 
        std::string& switch_evidence,
        std::string& relying_party_policy,
        std::string& rim_url,
        std::string& ocsp_url,
        std::string& nras_url,
        std::string& log_level) {

        AttestOutput attest_output = attest(nonce, device, verifier, gpu_evidence, switch_evidence, relying_party_policy, rim_url, ocsp_url, nras_url, log_level);
        nvat_sdk_shutdown();

        auto json = attest_output.to_json();
        std::cout << json.dump(4) << std::endl;
        return attest_output.result_code;
    }
}
