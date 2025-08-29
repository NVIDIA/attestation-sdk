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
        : claims(""), result_code(result_code) {}

    AttestOutput::AttestOutput(const std::string& claims, const int result_code)
        : claims(claims), result_code(result_code) {}
    
    nlohmann::json AttestOutput::to_json() const {
        nlohmann::json claims_json;
        try {
            claims_json = nlohmann::json::parse(claims); // Parse claims as JSON
        } catch (...) {
            claims_json = nullptr; // or handle error as desired
        }
        return nlohmann::json{
            {"claims", claims_json},
            {"result_code", result_code},
            {"result_message", nvat_rc_to_string(result_code)}
        };
    }

    CLI::App* create_attest_subcommand(
        CLI::App& app, 
        std::vector<std::string>& devices, 
        std::string& verifier, 
        std::string& gpu_evidence, 
        std::string& switch_evidence, 
        std::string& relying_party_policy,
        std::string& rim_url,
        std::string& ocsp_url,
        std::string& nras_url) {

        auto* subcommand = app.add_subcommand("attest", "Run attestation and print results as JSON");
        subcommand->add_option("--device", devices, "Device type ('gpu' or 'switch')")
                  ->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)
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
        const std::vector<std::string>& devices, 
        const std::string& verifier, 
        const std::string& gpu_evidence, 
        const std::string& switch_evidence,
        const std::string& relying_party_policy,
        const std::string& rim_url,
        const std::string& ocsp_url,
        const std::string& nras_url) {

        nvat_rc_t err;

        // Determine which device drivers we need before SDK init
        // if gpu evidence or switch evidence file is provided,
        // we do not need load those drivers
        nvat_devices_t opts_device_bitmap = 0;
        for (auto& device : devices) {
            if (device == "gpu" && gpu_evidence.empty()) {
                opts_device_bitmap |= NVAT_DEVICE_GPU;
            } else if (device == "nvswitch" && switch_evidence.empty()) {
                opts_device_bitmap |= NVAT_DEVICE_NVSWITCH;
            }
        }

        nv_unique_ptr<nvat_sdk_opts_t> opts;
        nvat_sdk_opts_t raw_opts = nullptr;
        err = nvat_sdk_opts_create(&raw_opts);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }
        opts.reset(&raw_opts);

        nvat_sdk_opts_set_enabled_device_drivers(*(opts.get()), opts_device_bitmap);

        err = nvat_sdk_init(opts.get());
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }

        nv_unique_ptr<nvat_attestation_ctx_t> ctx;
        nvat_attestation_ctx_t raw_ctx = nullptr;
        nvat_devices_t ctx_device_bitmap = 0;
        for (auto& device : devices) {
            if (device == "gpu") {
                ctx_device_bitmap |= NVAT_DEVICE_GPU;
            } else if (device == "nvswitch") {
                ctx_device_bitmap |= NVAT_DEVICE_NVSWITCH;
            }
        }
        err = nvat_attestation_ctx_create(&raw_ctx, ctx_device_bitmap);
        if (err != NVAT_RC_OK) return err;
        ctx.reset(&raw_ctx);

        if (!gpu_evidence.empty()) {
            err = nvat_attestation_ctx_set_gpu_evidence_source_json_file(*ctx, gpu_evidence.c_str());
            if (err != NVAT_RC_OK) {
                return err;
            }
        }

        if (!switch_evidence.empty()) {
            err = nvat_attestation_ctx_set_switch_evidence_source_json_file(*ctx, switch_evidence.c_str());
            if (err != NVAT_RC_OK) {
                return err;
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
        err = nvat_attest_system(*(ctx.get()), NULL, &raw_claims);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }
        claims.reset(&raw_claims);

        nvat_str_t serialized_str;
        err = nvat_claims_collection_serialize_json(*(claims.get()), &serialized_str);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }

        char * serialized_data = nullptr;
        err = nvat_str_get_data(serialized_str, &serialized_data);
        if (err != NVAT_RC_OK) {
            return AttestOutput(err);
        }

        return AttestOutput(std::string(serialized_data), NVAT_RC_OK);
    }


    int handle_attest_subcommand(
        std::vector<std::string>& devices, 
        std::string& verifier, 
        std::string& gpu_evidence, 
        std::string& switch_evidence,
        std::string& relying_party_policy,
        std::string& rim_url,
        std::string& ocsp_url,
        std::string& nras_url) {

        AttestOutput attest_output = attest(devices, verifier, gpu_evidence, switch_evidence, relying_party_policy, rim_url, ocsp_url, nras_url);
        nvat_sdk_shutdown();

        auto json = attest_output.to_json();
        SPDLOG_INFO(json.dump(4));
        return attest_output.result_code;
    }
}
