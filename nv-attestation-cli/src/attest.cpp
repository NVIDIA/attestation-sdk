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

    AttestOutput::AttestOutput(const nvat_rc_t result_code)
        : result_code(result_code), claims(""), detached_eat("") {}

    AttestOutput::AttestOutput(const nvat_rc_t result_code, const std::string& claims, const std::string& detached_eat)
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

        auto* subcommand = app.add_subcommand("attest");
        subcommand->description( 
            "Run end-to-end attestation against a given device. \n\n"
            "Results are printed to standard out. "
            "Control output format through the global --format option."
        );

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
        CliLogger& logger,
        const EvidenceCollectionOptions& evidence_collection_options,
        const EvidenceVerificationOptions& evidence_verification_options,
        const EvidencePolicyOptions& evidence_policy_options,
        const CommonOptions& common_options) {

        nvat_rc_t err;

        err = init_sdk(logger, common_options);
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
        nvat_evidence_policy_set_verify_rim_signature(evidence_policy.get(), evidence_policy_options.verify_rim_signature);
        nvat_evidence_policy_set_verify_rim_cert_chain(evidence_policy.get(), evidence_policy_options.verify_rim_cert_chain);

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

            if (evidence_collection_options.gpu_evidence_source == "corelib") {
                SPDLOG_ERROR("The corelib evidence source is only supported with the collect-evidence subcommand.");
                return AttestOutput(NVAT_RC_BAD_ARGUMENT);
            }

            if (evidence_collection_options.gpu_evidence_source == "file") {
                err = nvat_attestation_ctx_set_gpu_evidence_source_json_file(*(ctx.get()), evidence_collection_options.gpu_evidence_file.c_str());
                if (err != NVAT_RC_OK) {
                    return AttestOutput(err);
                }
            }
            // default to NVML
            
        } else if (evidence_collection_options.device == "nvswitch") {
            err = nvat_attestation_ctx_set_device_type(*(ctx.get()), NVAT_DEVICE_NVSWITCH);
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }

            if (evidence_collection_options.switch_evidence_source == "file") {
                err = nvat_attestation_ctx_set_switch_evidence_source_json_file(*(ctx.get()), evidence_collection_options.switch_evidence_file.c_str());
                if (err != NVAT_RC_OK) {
                    return AttestOutput(err);
                }
            }
            // default to NSCQ
        }

        if (!evidence_verification_options.service_key.empty()) {
            err = nvat_attestation_ctx_set_service_key(*(ctx.get()), evidence_verification_options.service_key.c_str());
            if (err != NVAT_RC_OK) {
                return AttestOutput(err);
            }
        }

        // Configure RIM store 
        if (evidence_verification_options.verifier == "local") {
            nv_unique_ptr<nvat_rim_store_t> rim_store;
            nvat_rim_store_t rim_store_raw = nullptr;
            if (evidence_verification_options.rim_store == "remote") {
                auto rim_url = evidence_verification_options.rim_url.c_str();
                auto service_key = evidence_verification_options.service_key.empty() ? nullptr : evidence_verification_options.service_key.c_str();
                err = nvat_rim_store_create_remote(&rim_store_raw, rim_url, service_key, nullptr);
                if (err != NVAT_RC_OK) {
                    return AttestOutput(err);
                }
            } else if (evidence_verification_options.rim_store == "dir") {
                auto rim_dir = evidence_verification_options.rim_path.c_str();
                err = nvat_rim_store_create_filesystem(&rim_store_raw, rim_dir);
                if (err != NVAT_RC_OK) {
                    return AttestOutput(err);
                }
            } else {
                // unreachable
                return AttestOutput(NVAT_RC_BAD_ARGUMENT);
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

    void print_device_claims(const std::string& claims_json) {
        SPDLOG_CRITICAL("Devices: ");
        if (claims_json.empty()) {
            SPDLOG_CRITICAL("[no device claims]");
            return;
        }

        nlohmann::json claims;
        try {
            claims = nlohmann::json::parse(claims_json);
        } catch (...) {
            SPDLOG_CRITICAL("[failed to parse device JSON claims]");
            return;
        }

        auto get_string = [](const nlohmann::json& j, const std::string& key) -> std::string {
            if (j.contains(key)) {
                if (j[key].is_string()) {
                    std::string value = j[key].get<std::string>();
                    return value == "" ? "[blank]" : value;
                }
                if (j[key].is_null()) {
                    return "[not set]";
                }
            }
            return "[unknown]";
        };

        auto string_key_not_blank = [](const nlohmann::json& j, const std::string& key) -> bool {
            return j.contains(key) && j[key].is_string() && !j[key].get<std::string>().empty();
        };

        auto print_cert_chain = [&get_string, &string_key_not_blank](
            const nlohmann::json& device_claims,
            const std::string& key,
            const std::string& label
        ) {
            if (!device_claims.contains(key)) {
                return;
            }
            const auto& cert_chain = device_claims[key];
            if (!cert_chain.is_object()) {
                SPDLOG_CRITICAL("    {}: [invalid]", label);
                return;
            }
            std::string status = get_string(cert_chain, "x-nvidia-cert-status");
            std::string ocsp_status = get_string(cert_chain, "x-nvidia-cert-ocsp-status");
            std::string expiration = get_string(cert_chain, "x-nvidia-cert-expiration-date");

            SPDLOG_CRITICAL("    {}:", label);
            SPDLOG_CRITICAL("        Status: {}, OCSP: {}", status, ocsp_status);
            SPDLOG_CRITICAL("        Expires: {}", expiration);
            if (string_key_not_blank(cert_chain,  "x-nvidia-cert-revocation-reason")) {
                std::string revocation = get_string(cert_chain, "x-nvidia-cert-revocation-reason");
                SPDLOG_CRITICAL("        Revocation Reason: {}", revocation);
            }
        };

        if (!claims.is_array()) {
            SPDLOG_CRITICAL("[expected array of device claims]");
            return;
        }

        for (size_t idx = 0; idx < claims.size(); ++idx) {
            const nlohmann::json& device_claims = claims[idx];

            if (!device_claims.is_object()) {
                SPDLOG_CRITICAL("- Device {}: [invalid claims format]", idx);
                continue;
            }

            SPDLOG_CRITICAL("- Device {}:", idx);

            std::string device_type = get_string(device_claims, "x-nvidia-device-type");
            std::string hwmodel = get_string(device_claims, "hwmodel");
            std::string ueid = get_string(device_claims, "ueid");

            SPDLOG_CRITICAL("    Device Type: {}", device_type);
            SPDLOG_CRITICAL("    Hardware Model: {}", hwmodel);
            SPDLOG_CRITICAL("    UEID: {}", ueid);

            bool is_gpu = (device_type == "gpu");
            bool is_switch = (device_type == "nvswitch");

            if (is_gpu) {
                std::string vbios_version = get_string(device_claims, "x-nvidia-gpu-vbios-version");
                SPDLOG_CRITICAL("    VBIOS Version: {}", vbios_version);

                std::string driver_version = get_string(device_claims, "x-nvidia-gpu-driver-version");
                SPDLOG_CRITICAL("    Driver Version: {}", driver_version);
            } else if (is_switch) {
                std::string bios_version = get_string(device_claims, "x-nvidia-switch-bios-version");
                SPDLOG_CRITICAL("    BIOS Version: {}", bios_version);
            }

            std::string measres = get_string(device_claims, "measres");
            SPDLOG_CRITICAL("    Measurement Result: {}", measres);

            if (is_gpu && string_key_not_blank(device_claims, "x-nvidia-gpu-mode")) {
                std::string gpu_mode = get_string(device_claims, "x-nvidia-gpu-mode");
                SPDLOG_CRITICAL("    GPU Mode: {}", gpu_mode);
            }

            if (is_gpu) {
                print_cert_chain(device_claims, "x-nvidia-gpu-attestation-report-cert-chain", "Attestation Report Cert Chain");
                print_cert_chain(device_claims, "x-nvidia-gpu-driver-rim-cert-chain", "Driver RIM Cert Chain");
                print_cert_chain(device_claims, "x-nvidia-gpu-vbios-rim-cert-chain", "VBIOS RIM Cert Chain");
            } else if (is_switch) {
                print_cert_chain(device_claims, "x-nvidia-switch-attestation-report-cert-chain", "Attestation Report Cert Chain");
                print_cert_chain(device_claims, "x-nvidia-switch-bios-rim-cert-chain", "BIOS RIM Cert Chain");
            }

            if (device_claims.contains("x-nvidia-mismatch-measurement-records")) {
                const auto& mismatches = device_claims["x-nvidia-mismatch-measurement-records"];
                if (mismatches.is_array()) {
                    if (!mismatches.empty()) {
                        SPDLOG_CRITICAL("    Measurement Mismatches ({}):", mismatches.size());
                        for (const auto& mismatch : mismatches) {
                            if (!mismatch.is_object()) {
                                SPDLOG_CRITICAL("      - [invalid mismatch record]");
                                continue;
                            }

                            uint32_t index = mismatch.contains("index") && mismatch["index"].is_number()
                                ? mismatch["index"].get<uint32_t>() : 0;
                            std::string source = mismatch.contains("measurementSource") && mismatch["measurementSource"].is_string()
                                ? mismatch["measurementSource"].get<std::string>() : "unknown";
                            std::string golden = mismatch.contains("goldenValue") && mismatch["goldenValue"].is_string()
                                ? mismatch["goldenValue"].get<std::string>() : "N/A";
                            std::string runtime = mismatch.contains("runtimeValue") && mismatch["runtimeValue"].is_string()
                                ? mismatch["runtimeValue"].get<std::string>() : "N/A";

                            SPDLOG_CRITICAL("      - Index {}: source={}", index, source);
                            SPDLOG_CRITICAL("          Golden:  {}", golden);
                            SPDLOG_CRITICAL("          Runtime: {}", runtime);
                        }
                    }
                } else if (mismatches.is_null()) {
                    // no mismatches - null
                } else {
                    SPDLOG_CRITICAL("    Measurement Mismatches: [invalid record]");
                }
            } else {
                // no mismatches - no claim
            }
        }
        SPDLOG_CRITICAL("");
    }



    int handle_attest_subcommand(
        CliLogger& logger,
        const EvidenceCollectionOptions& evidence_collection_options,
        const EvidenceVerificationOptions& evidence_verification_options,
        const EvidencePolicyOptions& evidence_policy_options,
        const CommonOptions& common_options) {

        AttestOutput output = attest(logger, evidence_collection_options, evidence_verification_options, evidence_policy_options, common_options);
        nvat_sdk_shutdown();

        if(common_options.format == "text") {
            print_device_claims(output.claims);
            if (output.result_code == NVAT_RC_OK) {
                SPDLOG_INFO("{} attestation was successful", evidence_collection_options.pretty_device());
            } else {
                SPDLOG_CRITICAL("");
                SPDLOG_CRITICAL("{} attestation failed!", evidence_collection_options.pretty_device());
                print_error_help(logger, output.result_code);
            }
        } else if (common_options.format == "json") {
            auto json = output.to_json();
            std::cout << json.dump(4) << std::endl;
        }
        return output.result_code;
    }
}
