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

#include "utils.h"
#include "CLI/Validators.hpp"
#include "logging.h"
#include "nvat.h"
#include "spdlog/spdlog.h"
#include <sstream>
#include <string>

namespace nvattest {

    nvat_log_level_t CommonOptions::get_log_level() const {
        if (log_level_str == "trace") return NVAT_LOG_LEVEL_TRACE;
        if (log_level_str == "debug") return NVAT_LOG_LEVEL_DEBUG;
        if (log_level_str == "info") return NVAT_LOG_LEVEL_INFO;
        if (log_level_str == "warn") return NVAT_LOG_LEVEL_WARN;
        if (log_level_str == "error") return NVAT_LOG_LEVEL_ERROR;
        if (log_level_str == "off") return NVAT_LOG_LEVEL_OFF;
        return NVAT_LOG_LEVEL_INFO;
    }

    void add_evidence_collection_options(CLI::App* app, EvidenceCollectionOptions& options) {
        app->add_option("--nonce", options.nonce, "Nonce for the attestation in hex format. If not provided, a nonce will be generated.")
            ->default_val("");
        app->add_option("--device,-d", options.device, "Device to attest")
            ->check(CLI::IsMember({"gpu", "nvswitch"}))
            ->default_val("gpu");

        static const char* gpu_evidence_group = "GPU Evidence";
        app->add_option("--gpu-evidence-source", options.gpu_evidence_source, 
            "Source of GPU evidence. Used if --device=gpu\n\n"
            "NVML is the default and requires the NVIDIA GPU driver to be installed. "
            "Files can be used to appraise previously collected evidence.")
            ->group(gpu_evidence_group)
            ->check(CLI::IsMember({"nvml", "file"}))
            ->default_val("nvml");
        app->add_option("--gpu-evidence-file", options.gpu_evidence_file, 
            "Path to a file containing GPU evidence. Used if --gpu-evidence-source=file")
            ->group(gpu_evidence_group)
            ->default_str("");

        static const char* switch_evidence_group = "NVSwitch Evidence";
        app->add_option("--nvswitch-evidence-source", options.switch_evidence_source,
            "Source of NVSwitch evidence. Used if --device=nvswitch\n\n"
            "NSCQ is the default and requires NSCQ to be installed. "
            "Files can be used to appraise previously collected evidence.")
            ->group(switch_evidence_group)
            ->check(CLI::IsMember({"nscq", "file"}))
            ->default_val("nscq");
        app->add_option("--nvswitch-evidence-file", options.switch_evidence_file, 
            "Path to a file containing NVSwitch evidence. Used if --nvswitch-evidence-source=file")
            ->group(switch_evidence_group)
            ->default_str("");

        app->parse_complete_callback([&options]() {
            if (options.device == "gpu" && options.gpu_evidence_source == "file") {
                if (options.gpu_evidence_file.empty()) {
                    throw CLI::ValidationError("--gpu-evidence-file", "--gpu-evidence-file must be provided when --gpu-evidence-source=file");
                }
                auto validator = CLI::ExistingFile;
                auto result = validator(options.gpu_evidence_file);
                if (!result.empty()) {
                    throw CLI::ValidationError("--gpu-evidence-file", result);
                }
            }
            if (options.device == "nvswitch" && options.switch_evidence_source == "file") {
                if (options.switch_evidence_file.empty()) {
                    throw CLI::ValidationError("--nvswitch-evidence-file", "--nvswitch-evidence-file must be provided when --nvswitch-evidence-source=file");
                }
                auto validator = CLI::ExistingFile;
                auto result = validator(options.switch_evidence_file);
                if (!result.empty()) {
                    throw CLI::ValidationError("--nvswitch-evidence-file", result);
                }
            }
        });
    }

    void add_evidence_policy_options(CLI::App* app, EvidencePolicyOptions& options) {
        static const char* group = "Evidence Appraisal Options";
        app->add_flag("--verify-rim-signatures,!--no-verify-rim-signatures", options.verify_rim_signature, "Whether to verify RIM file signatures")
            ->group(group)
            ->default_val(true);
        app->add_flag("--verify-rim-cert-chain,!--no-verify-rim-cert-chain", options.verify_rim_cert_chain, "Whether to verify RIM file certificate chains")
            ->group(group)
            ->default_val(true);
    }

    void add_evidence_verification_options(CLI::App* app, EvidenceVerificationOptions& options) {
        app->add_option("--verifier", options.verifier, "Appraise evidence using the given verifier type")
            ->check(CLI::IsMember({"local", "remote"}))
            ->default_val("local");
        app->add_option("--relying-party-policy", options.relying_party_policy, "Path to a local file which contains a Relying Party Rego policy")
            ->check(CLI::ExistingFile)
            ->default_str("");
        app->add_option("--rim-store", options.rim_store, "Type of RIM store to use if --verifier=local")
            ->check(CLI::IsMember({"remote", "dir"}))
            ->default_val("remote");
        app->add_option("--rim-url", options.rim_url, "Base URL for the NVIDIA RIM service. Used if --rim-store=remote")
            ->envname("NVAT_RIM_SERVICE_BASE_URL")
            ->default_val("https://rim.attestation.nvidia.com");
        app->add_option("--rim-dir", options.rim_path, "Path to a directory containing RIM files. Used if --rim-store=dir")
            ->check(CLI::ExistingDirectory)
            ->default_val(".");
        app->add_option("--ocsp-url", options.ocsp_url, "Base URL for the OCSP responder")
            ->envname("NVAT_OCSP_BASE_URL")
            ->default_val("https://ocsp.ndis.nvidia.com");
        app->add_option("--nras-url", options.nras_url, "Base URL for the NVIDIA Remote Attestation Service")
            ->envname("NVAT_NRAS_BASE_URL")
            ->default_val("https://nras.attestation.nvidia.com");
        app->add_option("--service-key", options.service_key, "Service key used to authenticate remote service calls to attestation services")
           ->envname("NV_ATTESTATION_SERVICE_KEY")
           ->default_val("");
    }

    void add_common_options(CLI::App& app, CommonOptions& options) {
        app.fallthrough(true);
        
        app.add_option("--log-level,-l", options.log_level_str, "Print logs at or above the given level")
            ->envname("NVAT_LOG_LEVEL")
            ->check(CLI::IsMember({"trace", "debug", "info", "warn", "error", "off"}))
            ->default_val("info");
        
        app.add_option("--format,-f", options.format, "Print output in the given format")
            ->envname("NVAT_FORMAT")
            ->check(CLI::IsMember({"text", "json"}))
            ->default_val("text");
    }

    void print_error_help(const CliLogger& logger, nvat_rc_t rc) {
        if (rc == NVAT_RC_OK) {
            return;
        }

        bool needs_debug_hint = true;
        switch(rc) {
            case NVAT_RC_BAD_ARGUMENT:
                needs_debug_hint = false;
                break;
            case NVAT_RC_RP_POLICY_MISMATCH:
                SPDLOG_CRITICAL("Submitted evidence was appraised by the verifier, but did not match the relying party policy.");
                SPDLOG_CRITICAL("Review the attestation results against the supplied relying party policy.");
                break;
            case NVAT_RC_OVERALL_RESULT_FALSE:
                SPDLOG_CRITICAL("Submitted evidence did not match the verifier evidence appraisal policy.");
                break;
            case NVAT_RC_NVML_INIT_FAILED:
                SPDLOG_CRITICAL("Ensure the NVIDIA Driver is installed and initialized.");
                break;
            case NVAT_RC_NSCQ_INIT_FAILED:
                SPDLOG_CRITICAL("Ensure libnvidia-nscq is installed and an NVSwitch is available on this node.");
                break;
        }

        SPDLOG_CRITICAL("");
        SPDLOG_CRITICAL("Error {:03d}: {}", rc, nvat_rc_to_string(rc));
        SPDLOG_CRITICAL("Backtrace:");
        auto errors = logger.get_error_messages();
        if (!errors.empty()) {
            for (auto it = errors.rbegin(); it != errors.rend(); ++it) {
                std::istringstream stream(*it);
                std::string line;
                bool first_line = true;
                while (std::getline(stream, line)) {
                    if (first_line) {
                        SPDLOG_CRITICAL("  | {}", line);
                        first_line = false;
                    } else {
                        SPDLOG_CRITICAL("    {}", line);
                    }
                }
            }
        }

        if (needs_debug_hint) {
            SPDLOG_CRITICAL("");
            SPDLOG_CRITICAL("Run with --log-level=debug for more information.");
        }
    }

    nvat_rc_t init_sdk(CliLogger& logger, const CommonOptions& common_options) {
        nvat_rc_t err;

        nv_unique_ptr<nvat_sdk_opts_t> opts;
        nvat_sdk_opts_t raw_opts = nullptr;
        err = nvat_sdk_opts_create(&raw_opts);
        if (err != NVAT_RC_OK) {
            return err;
        }
        opts.reset(&raw_opts);

        nvat_logger_t nvat_logger;
        err = logger.create_nvat_logger(&nvat_logger);
        if (err != NVAT_RC_OK) {
            return err;
        }
        nvat_sdk_opts_set_logger(*(opts.get()), nvat_logger);
        nvat_logger_free(&nvat_logger);

        return nvat_sdk_init(*(opts.get()));
    }
}
