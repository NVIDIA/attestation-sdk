/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "CLI/Validators.hpp"
#include "collect_evidence_v2.h"
#include "nvat.h"
#include "nvattest_types.h"
#include "spdlog/spdlog.h"
#include "utils.h"

namespace nvattest {

namespace {

class CollectEvidenceV2Output {
  public:
    nvat_rc_t result_code = NVAT_RC_OK;
    nlohmann::json evidences = nullptr;

};

CollectEvidenceV2Output run_collect(
    CliLogger& logger,
    const EvidenceCollectionV2Options& options,
    const CommonOptions& common_options) {

    CollectEvidenceV2Output output;

    nvat_rc_t err = init_sdk(logger, common_options);
    if (err != NVAT_RC_OK) {
        output.result_code = err;
        return output;
    }

    if (options.evidence_source == "spdm-files") {
        std::vector<uint8_t> cmw_json;
        err = collect_cmw_json_from_spdm(
            options.spdm_transcript_file, options.cert_chain_file,
            options.nonce, cmw_json);
        if (err != NVAT_RC_OK) {
            output.result_code = err;
            return output;
        }
        output.evidences = nlohmann::json::parse(
            cmw_json, nullptr, /*allow_exceptions=*/false);
        if (output.evidences.is_discarded()) {
            SPDLOG_ERROR("Failed to parse serialized CMW JSON from SPDM transcript");
            output.result_code = NVAT_RC_JSON_SERIALIZATION_ERROR;
            return output;
        }
        output.result_code = NVAT_RC_OK;
        return output;
    }

    nvat_nonce_t raw_nonce = nullptr;
    nv_unique_ptr<nvat_nonce_t> nonce_guard;
    if (!options.nonce.empty()) {
        err = nvat_nonce_from_hex(&raw_nonce, options.nonce.c_str());
    } else {
        err = nvat_nonce_create(&raw_nonce, 32);
    }
    if (err != NVAT_RC_OK) {
        output.result_code = err;
        return output;
    }
    nonce_guard.reset(&raw_nonce);

    nvat_gpu_evidence_source_t raw_source = nullptr;
    nv_unique_ptr<nvat_gpu_evidence_source_t> source_guard;
    if (options.evidence_source == "corelib") {
        // TODO: hardcoded, needs revisiting once we need to enable other GPU arch.
        err = nvat_gpu_evidence_source_corelib_create(&raw_source, "BLACKWELL");
    } else {
        err = nvat_gpu_evidence_source_nvml_create(&raw_source);
    }
    if (err != NVAT_RC_OK) {
        output.result_code = err;
        return output;
    }
    source_guard.reset(&raw_source);

    std::vector<uint8_t> cmw_json;
    err = collect_cmw_json(raw_source, raw_nonce, cmw_json);
    if (err != NVAT_RC_OK) {
        output.result_code = err;
        return output;
    }
    try {
        output.evidences = nlohmann::json::parse(cmw_json);
    } catch (const nlohmann::json::parse_error& e) {
        SPDLOG_ERROR("Failed to parse serialized CMW JSON: {}", e.what());
        output.result_code = NVAT_RC_JSON_SERIALIZATION_ERROR;
        return output;
    }
    output.result_code = NVAT_RC_OK;
    return output;
}

} // namespace

CLI::App* create_collect_evidence_v2_subcommand(
    CLI::App& app, EvidenceCollectionV2Options& options) {

    auto* subcommand = app.add_subcommand("collect-evidence-v2");
    subcommand->group("Experimental Subcommands");
    subcommand->description(
        "[EXPERIMENTAL] Collect attestation evidence and emit a CMW input collection.");

    subcommand->add_option(
        "--nonce", options.nonce,
        "Nonce for the attestation in hex format. "
        "Required for nvml (generated if absent); "
        "optional for spdm-files (enables transcript freshness check if supplied).")
        ->default_val("");

    subcommand->add_option("--evidence-source", options.evidence_source,
                           "Where evidence comes from. nvml collects live via NVML; "
                           "corelib collects live via Corelib (non-CC mode only); "
                           "spdm-files reads a raw SPDM transcript and PEM cert chain.")
        ->check(CLI::IsMember({"nvml", "corelib", "spdm-files"}))
        ->default_val("nvml");

    subcommand->add_option(
        "--spdm-transcript-file", options.spdm_transcript_file,
        "Path to a binary SPDM measurement transcript. Required when "
        "--evidence-source=spdm-files.")
        ->check(CLI::ExistingFile);

    subcommand->add_option(
        "--cert-chain-file", options.cert_chain_file,
        "Path to a PEM certificate chain. Required when --evidence-source=spdm-files.")
        ->check(CLI::ExistingFile);

    subcommand->parse_complete_callback([&options]() {
        if (options.evidence_source == "spdm-files") {
            if (options.spdm_transcript_file.empty()) {
                throw CLI::ValidationError(
                    "--spdm-transcript-file",
                    "--spdm-transcript-file must be provided when --evidence-source=spdm-files");
            }
            if (options.cert_chain_file.empty()) {
                throw CLI::ValidationError(
                    "--cert-chain-file",
                    "--cert-chain-file must be provided when --evidence-source=spdm-files");
            }
        }
    });

    return subcommand;
}

int handle_collect_evidence_v2_subcommand(
    CliLogger& logger,
    const EvidenceCollectionV2Options& options,
    const CommonOptions& common_options) {

    CollectEvidenceV2Output output = run_collect(logger, options, common_options);
    nvat_sdk_shutdown();

    if (common_options.format == "text") {
        if (output.result_code == NVAT_RC_OK) {
            SPDLOG_INFO("GPU evidence (v2) collection was successful.");
            SPDLOG_INFO("Re-run with --format=json to print the CMW collection.");
        } else {
            SPDLOG_CRITICAL("");
            SPDLOG_CRITICAL("GPU evidence (v2) collection failed!");
            print_error_help(logger, output.result_code);
        }
    } else {
        if (output.result_code == NVAT_RC_OK) {
            std::cout << output.evidences.dump(4) << std::endl;
        } else {
            SPDLOG_CRITICAL("");
            SPDLOG_CRITICAL("Evidence collection failed!");
            print_error_help(logger, output.result_code);
        }
    }
    return output.result_code;
}

} // namespace nvattest
