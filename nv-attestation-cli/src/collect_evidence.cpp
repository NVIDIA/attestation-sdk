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
#include <vector>

#include "collect_evidence.h"
#include "nvattest_types.h"
#include "nvat.h"
#include "nlohmann/json.hpp"
#include "spdlog/spdlog.h"
#include "utils.h"

namespace nvattest {

    CollectEvidenceOutput::CollectEvidenceOutput(const nvat_rc_t result_code)
        : result_code(result_code), evidences("") {}

    CollectEvidenceOutput::CollectEvidenceOutput(const nvat_rc_t result_code, const std::string& evidences)
        : result_code(result_code), evidences(evidences) {}

    nlohmann::json CollectEvidenceOutput::to_json() const {
        nlohmann::json evidences_json = nullptr;
        if (result_code == NVAT_RC_OK) {
            try {
                evidences_json = nlohmann::json::parse(evidences);
            } catch (const nlohmann::json::parse_error& e) {
                SPDLOG_ERROR("Failed to parse evidences as JSON: {}. Evidences: {}", e.what(), evidences);
            } catch (...) {
                SPDLOG_ERROR("Failed to parse evidences as JSON. Evidences: {}", evidences);
            }
        }

        nlohmann::json output_json = nlohmann::json::object();
        output_json["result_code"] = result_code;
        output_json["result_message"] = nvat_rc_to_string(result_code);
        output_json["evidences"] = evidences_json;
        return output_json;
    }


    CLI::App* create_collect_evidence_subcommand(
        CLI::App& app,
        EvidenceCollectionOptions& evidence_collection_options) {
        
        auto* subcommand = app.add_subcommand("collect-evidence");
        subcommand->description(
            "Collect attestation evidence from a given device.\n\n"
            "Results are printed to standard out. "
            "Control output format through the global --format option."
        );
        add_evidence_collection_options(subcommand, evidence_collection_options);
        return subcommand;
    }

    CollectEvidenceOutput collect_evidence(
        CliLogger& logger,
        const EvidenceCollectionOptions& evidence_collection_options,
        const CommonOptions& common_options
    ) {
        nvat_rc_t err;

        err = init_sdk(logger, common_options);
        if (err != NVAT_RC_OK) {
            return CollectEvidenceOutput(err);
        }

        nv_unique_ptr<nvat_nonce_t> nonce;
        nvat_nonce_t raw_nonce = nullptr;
        if (!evidence_collection_options.nonce.empty()) {
            err = nvat_nonce_from_hex(&raw_nonce, evidence_collection_options.nonce.c_str());
            if (err != NVAT_RC_OK) {
                return CollectEvidenceOutput(err);
            }
        }
        nonce.reset(&raw_nonce);
 
        nv_unique_ptr<nvat_str_t> serialized_evidence;
        nvat_str_t raw_serialized_evidence = nullptr;
        std::string evidences_str = "[]";
 
        if (evidence_collection_options.device == "gpu") {
            // Validate corelib-specific requirements
            if (evidence_collection_options.gpu_evidence_source == "corelib") {
                if (evidence_collection_options.gpu_architecture.empty()) {
                    SPDLOG_ERROR("--gpu-architecture is required when using --gpu-evidence-source=corelib");
                    return CollectEvidenceOutput(NVAT_RC_BAD_ARGUMENT);
                }
            }

            nv_unique_ptr<nvat_gpu_evidence_source_t> source;
            nvat_gpu_evidence_source_t raw_source = nullptr;
            if (evidence_collection_options.gpu_evidence_source == "file") {
                err = nvat_gpu_evidence_source_from_json_file(&raw_source, evidence_collection_options.gpu_evidence_file.c_str());
                if (err != NVAT_RC_OK) {
                    return CollectEvidenceOutput(err);
                }
            } else if (evidence_collection_options.gpu_evidence_source == "corelib") {
                err = nvat_gpu_evidence_source_corelib_create(&raw_source, evidence_collection_options.gpu_architecture.c_str());
                if (err != NVAT_RC_OK) {
                    return CollectEvidenceOutput(err);
                }
            } else {
                err = nvat_gpu_evidence_source_nvml_create(&raw_source);
                if (err != NVAT_RC_OK) {
                    return CollectEvidenceOutput(err);
                }
            }
            source.reset(&raw_source);

            nv_unique_ptr<GpuEvidenceWrapper> evidence_array(new GpuEvidenceWrapper());
            err = nvat_gpu_evidence_collect(
                *(source.get()),
                *(nonce.get()),
                &evidence_array->evidences,
                &evidence_array->num_evidences);
            if (err != NVAT_RC_OK) {
                return CollectEvidenceOutput(err);
            }

            err = nvat_gpu_evidence_serialize_json(
                evidence_array->evidences,
                evidence_array->num_evidences,
                &raw_serialized_evidence);
            if (err != NVAT_RC_OK) {
                SPDLOG_ERROR("Failed to serialize the gpu evidence");
                return CollectEvidenceOutput(NVAT_RC_INTERNAL_ERROR);
            }
        } else if (evidence_collection_options.device == "nvswitch") {
            nv_unique_ptr<nvat_switch_evidence_source_t> source;
            nvat_switch_evidence_source_t raw_source = nullptr;
            if (evidence_collection_options.switch_evidence_source == "file") {
                err = nvat_switch_evidence_source_from_json_file(&raw_source, evidence_collection_options.switch_evidence_file.c_str());
                if (err != NVAT_RC_OK) {
                    return CollectEvidenceOutput(err);
                }
            } else {
                err = nvat_switch_evidence_source_nscq_create(&raw_source);
                if (err != NVAT_RC_OK) {
                    return CollectEvidenceOutput(err);
                }
            }
            source.reset(&raw_source);

            nv_unique_ptr<SwitchEvidenceWrapper> evidence_array(new SwitchEvidenceWrapper());
            err = nvat_switch_evidence_collect(
                *(source.get()),
                *(nonce.get()),
                &evidence_array->evidences,
                &evidence_array->num_evidences);
            if (err != NVAT_RC_OK) {
                return CollectEvidenceOutput(err);
            }

            err = nvat_switch_evidence_serialize_json(
                evidence_array->evidences,
                evidence_array->num_evidences,
                &raw_serialized_evidence);
            if (err != NVAT_RC_OK) {
                SPDLOG_ERROR("Failed to serialize the switch evidence");
                return CollectEvidenceOutput(NVAT_RC_INTERNAL_ERROR);
            }
        }
        serialized_evidence.reset(&raw_serialized_evidence);
 
        char* evidences_data = nullptr;
        err = nvat_str_get_data(*(serialized_evidence.get()), &evidences_data);
        if (err != NVAT_RC_OK) {
            return CollectEvidenceOutput(err);
        }
        evidences_str = std::string(evidences_data);
        
        return CollectEvidenceOutput(err, evidences_str);
    }

    int handle_collect_evidence_subcommand(
        CliLogger& logger,
        const EvidenceCollectionOptions& evidence_collection_options,
        const CommonOptions& common_options
    ) {
        CollectEvidenceOutput output = collect_evidence(logger, evidence_collection_options, common_options);
        nvat_sdk_shutdown();

        if(common_options.format == "text") {
            if (output.result_code == NVAT_RC_OK) {
                SPDLOG_INFO("{} evidence collection was successful.", evidence_collection_options.pretty_device());
            } else {
                SPDLOG_CRITICAL("");
                SPDLOG_CRITICAL("{} evidence collection failed!", evidence_collection_options.pretty_device());
                print_error_help(logger, output.result_code);
            }
        } else if (common_options.format == "json") {
            auto json = output.to_json();
            std::cout << json.dump(4) << std::endl;
        }
        return output.result_code;
    }
}