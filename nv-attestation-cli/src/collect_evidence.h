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
#include "nlohmann/json.hpp"

#include "CLI/CLI.hpp"
#include "nvat.h"
#include "nvattest_options.h"
#include "logging.h"

namespace nvattest {
    /**
     * @brief Represents the output of the 'collect-evidence' CLI subcommand.
     *
     * Encapsulates the evidence collection results and provides a way to serialize it into JSON.
     */
    class CollectEvidenceOutput {
        public:
            nvat_rc_t result_code;
            std::string evidences;
        
            CollectEvidenceOutput(const nvat_rc_t result_code);
            CollectEvidenceOutput(const nvat_rc_t result_code, const std::string& evidences);
            nlohmann::json to_json() const;
    };

    /**
     * @brief Creates and adds the 'collect-evidence' subcommand to the main CLI application.
     *
     * @param app The CLI11 application to which the subcommand will be added.
     * @return Pointer to the created CLI11 subcommand.
     */
    CLI::App* create_collect_evidence_subcommand(
        CLI::App& app,
        EvidenceCollectionOptions& evidence_collection_options
    );

    /**
     * @brief Handles the logic when the 'collect-evidence' subcommand is invoked.
     *
     * @param device String specifying which devices to use ("gpu", "nvswitch", etc.).
     * @param nonce Nonce for the attestation (in hex format).
     * @return Exit code for the subcommand handler (0 = success, 1 = failure).
     */
    int handle_collect_evidence_subcommand(
        CliLogger& logger,
        const EvidenceCollectionOptions& evidence_collection_options,
        const CommonOptions& common_options
    );

}
