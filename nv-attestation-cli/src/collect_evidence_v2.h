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

#pragma once
#include <string>

#include "CLI/CLI.hpp"
#include "logging.h"
#include "nvat.h"
#include "nvattest_options.h"

namespace nvattest {

struct EvidenceCollectionV2Options {
    std::string nonce;
    std::string evidence_source;      // nvml | corelib | spdm-files
    std::string spdm_transcript_file; // required if spdm-files
    std::string cert_chain_file;      // required if spdm-files
};

CLI::App* create_collect_evidence_v2_subcommand(
    CLI::App& app,
    EvidenceCollectionV2Options& options);

int handle_collect_evidence_v2_subcommand(
    CliLogger& logger,
    const EvidenceCollectionV2Options& options,
    const CommonOptions& common_options);

} // namespace nvattest
