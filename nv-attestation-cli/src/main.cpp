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

#include "nvat.h"
#include <iostream>
#include <string>
#include "CLI/CLI.hpp"
#include "version.h"
#include "attest.h"
#include "attest_v2.h"
#include "collect_evidence.h"
#include "verify_token.h"
#include "collect_evidence_v2.h"
#include "nvattest_options.h"
#include "utils.h"
#include "logging.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_sinks.h"


int main(int argc, char** argv) {

    CLI::App app{"NVIDIA attestation CLI for collecting evidence and verifying device integrity"};

    nvattest::EvidenceCollectionOptions evidence_collection_options;
    nvattest::EvidenceVerificationOptions evidence_verification_options;
    nvattest::EvidencePolicyOptions evidence_policy_options;
    nvattest::EvidenceCollectionV2Options collect_v2_options;
    nvattest::AttestV2Options attest_v2_options;
    nvattest::CommonOptions common_options;
    nvattest::VerifyTokenOptions verify_token_options;
    

    add_common_options(app, common_options);

    CLI::App* collect_evidence_subcommand = nvattest::create_collect_evidence_subcommand(app, evidence_collection_options);
    CLI::App* attest_subcommand = nvattest::create_attest_subcommand(app, evidence_collection_options, evidence_verification_options, evidence_policy_options);
    CLI::App* collect_evidence_v2_subcommand = nvattest::create_collect_evidence_v2_subcommand(app, collect_v2_options);
    CLI::App* attest_v2_subcommand = nvattest::create_attest_v2_subcommand(app, attest_v2_options);
    CLI::App* version_subcommand = nvattest::create_version_subcommand(app);
    CLI::App* verify_token_subcommand = nvattest::create_verify_token_subcommand(app, verify_token_options, evidence_verification_options);

    CLI11_PARSE(app, argc, argv);

    nvattest::CliLogger logger(common_options.get_log_level());
    logger.install();

    // Dispatch subcommands
    if (version_subcommand->parsed()) {
        return nvattest::handle_version_subcommand();
    } else if (attest_subcommand->parsed()) {
        return nvattest::handle_attest_subcommand(logger, evidence_collection_options, evidence_verification_options, evidence_policy_options, common_options);
    } else if (collect_evidence_subcommand->parsed()) {
        return nvattest::handle_collect_evidence_subcommand(logger, evidence_collection_options, common_options);
    } else if (verify_token_subcommand->parsed()) {
        return nvattest::handle_verify_token_subcommand(logger, verify_token_options, evidence_verification_options, common_options);
    } else if (collect_evidence_v2_subcommand->parsed()) {
        return nvattest::handle_collect_evidence_v2_subcommand(logger, collect_v2_options, common_options);
    } else if (attest_v2_subcommand->parsed()) {
        return nvattest::handle_attest_v2_subcommand(logger, attest_v2_options, common_options);
    } else {
        // Default behavior is to display the help message
        std::cout << app.help() << std::endl;
    }

    return 0;
}
