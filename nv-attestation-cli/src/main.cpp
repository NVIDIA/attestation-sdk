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

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_sinks.h"


int main(int argc, char** argv) {
    // Configure logger
    auto console = spdlog::stdout_logger_mt("console");
    spdlog::set_default_logger(console);
    spdlog::set_pattern("%v");

    CLI::App app{"NVIDIA attestation CLI for collecting evidence and verifying device integrity in confidential computing environments"};
    app.set_config("--config", "config.toml", "Read options from a TOML configuration file");

    // todo (p1): group these options into a struct and pass it to the subcommands
    std::string nonce, device, verifier, gpu_evidence, switch_evidence, relying_party_policy, rim_url, ocsp_url, nras_url;
    std::string log_level;
    
    CLI::App* version_subcommand = nvattest::create_version_subcommand(app);
    CLI::App* attest_subcommand = nvattest::create_attest_subcommand(app, nonce, device, verifier, gpu_evidence, switch_evidence, relying_party_policy, rim_url, ocsp_url, nras_url, log_level);

    CLI11_PARSE(app, argc, argv);

    // Dispatch subcommands
    if (version_subcommand->parsed()) {
        return nvattest::handle_version_subcommand();
    } else if (attest_subcommand->parsed()) {
        return nvattest::handle_attest_subcommand(nonce, device, verifier, gpu_evidence, switch_evidence, relying_party_policy, rim_url, ocsp_url, nras_url, log_level);
    } else {
        // Default behavior is to display the help message
        std::cout << app.help() << std::endl;
    }

    return 0;
}