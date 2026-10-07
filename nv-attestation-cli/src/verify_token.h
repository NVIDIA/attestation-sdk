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
#include <nlohmann/json.hpp>

#include "CLI/CLI.hpp"
#include "nvat.h"
#include "nvattest_options.h"
#include "logging.h"

namespace nvattest {

    /**
     * @brief Represents the output of the 'verify-token' CLI subcommand.
     *
     * Encapsulates the token verification results and provides a way to serialize to JSON.
     */
    class VerifyTokenOutput {
      public:
        nvat_rc_t result_code;
        std::string claims;
        std::string ear;
        bool include_ear = false;
        bool ear_output = false;

        explicit VerifyTokenOutput(nvat_rc_t rc) : result_code(rc), claims("") {}
        VerifyTokenOutput(nvat_rc_t rc, const std::string& claims) : result_code(rc), claims(claims) {}
        static VerifyTokenOutput from_ear(nvat_rc_t rc, const std::string& ear,
                                          bool include_ear);
        nlohmann::json to_json() const;
    };

    /**
     * @brief Creates and adds the 'verify-token' subcommand to the main CLI application.
     *
     * @param app The CLI11 application to which the subcommand will be added.
     * @param options Token input options (file path or stdin).
     * @param verification_options Shared evidence verification options (nras-url, relying-party-policy, TLS opts).
     * @return Pointer to the created CLI11 subcommand.
     */
    CLI::App* create_verify_token_subcommand(
        CLI::App& app,
        VerifyTokenOptions& options,
        EvidenceVerificationOptions& verification_options
    );

    /**
     * @brief Handles the logic when the 'verify-token' subcommand is invoked.
     *
     * @param logger CLI logger instance.
     * @param options Token input options.
     * @param verification_options Shared evidence verification options.
     * @param common_options Common CLI options (format, log level).
     * @return Exit code: 0 = success, 1 = error, 2 = RP policy mismatch, 3 = overall result false.
     */
    int handle_verify_token_subcommand(
        CliLogger& logger,
        const VerifyTokenOptions& options,
        const EvidenceVerificationOptions& verification_options,
        const CommonOptions& common_options
    );

} // namespace nvattest
