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
#include <nlohmann/json.hpp>

#include "CLI/CLI.hpp"
#include "nvat.h"

namespace nvattest {

    /**
     * @brief Represents the output of the 'attest' CLI subcommand.
     *
     * Encapsulates the attestation results and provides a way to serialize it into JSON.
     */
    class AttestOutput {
        public:
            int result_code;
            std::string claims;
            std::string detached_eat;
        
            AttestOutput(const int result_code);
            AttestOutput(const int result_code, const std::string& claims, const std::string& detached_eat);
            nlohmann::json to_json() const;
    };

    /**
     * @brief Creates and adds the 'attest' subcommand to the main CLI application.
     *
     * @param app The CLI11 application to which the subcommand will be added.
     * @param devices List of devices to attest
     * @param verifier Reference to a string for verifier type, typically "local" or "remote".
     * @param gpu_evidence Path to a local file which contains GPU evidence. Used instead of calling NVML
     * @param switch_evidence Path to a local file which contains GPU evidence.  Used instead of calling NSCQ
     * @param relying_party_policy Path to a local file which contains a Relying Party Rego policy
     * @param rim_url RIM Service URL
     * @param ocsp_url OCSP URL
     * @param nras_url NRAS URL
     * @return Pointer to the created CLI11 subcommand.
     */
    CLI::App* create_attest_subcommand(
        CLI::App& app,
        std::string& nonce,
        std::vector<std::string>& devices,
        std::string& verifier,
        std::string& gpu_evidence, 
        std::string& switch_evidence,
        std::string& relying_party_policy,
        std::string& rim_url,
        std::string& ocsp_url,
        std::string& nras_url
    );

    /**
     * @brief Handles the logic when the 'attest' subcommand is invoked.
     *
     * @param devices String specifying which devices to use ("gpu", "nvswitch", etc.).
     * @param verifier String specifying verifier type ("local" or "remote").
     * @param gpu_evidence Path to a local file which contains GPU evidence. Used instead of calling NVML
     * @param switch_evidence Path to a local file which contains GPU evidence.  Used instead of calling NSCQ
     * @param relying_party_policy Path to a local file which contains a Relying Party policy
     * @param rim_url RIM Service URL
     * @param ocsp_url OCSP URL
     * @param nras_url NRAS URL
     * @return Exit code for the subcommand handler (0 = success, 1 = failure, 2 = policy mismatch).
     */
    int handle_attest_subcommand(
        std::string& nonce,
        std::vector<std::string>& devices,
        std::string& verifier,
        std::string& gpu_evidence, 
        std::string& switch_evidence,
        std::string& relying_party_policy,
        std::string& rim_url,
        std::string& ocsp_url,
        std::string& nras_url
    );

}
