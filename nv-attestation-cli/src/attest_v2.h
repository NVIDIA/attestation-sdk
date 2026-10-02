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
#include <vector>

#include "CLI/CLI.hpp"
#include "logging.h"
#include "nvattest_options.h"

namespace nvattest {

struct AttestV2Options {
    std::string evidence_source;                 // nvml | file | spdm-files | eat-file
    std::string nonce;                           // expected hex nonce; nvml generates if empty
    std::string evidence_file;                   // required when source=file
    std::string spdm_transcript_file;            // required when source=spdm-files
    std::string cert_chain_file;                 // required when source=spdm-files
    std::string eat_file;                        // required when source=eat-file
    std::vector<std::string> rim_url_rewrites;   // flattened [pattern, replacement] pairs
    bool verify_rim_signature = true;            // false accepts unsigned CoRIMs too
    bool verify_evidence_signature = true;       // false parses unauthenticated evidence
    bool verify_revocation = true;               // OCSP revocation check (on by default)
    std::string ocsp_cert_id_hash;               // OCSP CertID hash algorithm
    std::vector<std::string> ocsp_url_rewrites;  // flattened [pattern, replacement] pairs
    std::string service_key;                     // auth for RIM/OCSP calls; empty = none
    std::string backup_spdm_coev_file;
    std::vector<std::string> backup_rim_locators;
    std::string ear_signing_key_file;
    std::string ear_signing_issuer;
    std::string ear_signing_kid;
    std::string relying_party_policy;
};

CLI::App* create_attest_v2_subcommand(CLI::App& app, AttestV2Options& options);

int handle_attest_v2_subcommand(
    CliLogger& logger,
    const AttestV2Options& options,
    const CommonOptions& common_options);

} // namespace nvattest
