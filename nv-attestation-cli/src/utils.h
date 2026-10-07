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

#include <cstdint>
#include <string>
#include <vector>

#include "CLI/CLI.hpp"
#include "nvattest_options.h"
#include "nvat.h"
#include "nvattest_types.h"
#include "logging.h"

namespace nvattest {
    void add_evidence_collection_options(CLI::App* app, EvidenceCollectionOptions& options);
    void add_evidence_policy_options(CLI::App* app, EvidencePolicyOptions& options);
    void add_evidence_verification_options(CLI::App* app, EvidenceVerificationOptions& options);
    void add_ocsp_cert_id_hash_option(CLI::App* app, std::string& value);
    void add_common_options(CLI::App& app, CommonOptions& options);

    void print_error_help(const CliLogger& logger, nvat_rc_t rc);
    nvat_rc_t init_sdk(CliLogger& logger, const CommonOptions& common_options);

    /**
     * @brief Builds an nvat_http_options_t from the TLS CA fields in verification_options.
     *
     * Returns NVAT_RC_OK and sets http_options_raw to nullptr when neither field is set
     * (callers pass nullptr directly to SDK functions). Returns an error code on SDK
     * allocation failure.  The caller must wrap the returned handle in nv_unique_ptr.
     */
    nvat_rc_t make_http_options(
        const EvidenceVerificationOptions& verification_options,
        nvat_http_options_t& http_options_raw);

    /** @brief Validates OCSP CertID hash names using the SDK parser. */
    CLI::Validator ocsp_cert_id_hash_validator();

    /**
     * @brief Builds OCSP client options for the requested CertID hash name.
     *
     * The caller must wrap the returned handle in nv_unique_ptr.
     */
    nvat_rc_t make_ocsp_client_options(
        const std::string& name,
        nvat_ocsp_client_options_t& out_options);

    /**
     * @brief Loads a Rego relying-party policy and creates its SDK handle.
     *
     * On failure, out_raw_policy is null. The caller owns and must free a
     * successful returned handle.
     */
    nvat_rc_t load_relying_party_policy(
        const std::string& path,
        nvat_relying_party_policy_t& out_raw_policy);

    /** Removes ASCII whitespace from both ends of a CLI input string. */
    void trim_ascii_whitespace(std::string& value);

    nvat_rc_t read_binary_file(const std::string& path, std::vector<uint8_t>& out);

    // Collect GPU evidence from an already-created source and pack it into a
    // serialized CMW input collection (JSON bytes).
    nvat_rc_t collect_cmw_json(nvat_gpu_evidence_source_t source,
                               nvat_nonce_t nonce,
                               std::vector<uint8_t>& out_cmw_json);

    // Build a CMW input collection from an SPDM transcript + PEM cert chain and
    // serialize it to JSON bytes. nonce_hex may be empty (no freshness binding).
    nvat_rc_t collect_cmw_json_from_spdm(const std::string& transcript_file,
                                         const std::string& cert_chain_file,
                                         const std::string& nonce_hex,
                                         std::vector<uint8_t>& out_cmw_json);

    // Build a CMW input collection from a signed EAT/CWT file and serialize it
    // to JSON bytes. nonce_hex may be empty (no freshness binding).
    nvat_rc_t collect_cmw_json_from_eat(const std::string& eat_file,
                                        const std::string& nonce_hex,
                                        std::vector<uint8_t>& out_cmw_json);
}
