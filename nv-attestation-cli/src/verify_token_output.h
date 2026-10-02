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

#include "nvat.h"

namespace nvattest {

// Pure output/result-mapping helpers for the verify-token subcommand.
//
// These deliberately depend only on nvat.h (result-code macros/typedef) and
// nlohmann/json — no libnvat symbols — so they can be unit-tested in-process
// by the CLI test binary, which does not link libnvat.

// True when the given verification result code carries a populated claims
// collection (verification succeeded, the relying-party policy rejected the
// claims, or the token's overall result was false — all still produce claims).
bool verify_token_result_has_claims(nvat_rc_t rc);

// Maps a verification result code to the documented process exit code:
//   NVAT_RC_OK                   -> 0
//   NVAT_RC_RP_POLICY_MISMATCH   -> 2
//   NVAT_RC_OVERALL_RESULT_FALSE -> 3
//   anything else                -> 1
int verify_token_exit_code(nvat_rc_t rc);

// Builds the verify-token JSON document. `result_message` is supplied by the
// caller (from nvat_rc_to_string) so this function stays free of libnvat
// symbols. When the result code carries claims and `claims` is non-empty, it is
// parsed as JSON; if it is empty or malformed, an empty object is used.
nlohmann::json verify_token_build_json(nvat_rc_t rc, const std::string& result_message,
                                       const std::string& claims);

nlohmann::json verify_token_build_ear_json(
    nvat_rc_t rc, const std::string& result_message, const std::string& ear,
    bool include_ear);

} // namespace nvattest
