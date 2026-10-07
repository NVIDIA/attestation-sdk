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

#include "verify_token_output.h"

namespace nvattest {

bool verify_token_result_has_claims(nvat_rc_t rc) {
    return rc == NVAT_RC_OK ||
           rc == NVAT_RC_RP_POLICY_MISMATCH ||
           rc == NVAT_RC_OVERALL_RESULT_FALSE;
}

int verify_token_exit_code(nvat_rc_t rc) {
    if (rc == NVAT_RC_OK) {
        return 0;
    }
    if (rc == NVAT_RC_RP_POLICY_MISMATCH) {
        return 2;
    }
    if (rc == NVAT_RC_OVERALL_RESULT_FALSE) {
        return 3;
    }
    return 1;
}

nlohmann::json verify_token_build_json(nvat_rc_t rc, const std::string& result_message,
                                       const std::string& claims) {
    nlohmann::json claims_json = nlohmann::json::object();
    if (verify_token_result_has_claims(rc) && !claims.empty()) {
        try {
            claims_json = nlohmann::json::parse(claims);
        } catch (const nlohmann::json::parse_error&) {
            // Malformed claims payload: fall back to an empty object rather than
            // failing the whole output. The result code still conveys the state.
            claims_json = nlohmann::json::object();
        }
    }

    nlohmann::json output = nlohmann::json::object();
    output["result_code"] = rc;
    output["result_message"] = result_message;
    output["claims"] = claims_json;
    return output;
}

nlohmann::json verify_token_build_ear_json(
    nvat_rc_t rc, const std::string& result_message, const std::string& ear,
    bool include_ear) {
    nlohmann::json ear_json = nlohmann::json::object();
    if (include_ear && !ear.empty()) {
        const nlohmann::json parsed =
            nlohmann::json::parse(ear, nullptr, /*allow_exceptions=*/false);
        if (parsed.is_object()) {
            ear_json = parsed;
        }
    }

    nlohmann::json output = nlohmann::json::object();
    output["result_code"] = rc;
    output["result_message"] = result_message;
    output["ear"] = ear_json;
    return output;
}

} // namespace nvattest
