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

#include "example_utils.h"

const char* REGO_RP_POLICY =
  "package policy\n"
  "import future.keywords.every\n"
  "default nv_match := false\n"
  "nv_match {\n"
  "  every result in input {\n"
  "    result[\"x-nvidia-device-type\"] == \"gpu\"\n"
  "    result.secboot\n"
  "    result.dbgstat == \"disabled\"\n"
  "  }\n"
  "}\n";

int main(void) {
    nvat_sdk_opts_t opts;
    nvat_logger_t logger;
    if (setup_sdk(&opts, &logger) != NVAT_RC_OK) return 1;

    nvat_attestation_ctx_t ctx;
    if (create_default_gpu_ctx(&ctx) != NVAT_RC_OK) {
        cleanup_sdk(&opts, &logger);
        return 1;
    }

    nvat_relying_party_policy_t rp_policy;
    nvat_rc_t err = nvat_relying_party_policy_create_rego_from_str(&rp_policy, REGO_RP_POLICY);
    if (err != NVAT_RC_OK) {
        fprintf(stderr, "Failed to create policy: %s\n", nvat_rc_to_string(err));
        nvat_attestation_ctx_free(&ctx);
        cleanup_sdk(&opts, &logger);
        return 1;
    }

    err = nvat_attestation_ctx_set_relying_party_policy(ctx, rp_policy);
    nvat_relying_party_policy_free(&rp_policy); // Free after setting
    if (err != NVAT_RC_OK) {
        fprintf(stderr, "Failed to set policy: %s\n", nvat_rc_to_string(err));
        nvat_attestation_ctx_free(&ctx);
        cleanup_sdk(&opts, &logger);
        return 1;
    }

    err = nvat_attestation_ctx_set_verifier_type(ctx, NVAT_VERIFY_LOCAL);
    if (err != NVAT_RC_OK) {
        nvat_attestation_ctx_free(&ctx);
        cleanup_sdk(&opts, &logger);
        return 1;
    }

    nvat_str_t detached_eat = NULL;
    nvat_claims_collection_t claims = NULL;
    nvat_rc_t rc = nvat_attest_device(ctx, NULL, &detached_eat, &claims);

    print_results(rc, detached_eat, claims);

    if (detached_eat) nvat_str_free(&detached_eat);
    if (claims) nvat_claims_collection_free(&claims);

    nvat_attestation_ctx_free(&ctx);
    cleanup_sdk(&opts, &logger);
    
    if (rc == NVAT_RC_OK) return 0;
    if (rc == NVAT_RC_RP_POLICY_MISMATCH) return 1;
    return 1;
}
