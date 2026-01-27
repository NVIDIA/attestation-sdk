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
#include <stdlib.h>

int main(void) {
    nvat_sdk_opts_t opts;
    nvat_logger_t logger;
    if (setup_sdk(&opts, &logger) != NVAT_RC_OK) return 1;

    nvat_attestation_ctx_t ctx;
    if (create_default_gpu_ctx(&ctx) != NVAT_RC_OK) {
        cleanup_sdk(&opts, &logger);
        return 1;
    }

    nvat_rc_t err = nvat_attestation_ctx_set_verifier_type(ctx, NVAT_VERIFY_REMOTE);
    if (err != NVAT_RC_OK) {
        fprintf(stderr, "Failed to set verifier type: %s\n", nvat_rc_to_string(err));
        nvat_attestation_ctx_free(&ctx);
        cleanup_sdk(&opts, &logger);
        return 1;
    }
    
    // Check for optional service key for NRAS
    const char* api_key = getenv("EXAMPLE_NRAS_SERVICE_KEY");
    if (api_key) {
        err = nvat_attestation_ctx_set_service_key(ctx, api_key);
        if (err != NVAT_RC_OK) {
            fprintf(stderr, "Failed to set service key: %s\n", nvat_rc_to_string(err));
            nvat_attestation_ctx_free(&ctx);
            cleanup_sdk(&opts, &logger);
            return 1;
        }
    }

    nvat_str_t detached_eat = NULL;
    nvat_claims_collection_t claims = NULL;
    nvat_rc_t rc = nvat_attest_device(ctx, NULL, &detached_eat, &claims);

    print_results(rc, detached_eat, claims);
    
    if (detached_eat) nvat_str_free(&detached_eat);
    if (claims) nvat_claims_collection_free(&claims);

    nvat_attestation_ctx_free(&ctx);
    cleanup_sdk(&opts, &logger);

    return (rc == NVAT_RC_OK) ? 0 : 1;
}
