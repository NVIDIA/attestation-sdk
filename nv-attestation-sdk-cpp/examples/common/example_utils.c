/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */

#include "example_utils.h"
#include <string.h>

static nvat_log_level_t get_log_level_from_env() {
    const char* env_val = getenv("NVAT_SDK_EXAMPLES_LOG_LEVEL");
    if (env_val == NULL) {
        return NVAT_LOG_LEVEL_ERROR;
    }
    if (strcmp(env_val, "TRACE") == 0) return NVAT_LOG_LEVEL_TRACE;
    if (strcmp(env_val, "DEBUG") == 0) return NVAT_LOG_LEVEL_DEBUG;
    if (strcmp(env_val, "INFO") == 0) return NVAT_LOG_LEVEL_INFO;
    if (strcmp(env_val, "WARN") == 0) return NVAT_LOG_LEVEL_WARN;
    if (strcmp(env_val, "ERROR") == 0) return NVAT_LOG_LEVEL_ERROR;
    
    // Default to ERROR if value is unknown
    return NVAT_LOG_LEVEL_ERROR;
}

nvat_rc_t setup_sdk(nvat_sdk_opts_t* opts, nvat_logger_t* logger) {
    nvat_rc_t err = nvat_sdk_opts_create(opts);
    if (err != NVAT_RC_OK) {
        fprintf(stderr, "Failed to create SDK options: %s\n", nvat_rc_to_string(err));
        return err;
    }

    nvat_log_level_t log_level = get_log_level_from_env();
    err = nvat_logger_spdlog_create(logger, "nvat_example", log_level);
    if (err != NVAT_RC_OK) {
        fprintf(stderr, "Failed to create logger: %s\n", nvat_rc_to_string(err));
        nvat_sdk_opts_free(opts);
        return err;
    }
    nvat_sdk_opts_set_logger(*opts, *logger);

    err = nvat_sdk_init(*opts);
    if (err != NVAT_RC_OK) {
        fprintf(stderr, "Failed to initialize SDK: %s\n", nvat_rc_to_string(err));
        nvat_sdk_opts_free(opts);
        nvat_logger_free(logger);
    }
    return err;
}

void cleanup_sdk(nvat_sdk_opts_t* opts, nvat_logger_t* logger) {
    if (opts) {
        nvat_sdk_opts_free(opts);
    }
    if (logger) {
        nvat_logger_free(logger);
    }
    nvat_sdk_shutdown();
}

nvat_rc_t create_default_gpu_ctx(nvat_attestation_ctx_t* ctx) {
    nvat_rc_t err = nvat_attestation_ctx_create(ctx);
    if (err != NVAT_RC_OK) {
        fprintf(stderr, "Failed to create attestation context: %s\n", nvat_rc_to_string(err));
        return err;
    }

    err = nvat_attestation_ctx_set_device_type(*ctx, NVAT_DEVICE_GPU);
    if (err != NVAT_RC_OK) {
        fprintf(stderr, "Failed to set device type to GPU: %s\n", nvat_rc_to_string(err));
        nvat_attestation_ctx_free(ctx);
    }
    return err;
}

nvat_rc_t print_results(nvat_rc_t attestation_rc, nvat_str_t detached_eat, nvat_claims_collection_t claims) {
    if (attestation_rc != NVAT_RC_OK && attestation_rc != NVAT_RC_RP_POLICY_MISMATCH && attestation_rc != NVAT_RC_OVERALL_RESULT_FALSE) {
        fprintf(stderr, "Error during attestation: %s (code: %d)\n", nvat_rc_to_string(attestation_rc), attestation_rc);
        return attestation_rc;
    }

    if (attestation_rc == NVAT_RC_RP_POLICY_MISMATCH) {
         fprintf(stderr, "Attestation results did not match relying party policy (code: %d)\n", attestation_rc);
    } else if (attestation_rc == NVAT_RC_OVERALL_RESULT_FALSE) {
         fprintf(stderr, "Overall attestation result fail (code: %d)\n", attestation_rc);
    } else {
        printf("Attestation successful.\n");
    }

    // Print Detached EAT
    if (detached_eat != NULL) {
        char* detached_buf = NULL;
        nvat_rc_t err = nvat_str_get_data(detached_eat, &detached_buf);
        if (err != NVAT_RC_OK) {
             fprintf(stderr, "Failed to get detached EAT data: %s\n", nvat_rc_to_string(err));
        } else {
            printf("Detached EAT: %s\n", detached_buf);
        }
    }

    // Print Claims
    if (claims != NULL) {
        nvat_str_t json_str;
        nvat_rc_t err = nvat_claims_collection_serialize_json(claims, &json_str);
        if (err != NVAT_RC_OK) {
            fprintf(stderr, "Failed to serialize claims: %s\n", nvat_rc_to_string(err));
            return attestation_rc;
        }

        char* buf = NULL;
        err = nvat_str_get_data(json_str, &buf);
        if (err != NVAT_RC_OK) {
            fprintf(stderr, "Failed to get claims JSON data: %s\n", nvat_rc_to_string(err));
        } else {
            printf("Claims: %s\n", buf);
        }
        nvat_str_free(&json_str);
    }
    
    return attestation_rc;
}
