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

#include <cstdint>
#include <string>

#include "nvat.h"

// Control block for the in-process fake nvat C API (fake_nvat.cpp). A test sets
// the desired return codes / payloads, then calls a CLI handler
// (handle_verify_token_subcommand, handle_attest_subcommand, …) to drive the CLI
// source against the fakes without a real SDK, network, or subprocess.
struct FakeNvatControl {
    // Shared across subcommands.
    nvat_rc_t sdk_init_rc = NVAT_RC_OK;
    nvat_rc_t http_options_rc = NVAT_RC_OK;
    nvat_rc_t serialize_rc = NVAT_RC_OK;
    nvat_rc_t str_get_data_rc = NVAT_RC_OK;
    nvat_rc_t nonce_rc = NVAT_RC_OK;

    // verify-token.
    nvat_rc_t verify_rc = NVAT_RC_OK;
    nvat_rc_t verify_ear_rc = NVAT_RC_OK;
    nvat_rc_t policy_create_rc = NVAT_RC_OK;
    nvat_rc_t policy_apply_rc = NVAT_RC_OK;
    nvat_rc_t policy_apply_ear_rc = NVAT_RC_OK;
    int sdk_shutdown_calls = 0;
    int tracked_sdk_handles = 0;
    bool sdk_shutdown_with_live_handles = false;
    int legacy_verify_calls = 0;
    int ear_verify_calls = 0;
    std::string verified_ear_json =
        "{\"ear_status\":\"affirming\",\"submods\":{\"gpu-0\":{\"ear_status\":\"affirming\"}}}";
    std::string verify_ear_jwt;
    std::string verify_ear_base_url;
    std::string verify_ear_service_key;
    bool verify_ear_nonce_present = false;
    bool verify_ear_http_options_present = false;
    bool verify_ear_jwt_options_present = false;
    uint64_t verify_ear_clock_skew_leeway_seconds = 0;
    std::string policy_apply_ear_input;

    // attest.
    nvat_rc_t ctx_create_rc = NVAT_RC_OK;
    nvat_rc_t evidence_policy_create_rc = NVAT_RC_OK;
    nvat_rc_t rim_store_create_rc = NVAT_RC_OK;
    nvat_rc_t ocsp_create_rc = NVAT_RC_OK;
    nvat_rc_t ocsp_options_create_rc = NVAT_RC_OK;
    nvat_rc_t ocsp_options_set_rc = NVAT_RC_OK;
    nvat_rc_t attest_rc = NVAT_RC_OK;
    nvat_ocsp_cert_id_hash_algorithm_t last_ocsp_cert_id_hash =
        NVAT_OCSP_CERT_ID_HASH_SHA256;
    int ocsp_options_create_calls = 0;
    int ocsp_options_free_calls = 0;
    int ocsp_default_create_calls = 0;
    int ocsp_default_with_options_create_calls = 0;

    // collect-evidence.
    nvat_rc_t source_create_rc = NVAT_RC_OK;
    nvat_rc_t collect_rc = NVAT_RC_OK;

    // attest-v2 / CoRIM verifier.
    nvat_rc_t corim_store_create_rc = NVAT_RC_OK;
    nvat_rc_t corim_store_enable_in_memory_cache_rc = NVAT_RC_OK;
    nvat_rc_t ocsp_create_cached_rc = NVAT_RC_OK;
    nvat_rc_t corim_verifier_create_rc = NVAT_RC_OK;
    nvat_rc_t detached_eat_options_create_rc = NVAT_RC_OK;
    nvat_rc_t verify_cmw_rc = NVAT_RC_OK;
    int ocsp_aia_create_calls = 0;
    int ocsp_cached_create_calls = 0;
    // Result JSON handed back by nvat_local_corim_verifier_verify_cmw. Set to
    // an empty string to model a verifier that reports success but yields no
    // usable result.
    std::string verify_cmw_result_json =
        "{\"submods\":{\"gpu_0\":{\"ear_status\":\"contraindicated\"}}}";

    // collect-evidence-v2 / CMW.
    nvat_rc_t cmw_create_rc = NVAT_RC_OK;
    nvat_rc_t cmw_serialize_rc = NVAT_RC_OK;
    nvat_rc_t str_length_rc = NVAT_RC_OK;

    // Serialized payloads the fakes hand back.
    std::string claims_json = "[{\"x-nvidia-device-type\":\"gpu\"}]";
    std::string detached_eat_json = "[[\"JWT\",\"fake\"],{\"GPU-0\":\"fake\"}]";
    std::string evidences_json = "[{\"arch\":\"HOPPER\"}]";
    std::string cmw_json = "{\"__cmwc_t\":\"tag:nvidia.com,2024:cmw\"}";
};

extern FakeNvatControl g_fake_nvat;

// Reset all controls to their defaults (success path with sample claims).
void fake_nvat_reset();
