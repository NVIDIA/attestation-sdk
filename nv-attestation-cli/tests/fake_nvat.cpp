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

// In-process fakes for the subset of the nvat C API that the verify-token path
// calls. The CLI test binary links no real libnvat, so these definitions
// satisfy the linker and let verify_token.cpp be exercised in-process with
// controllable return values (see fake_nvat_control.h).

#include <string>

#include "nvat.h"
#include "fake_nvat_control.h"

namespace {

// Minimal base64url (no padding) encoder, used to wrap the fake's configured
// JSON payload into a JWT shape (header.payload.signature) for out_result_jwt.
std::string base64url_encode(const std::string& in) {
    static const char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    int buf = 0;
    int bits = 0;
    for (unsigned char ch : in) {
        buf = (buf << 8) | ch;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(kAlphabet[(buf >> bits) & 0x3F]);
        }
    }
    if (bits > 0) {
        out.push_back(kAlphabet[(buf << (6 - bits)) & 0x3F]);
    }
    return out;
}

// Wraps a JSON payload string into an unsigned-looking compact JWT
// (header.payload.signature). The header/signature segments are not real
// JWT structures; this fake never verifies them.
std::string wrap_as_fake_jwt(const std::string& payload_json) {
    return base64url_encode(R"({"alg":"none"})") + "." +
           base64url_encode(payload_json) + "." + "fakesig";
}

} // namespace

// Concrete stand-ins for the opaque SDK handle types. verify_token.cpp only
// passes these around as opaque pointers; only nvat_str_st needs real state, so
// nvat_str_get_data can hand back a char*.
struct nvat_sdk_opts_st { int unused; };
struct nvat_logger_st { int unused; };
struct nvat_http_options_st { int unused; };
struct nvat_jwt_validation_options_st { uint64_t clock_skew_leeway_seconds = 60; };
struct nvat_nonce_st { int unused; };
struct nvat_claims_collection_st { int unused; };
struct nvat_relying_party_policy_st { int unused; };
struct nvat_str_st {
    std::string data;
    bool tracked_sdk_handle = false;
};
struct nvat_attestation_ctx_st { int unused; };
struct nvat_evidence_policy_st { int unused; };
struct nvat_rim_store_st { int unused; };
struct nvat_ocsp_client_st { int unused; };
struct nvat_ocsp_client_options_st {
    nvat_ocsp_cert_id_hash_algorithm_t algorithm =
        NVAT_OCSP_CERT_ID_HASH_SHA256;
};
struct nvat_gpu_evidence_source_st { int unused; };
struct nvat_switch_evidence_source_st { int unused; };
struct nvat_gpu_evidence_st { int unused; };
struct nvat_cmw_collection_st { int unused; };
struct nvat_corim_store_st { int unused; };
struct nvat_local_corim_verifier_st { int unused; };
struct nvat_detached_eat_options_st { int unused; };

FakeNvatControl g_fake_nvat;
void fake_nvat_reset() { g_fake_nvat = FakeNvatControl{}; }

extern "C" {

// --- SDK init / options / logger ---
nvat_rc_t nvat_sdk_opts_create(nvat_sdk_opts_t* out_opts) {
    *out_opts = new nvat_sdk_opts_st{};
    return NVAT_RC_OK;
}
void nvat_sdk_opts_set_logger(nvat_sdk_opts_t /*opts*/, nvat_logger_t /*logger*/) {}
void nvat_sdk_opts_free(nvat_sdk_opts_t* sdk_opts) {
    if (sdk_opts != nullptr && *sdk_opts != nullptr) { delete *sdk_opts; *sdk_opts = nullptr; }
}
nvat_rc_t nvat_sdk_init(nvat_sdk_opts_t /*opts*/) { return g_fake_nvat.sdk_init_rc; }
void nvat_sdk_shutdown(void) {
    ++g_fake_nvat.sdk_shutdown_calls;
    if (g_fake_nvat.tracked_sdk_handles != 0) {
        g_fake_nvat.sdk_shutdown_with_live_handles = true;
    }
}

nvat_rc_t nvat_logger_callback_create(nvat_logger_t* out_logger, nvat_log_callback_t /*log_cb*/,
                                      nvat_should_log_callback_t /*should_log_cb*/,
                                      nvat_flush_callback_t /*flush_cb*/, void* /*user_data*/) {
    *out_logger = new nvat_logger_st{};
    return NVAT_RC_OK;
}
void nvat_logger_free(nvat_logger_t* logger) {
    if (logger != nullptr && *logger != nullptr) { delete *logger; *logger = nullptr; }
}

// --- HTTP options ---
nvat_rc_t nvat_http_options_create_default(nvat_http_options_t* http_options) {
    if (g_fake_nvat.http_options_rc != NVAT_RC_OK) { return g_fake_nvat.http_options_rc; }
    *http_options = new nvat_http_options_st{};
    ++g_fake_nvat.tracked_sdk_handles;
    return NVAT_RC_OK;
}
void nvat_http_options_set_tls_ca_cert(nvat_http_options_t /*http_options*/, const char* /*cert*/) {}
void nvat_http_options_set_tls_ca_path(nvat_http_options_t /*http_options*/, const char* /*path*/) {}
void nvat_http_options_free(nvat_http_options_t* http_options) {
    if (http_options != nullptr && *http_options != nullptr) {
        delete *http_options;
        *http_options = nullptr;
        --g_fake_nvat.tracked_sdk_handles;
    }
}

// --- Nonce ---
nvat_rc_t nvat_nonce_from_hex(nvat_nonce_t* out_nonce, const char* /*hex*/) {
    if (g_fake_nvat.nonce_rc != NVAT_RC_OK) { return g_fake_nvat.nonce_rc; }
    *out_nonce = new nvat_nonce_st{};
    ++g_fake_nvat.tracked_sdk_handles;
    return NVAT_RC_OK;
}
void nvat_nonce_free(nvat_nonce_t* nonce) {
    if (nonce != nullptr && *nonce != nullptr) {
        delete *nonce;
        *nonce = nullptr;
        --g_fake_nvat.tracked_sdk_handles;
    }
}

// --- Verify ---
nvat_rc_t nvat_verify_attestation_result(const char* /*eat*/, const char* /*nras_base_url*/,
                                         const char* /*service_key*/, nvat_nonce_t /*expected_nonce*/,
                                         nvat_http_options_t /*http_options*/,
                                         nvat_jwt_validation_options_t /*jwt_validation_options*/,
                                         nvat_claims_collection_t* out_claims) {
    ++g_fake_nvat.legacy_verify_calls;
    // OK and OVERALL_RESULT_FALSE both yield populated claims, matching the real API.
    if (g_fake_nvat.verify_rc == NVAT_RC_OK || g_fake_nvat.verify_rc == NVAT_RC_OVERALL_RESULT_FALSE) {
        *out_claims = new nvat_claims_collection_st{};
        ++g_fake_nvat.tracked_sdk_handles;
    }
    return g_fake_nvat.verify_rc;
}

nvat_rc_t nvat_jwt_validation_options_create_default(
    nvat_jwt_validation_options_t* out_options) {
    *out_options = new nvat_jwt_validation_options_st{};
    ++g_fake_nvat.tracked_sdk_handles;
    return NVAT_RC_OK;
}
void nvat_jwt_validation_options_set_clock_skew_leeway_seconds(
    nvat_jwt_validation_options_t options, uint64_t seconds) {
    if (options != nullptr) {
        options->clock_skew_leeway_seconds = seconds;
    }
}
void nvat_jwt_validation_options_free(nvat_jwt_validation_options_t* options) {
    if (options != nullptr && *options != nullptr) {
        delete *options;
        *options = nullptr;
        --g_fake_nvat.tracked_sdk_handles;
    }
}

nvat_rc_t nvat_verify_ear(
    const char* ear_jwt, const char* verifier_base_url, const char* service_key,
    nvat_nonce_t expected_nonce, nvat_http_options_t http_options,
    nvat_jwt_validation_options_t jwt_validation_options, nvat_str_t* out_ear_json) {
    ++g_fake_nvat.ear_verify_calls;
    g_fake_nvat.verify_ear_jwt = ear_jwt == nullptr ? "" : ear_jwt;
    g_fake_nvat.verify_ear_base_url =
        verifier_base_url == nullptr ? "" : verifier_base_url;
    g_fake_nvat.verify_ear_service_key = service_key == nullptr ? "" : service_key;
    g_fake_nvat.verify_ear_nonce_present = expected_nonce != nullptr;
    g_fake_nvat.verify_ear_http_options_present = http_options != nullptr;
    g_fake_nvat.verify_ear_jwt_options_present = jwt_validation_options != nullptr;
    if (jwt_validation_options != nullptr) {
        g_fake_nvat.verify_ear_clock_skew_leeway_seconds =
            jwt_validation_options->clock_skew_leeway_seconds;
    }
    if (out_ear_json != nullptr) {
        *out_ear_json = nullptr;
    }
    if (g_fake_nvat.verify_ear_rc == NVAT_RC_OK && out_ear_json != nullptr) {
        *out_ear_json = new nvat_str_st{g_fake_nvat.verified_ear_json, true};
        ++g_fake_nvat.tracked_sdk_handles;
    }
    return g_fake_nvat.verify_ear_rc;
}
void nvat_claims_collection_free(nvat_claims_collection_t* claims_collection) {
    if (claims_collection != nullptr && *claims_collection != nullptr) {
        delete *claims_collection; *claims_collection = nullptr;
        --g_fake_nvat.tracked_sdk_handles;
    }
}

// --- Relying-party policy ---
nvat_rc_t nvat_relying_party_policy_create_rego_from_str(nvat_relying_party_policy_t* rp_policy,
                                                         const char* /*rego*/) {
    if (g_fake_nvat.policy_create_rc != NVAT_RC_OK) { return g_fake_nvat.policy_create_rc; }
    *rp_policy = new nvat_relying_party_policy_st{};
    ++g_fake_nvat.tracked_sdk_handles;
    return NVAT_RC_OK;
}
nvat_rc_t nvat_apply_relying_party_policy(nvat_relying_party_policy_t /*policy*/,
                                          const nvat_claims_collection_t /*claims*/) {
    return g_fake_nvat.policy_apply_rc;
}
nvat_rc_t nvat_apply_relying_party_policy_to_ear(
    nvat_relying_party_policy_t /*policy*/, const char* ear_json) {
    g_fake_nvat.policy_apply_ear_input = ear_json == nullptr ? "" : ear_json;
    return g_fake_nvat.policy_apply_ear_rc;
}
void nvat_relying_party_policy_free(nvat_relying_party_policy_t* relying_party_policy) {
    if (relying_party_policy != nullptr && *relying_party_policy != nullptr) {
        delete *relying_party_policy; *relying_party_policy = nullptr;
        --g_fake_nvat.tracked_sdk_handles;
    }
}

// --- Claims serialization ---
nvat_rc_t nvat_claims_collection_serialize_json(const nvat_claims_collection_t /*claims*/,
                                                nvat_str_t* out_serialized_claims) {
    if (g_fake_nvat.serialize_rc != NVAT_RC_OK) { return g_fake_nvat.serialize_rc; }
    *out_serialized_claims = new nvat_str_st{g_fake_nvat.claims_json};
    return NVAT_RC_OK;
}
nvat_rc_t nvat_str_get_data(const nvat_str_t str, char** out_data) {
    if (g_fake_nvat.str_get_data_rc != NVAT_RC_OK) { return g_fake_nvat.str_get_data_rc; }
    *out_data = const_cast<char*>(str->data.c_str());
    return NVAT_RC_OK;
}
void nvat_str_free(nvat_str_t* str) {
    if (str != nullptr && *str != nullptr) {
        const bool tracked_sdk_handle = (*str)->tracked_sdk_handle;
        delete *str;
        *str = nullptr;
        if (tracked_sdk_handle) {
            --g_fake_nvat.tracked_sdk_handles;
        }
    }
}

const char* nvat_rc_to_string(nvat_rc_t /*rc*/) { return "FakeRc"; }

// --- attest: attestation context ---
nvat_rc_t nvat_attestation_ctx_create(nvat_attestation_ctx_t* ctx) {
    if (g_fake_nvat.ctx_create_rc != NVAT_RC_OK) { return g_fake_nvat.ctx_create_rc; }
    *ctx = new nvat_attestation_ctx_st{};
    return NVAT_RC_OK;
}
void nvat_attestation_ctx_free(nvat_attestation_ctx_t* ctx) {
    if (ctx != nullptr && *ctx != nullptr) { delete *ctx; *ctx = nullptr; }
}
nvat_rc_t nvat_attestation_ctx_set_device_type(nvat_attestation_ctx_t, nvat_devices_t) { return NVAT_RC_OK; }
nvat_rc_t nvat_attestation_ctx_set_verifier_type(nvat_attestation_ctx_t, nvat_verifier_type_t) { return NVAT_RC_OK; }
nvat_rc_t nvat_attestation_ctx_set_service_key(nvat_attestation_ctx_t, const char*) { return NVAT_RC_OK; }
nvat_rc_t nvat_attestation_ctx_set_gpu_evidence_source_json_file(nvat_attestation_ctx_t, const char*) { return NVAT_RC_OK; }
nvat_rc_t nvat_attestation_ctx_set_switch_evidence_source_json_file(nvat_attestation_ctx_t, const char*) { return NVAT_RC_OK; }
nvat_rc_t nvat_attestation_ctx_set_default_rim_store(nvat_attestation_ctx_t, nvat_rim_store_t) { return NVAT_RC_OK; }
nvat_rc_t nvat_attestation_ctx_set_default_ocsp_client(nvat_attestation_ctx_t, nvat_ocsp_client_t) { return NVAT_RC_OK; }
nvat_rc_t nvat_attestation_ctx_set_relying_party_policy(nvat_attestation_ctx_t, nvat_relying_party_policy_t) { return NVAT_RC_OK; }
// Takes ownership of the evidence policy on success (matches the real API), so
// free it here and null the caller's handle to avoid a double free.
nvat_rc_t nvat_attestation_ctx_set_evidence_policy(nvat_attestation_ctx_t, nvat_evidence_policy_t* policy) {
    if (policy != nullptr && *policy != nullptr) { delete *policy; *policy = nullptr; }
    return NVAT_RC_OK;
}

// --- attest: evidence policy ---
nvat_rc_t nvat_evidence_policy_create_default(nvat_evidence_policy_t* policy) {
    if (g_fake_nvat.evidence_policy_create_rc != NVAT_RC_OK) { return g_fake_nvat.evidence_policy_create_rc; }
    *policy = new nvat_evidence_policy_st{};
    return NVAT_RC_OK;
}
void nvat_evidence_policy_set_verify_rim_signature(nvat_evidence_policy_t, bool) {}
void nvat_evidence_policy_set_verify_rim_cert_chain(nvat_evidence_policy_t, bool) {}
void nvat_evidence_policy_free(nvat_evidence_policy_t* policy) {
    if (policy != nullptr && *policy != nullptr) { delete *policy; *policy = nullptr; }
}

// --- attest: RIM store / OCSP client ---
nvat_rc_t nvat_rim_store_create_remote(nvat_rim_store_t* out_store, const char*, const char*,
                                       const nvat_http_options_t) {
    if (g_fake_nvat.rim_store_create_rc != NVAT_RC_OK) { return g_fake_nvat.rim_store_create_rc; }
    *out_store = new nvat_rim_store_st{};
    return NVAT_RC_OK;
}
nvat_rc_t nvat_rim_store_create_filesystem(nvat_rim_store_t* out_store, const char*) {
    if (g_fake_nvat.rim_store_create_rc != NVAT_RC_OK) { return g_fake_nvat.rim_store_create_rc; }
    *out_store = new nvat_rim_store_st{};
    return NVAT_RC_OK;
}
void nvat_rim_store_free(nvat_rim_store_t* rim_store) {
    if (rim_store != nullptr && *rim_store != nullptr) { delete *rim_store; *rim_store = nullptr; }
}
nvat_rc_t nvat_ocsp_client_create_default(nvat_ocsp_client_t* out_client, const char*, const char*,
                                          const nvat_http_options_t) {
    ++g_fake_nvat.ocsp_default_create_calls;
    if (g_fake_nvat.ocsp_create_rc != NVAT_RC_OK) { return g_fake_nvat.ocsp_create_rc; }
    *out_client = new nvat_ocsp_client_st{};
    return NVAT_RC_OK;
}
nvat_rc_t nvat_ocsp_client_options_create_default(
    nvat_ocsp_client_options_t* out_options) {
    ++g_fake_nvat.ocsp_options_create_calls;
    if (g_fake_nvat.ocsp_options_create_rc != NVAT_RC_OK) {
        return g_fake_nvat.ocsp_options_create_rc;
    }
    *out_options = new nvat_ocsp_client_options_st{};
    return NVAT_RC_OK;
}
nvat_rc_t nvat_ocsp_cert_id_hash_algorithm_from_name(
    const char* name, nvat_ocsp_cert_id_hash_algorithm_t* out_algorithm) {
    if (name == nullptr || out_algorithm == nullptr) return NVAT_RC_BAD_ARGUMENT;
    const std::string value(name);
    if (value == "sha-1") *out_algorithm = NVAT_OCSP_CERT_ID_HASH_SHA1;
    else if (value == "sha-256") *out_algorithm = NVAT_OCSP_CERT_ID_HASH_SHA256;
    else if (value == "sha-384") *out_algorithm = NVAT_OCSP_CERT_ID_HASH_SHA384;
    else return NVAT_RC_BAD_ARGUMENT;
    return NVAT_RC_OK;
}
nvat_rc_t nvat_ocsp_client_options_set_cert_id_hash_algorithm(
    nvat_ocsp_client_options_t options,
    nvat_ocsp_cert_id_hash_algorithm_t algorithm) {
    if (g_fake_nvat.ocsp_options_set_rc != NVAT_RC_OK) {
        return g_fake_nvat.ocsp_options_set_rc;
    }
    options->algorithm = algorithm;
    return NVAT_RC_OK;
}
void nvat_ocsp_client_options_free(nvat_ocsp_client_options_t* options) {
    if (options != nullptr && *options != nullptr) {
        delete *options;
        *options = nullptr;
        ++g_fake_nvat.ocsp_options_free_calls;
    }
}
nvat_rc_t nvat_ocsp_client_create_default_with_options(
    nvat_ocsp_client_t* out_client, const char*, const char*,
    const nvat_http_options_t, const nvat_ocsp_client_options_t options) {
    ++g_fake_nvat.ocsp_default_with_options_create_calls;
    if (options != nullptr) {
        g_fake_nvat.last_ocsp_cert_id_hash = options->algorithm;
    }
    if (g_fake_nvat.ocsp_create_rc != NVAT_RC_OK) {
        return g_fake_nvat.ocsp_create_rc;
    }
    *out_client = new nvat_ocsp_client_st{};
    return NVAT_RC_OK;
}
void nvat_ocsp_client_free(nvat_ocsp_client_t* ocsp_client) {
    if (ocsp_client != nullptr && *ocsp_client != nullptr) { delete *ocsp_client; *ocsp_client = nullptr; }
}

// --- attest: the attestation call ---
nvat_rc_t nvat_attest_device(const nvat_attestation_ctx_t, const nvat_nonce_t,
                             nvat_str_t* out_detached_eat, nvat_claims_collection_t* out_claims) {
    // OK / RP_POLICY_MISMATCH / OVERALL_RESULT_FALSE all yield populated outputs.
    if (g_fake_nvat.attest_rc == NVAT_RC_OK ||
        g_fake_nvat.attest_rc == NVAT_RC_RP_POLICY_MISMATCH ||
        g_fake_nvat.attest_rc == NVAT_RC_OVERALL_RESULT_FALSE) {
        *out_detached_eat = new nvat_str_st{g_fake_nvat.detached_eat_json};
        *out_claims = new nvat_claims_collection_st{};
        ++g_fake_nvat.tracked_sdk_handles;
    }
    return g_fake_nvat.attest_rc;
}

// --- collect-evidence: GPU ---
nvat_rc_t nvat_gpu_evidence_source_nvml_create(nvat_gpu_evidence_source_t* out_source) {
    if (g_fake_nvat.source_create_rc != NVAT_RC_OK) { return g_fake_nvat.source_create_rc; }
    *out_source = new nvat_gpu_evidence_source_st{};
    return NVAT_RC_OK;
}
nvat_rc_t nvat_gpu_evidence_source_corelib_create(nvat_gpu_evidence_source_t* out_source, const char*) {
    if (g_fake_nvat.source_create_rc != NVAT_RC_OK) { return g_fake_nvat.source_create_rc; }
    *out_source = new nvat_gpu_evidence_source_st{};
    return NVAT_RC_OK;
}
nvat_rc_t nvat_gpu_evidence_source_from_json_file(nvat_gpu_evidence_source_t* out_source, const char*) {
    if (g_fake_nvat.source_create_rc != NVAT_RC_OK) { return g_fake_nvat.source_create_rc; }
    *out_source = new nvat_gpu_evidence_source_st{};
    return NVAT_RC_OK;
}
void nvat_gpu_evidence_source_free(nvat_gpu_evidence_source_t* source) {
    if (source != nullptr && *source != nullptr) { delete *source; *source = nullptr; }
}
// Collect yields an empty array (the CLI only serializes + prints it); the empty
// array also means the wrapper's deleter never dereferences a fake evidence.
nvat_rc_t nvat_gpu_evidence_collect(const nvat_gpu_evidence_source_t, const nvat_nonce_t,
                                    nvat_gpu_evidence_t** out_array, size_t* out_num) {
    if (g_fake_nvat.collect_rc != NVAT_RC_OK) { return g_fake_nvat.collect_rc; }
    *out_array = nullptr;
    *out_num = 0;
    return NVAT_RC_OK;
}
nvat_rc_t nvat_gpu_evidence_serialize_json(const nvat_gpu_evidence_t*, size_t, nvat_str_t* out) {
    if (g_fake_nvat.serialize_rc != NVAT_RC_OK) { return g_fake_nvat.serialize_rc; }
    *out = new nvat_str_st{g_fake_nvat.evidences_json};
    return NVAT_RC_OK;
}
void nvat_gpu_evidence_array_free(nvat_gpu_evidence_t**, size_t) {}

// --- collect-evidence: NVSwitch ---
nvat_rc_t nvat_switch_evidence_source_nscq_create(nvat_switch_evidence_source_t* out_source) {
    if (g_fake_nvat.source_create_rc != NVAT_RC_OK) { return g_fake_nvat.source_create_rc; }
    *out_source = new nvat_switch_evidence_source_st{};
    return NVAT_RC_OK;
}
nvat_rc_t nvat_switch_evidence_source_from_json_file(nvat_switch_evidence_source_t* out_source, const char*) {
    if (g_fake_nvat.source_create_rc != NVAT_RC_OK) { return g_fake_nvat.source_create_rc; }
    *out_source = new nvat_switch_evidence_source_st{};
    return NVAT_RC_OK;
}
void nvat_switch_evidence_source_free(nvat_switch_evidence_source_t* source) {
    if (source != nullptr && *source != nullptr) { delete *source; *source = nullptr; }
}
nvat_rc_t nvat_switch_evidence_collect(const nvat_switch_evidence_source_t, const nvat_nonce_t,
                                       nvat_switch_evidence_t** out_array, size_t* out_num) {
    if (g_fake_nvat.collect_rc != NVAT_RC_OK) { return g_fake_nvat.collect_rc; }
    *out_array = nullptr;
    *out_num = 0;
    return NVAT_RC_OK;
}
nvat_rc_t nvat_switch_evidence_serialize_json(const nvat_switch_evidence_t*, size_t, nvat_str_t* out) {
    if (g_fake_nvat.serialize_rc != NVAT_RC_OK) { return g_fake_nvat.serialize_rc; }
    *out = new nvat_str_st{g_fake_nvat.evidences_json};
    return NVAT_RC_OK;
}
void nvat_switch_evidence_array_free(nvat_switch_evidence_t**, size_t) {}

// --- CMW collection ---
nvat_rc_t nvat_cmw_collection_create_from_spdm_transcript(nvat_cmw_collection_t* out,
                                                          const char* /*device_label*/,
                                                          const uint8_t* /*transcript*/,
                                                          size_t /*transcript_size*/,
                                                          const uint8_t* /*cert_chain*/,
                                                          size_t /*cert_chain_size*/,
                                                          nvat_nonce_t /*nonce*/) {
    if (g_fake_nvat.cmw_create_rc != NVAT_RC_OK) { return g_fake_nvat.cmw_create_rc; }
    *out = new nvat_cmw_collection_st{};
    return NVAT_RC_OK;
}
nvat_rc_t nvat_cmw_collection_create_from_eat(nvat_cmw_collection_t* out,
                                              const char* /*device_label*/,
                                              const uint8_t* /*signed_cwt*/,
                                              size_t /*signed_cwt_size*/,
                                              nvat_nonce_t /*nonce*/) {
    if (g_fake_nvat.cmw_create_rc != NVAT_RC_OK) { return g_fake_nvat.cmw_create_rc; }
    *out = new nvat_cmw_collection_st{};
    return NVAT_RC_OK;
}
nvat_rc_t nvat_cmw_collection_create_from_gpu_evidence(nvat_cmw_collection_t* out,
                                                       const nvat_gpu_evidence_t* /*array*/,
                                                       size_t /*count*/,
                                                       nvat_nonce_t /*nonce*/) {
    if (g_fake_nvat.cmw_create_rc != NVAT_RC_OK) { return g_fake_nvat.cmw_create_rc; }
    *out = new nvat_cmw_collection_st{};
    return NVAT_RC_OK;
}
nvat_rc_t nvat_cmw_collection_serialize(const nvat_cmw_collection_t /*cmw*/,
                                        nvat_cmw_format_t /*format*/,
                                        nvat_str_t* out_str) {
    if (g_fake_nvat.cmw_serialize_rc != NVAT_RC_OK) { return g_fake_nvat.cmw_serialize_rc; }
    *out_str = new nvat_str_st{g_fake_nvat.cmw_json};
    return NVAT_RC_OK;
}
void nvat_cmw_collection_free(nvat_cmw_collection_t* cmw) {
    if (cmw && *cmw) { delete *cmw; *cmw = nullptr; }
}

// --- nvat_str_length ---
nvat_rc_t nvat_str_length(const nvat_str_t str, size_t* out_length) {
    if (g_fake_nvat.str_length_rc != NVAT_RC_OK) { return g_fake_nvat.str_length_rc; }
    *out_length = str ? str->data.size() : 0;
    return NVAT_RC_OK;
}

// --- attest-v2: CoRIM store / local verifier ---
nvat_rc_t nvat_corim_store_create(nvat_corim_store_t* out_store,
                                  const char* /*service_key*/,
                                  nvat_http_options_t /*http_options*/) {
    if (g_fake_nvat.corim_store_create_rc != NVAT_RC_OK) {
        return g_fake_nvat.corim_store_create_rc;
    }
    *out_store = new nvat_corim_store_st{};
    return NVAT_RC_OK;
}

nvat_rc_t nvat_corim_store_add_url_rewrite(nvat_corim_store_t /*store*/,
                                           const char* /*pattern*/,
                                           const char* /*replacement*/) {
    return NVAT_RC_OK;
}

nvat_rc_t nvat_corim_store_enable_in_memory_cache(nvat_corim_store_t /*store*/,
                                        uint64_t /*max_size_bytes*/,
                                        time_t /*ttl_seconds*/) {
    return g_fake_nvat.corim_store_enable_in_memory_cache_rc;
}

void nvat_corim_store_free(nvat_corim_store_t* store) {
    if (store && *store) { delete *store; *store = nullptr; }
}

nvat_rc_t nvat_local_corim_verifier_create(nvat_local_corim_verifier_t* out_verifier,
                                           nvat_corim_store_t* /*store*/,
                                           nvat_ocsp_client_t /*ocsp*/) {
    if (g_fake_nvat.corim_verifier_create_rc != NVAT_RC_OK) {
        return g_fake_nvat.corim_verifier_create_rc;
    }
    *out_verifier = new nvat_local_corim_verifier_st{};
    return NVAT_RC_OK;
}

nvat_rc_t nvat_local_corim_verifier_set_verify_rim_signature(
    nvat_local_corim_verifier_t /*verifier*/, bool /*enabled*/) {
    return NVAT_RC_OK;
}

nvat_rc_t nvat_local_corim_verifier_set_verify_coev_signature(
    nvat_local_corim_verifier_t /*verifier*/, bool /*enabled*/) {
    return NVAT_RC_OK;
}

nvat_rc_t nvat_local_corim_verifier_set_verify_evidence_signature(
    nvat_local_corim_verifier_t /*verifier*/, bool /*enabled*/) {
    return NVAT_RC_OK;
}

nvat_rc_t nvat_local_corim_verifier_set_verify_revocation(
    nvat_local_corim_verifier_t /*verifier*/, bool /*enabled*/) {
    return NVAT_RC_OK;
}

nvat_rc_t nvat_local_corim_verifier_set_backup_spdm_coev(
    nvat_local_corim_verifier_t /*verifier*/, const uint8_t* /*data*/,
    size_t /*len*/) {
    return NVAT_RC_OK;
}

nvat_rc_t nvat_local_corim_verifier_add_backup_rim_locator(
    nvat_local_corim_verifier_t /*verifier*/, const char* /*uri*/) {
    return NVAT_RC_OK;
}

nvat_rc_t nvat_detached_eat_options_create(nvat_detached_eat_options_t* out_options,
                                           const char* /*private_key_pem*/,
                                           const char* /*issuer*/,
                                           const char* /*kid*/) {
    if (g_fake_nvat.detached_eat_options_create_rc != NVAT_RC_OK) {
        return g_fake_nvat.detached_eat_options_create_rc;
    }
    *out_options = new nvat_detached_eat_options_st{};
    return NVAT_RC_OK;
}

void nvat_detached_eat_options_free(nvat_detached_eat_options_t* options) {
    if (options && *options) { delete *options; *options = nullptr; }
}

// Both result strings are handed back only on success, matching the real API
// (nvat.cpp only sets its outputs on success). out_result_jwt is wrapped as a
// compact JWT; out_result_json is the same payload as plain JSON.
nvat_rc_t nvat_local_corim_verifier_verify_cmw(
    const nvat_local_corim_verifier_t /*verifier*/, const uint8_t* /*cmw_data*/,
    size_t /*cmw_len*/, nvat_cmw_format_t /*format*/,
    nvat_detached_eat_options_t /*ear_signing_options*/,
    nvat_str_t* out_result_jwt, nvat_str_t* out_result_json) {
    if (g_fake_nvat.verify_cmw_rc == NVAT_RC_OK &&
        !g_fake_nvat.verify_cmw_result_json.empty()) {
        if (out_result_jwt != nullptr) {
            *out_result_jwt = new nvat_str_st{wrap_as_fake_jwt(g_fake_nvat.verify_cmw_result_json)};
        }
        if (out_result_json != nullptr) {
            *out_result_json = new nvat_str_st{g_fake_nvat.verify_cmw_result_json};
        }
    }
    return g_fake_nvat.verify_cmw_rc;
}

void nvat_local_corim_verifier_free(nvat_local_corim_verifier_t* verifier) {
    if (verifier && *verifier) { delete *verifier; *verifier = nullptr; }
}

nvat_rc_t nvat_nonce_create(nvat_nonce_t* out_nonce, size_t /*size*/) {
    if (g_fake_nvat.nonce_rc != NVAT_RC_OK) { return g_fake_nvat.nonce_rc; }
    *out_nonce = new nvat_nonce_st{};
    ++g_fake_nvat.tracked_sdk_handles;
    return NVAT_RC_OK;
}

nvat_rc_t nvat_ocsp_client_create_aia(nvat_ocsp_client_t* out_client,
                                      const char* /*base_url*/,
                                      const char* /*service_key*/,
                                      const nvat_http_options_t /*http_options*/,
                                      const char* const* /*rewrite_patterns*/,
                                      const char* const* /*rewrite_replacements*/,
                                      size_t /*num_rewrites*/,
                                      const nvat_ocsp_client_options_t options) {
    ++g_fake_nvat.ocsp_aia_create_calls;
    if (options != nullptr) {
        g_fake_nvat.last_ocsp_cert_id_hash = options->algorithm;
    }
    if (g_fake_nvat.ocsp_create_rc != NVAT_RC_OK) {
        return g_fake_nvat.ocsp_create_rc;
    }
    *out_client = new nvat_ocsp_client_st{};
    return NVAT_RC_OK;
}

nvat_rc_t nvat_ocsp_client_create_cached(nvat_ocsp_client_t* out_client,
                                         const nvat_ocsp_client_t /*inner_client*/,
                                         uint64_t /*max_size_bytes*/,
                                         time_t /*ttl_seconds*/) {
    ++g_fake_nvat.ocsp_cached_create_calls;
    if (g_fake_nvat.ocsp_create_cached_rc != NVAT_RC_OK) {
        return g_fake_nvat.ocsp_create_cached_rc;
    }
    *out_client = new nvat_ocsp_client_st{};
    return NVAT_RC_OK;
}

} // extern "C"
