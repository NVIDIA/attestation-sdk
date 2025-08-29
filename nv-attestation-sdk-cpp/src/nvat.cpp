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

#include <cstdint>
#include <cstdlib>   // for std::getenv
#include <memory>
#include <string>
#include <vector>

#include "nv_attestation/attestation.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/claims_evaluator.h"
#include "nv_attestation/gpu/claims.h"
#include "nv_attestation/gpu/verify.h"
#include "nv_attestation/nv_http.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/nvat_private.hpp"
#include "nvat.h"

#include "nv_attestation/init.h"
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/switch/verify.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/gpu/evidence.h"
#include "nv_attestation/switch/evidence.h"
#include "nvat.h.in"

using namespace nvattestation;

extern "C" {

// === Free Functions ===

NVAT_FREE_FUNCTION(logger, ILogger);
NVAT_FREE_FUNCTION(nonce, std::vector<uint8_t>);
NVAT_FREE_FUNCTION(gpu_evidence, GpuEvidence);
NVAT_FREE_FUNCTION(gpu_evidence_source, std::shared_ptr<IGpuEvidenceSource>);
NVAT_FREE_FUNCTION(gpu_evidence_collection, std::vector<GpuEvidence>);
NVAT_FREE_FUNCTION(switch_evidence, SwitchEvidence);
NVAT_FREE_FUNCTION(switch_evidence_source, std::shared_ptr<ISwitchEvidenceSource>);
NVAT_FREE_FUNCTION(switch_evidence_collection, std::vector<SwitchEvidence>);
NVAT_FREE_FUNCTION(evidence_policy, EvidencePolicy);
NVAT_FREE_FUNCTION(relying_party_policy, std::shared_ptr<IClaimsEvaluator>);
NVAT_FREE_FUNCTION(http_options, HttpOptions);
NVAT_FREE_FUNCTION(ocsp_client, std::shared_ptr<IOcspHttpClient>);
NVAT_FREE_FUNCTION(rim_store, std::shared_ptr<IRimStore>);
NVAT_FREE_FUNCTION(claims, Claims);
NVAT_FREE_FUNCTION(claims_collection, ClaimsCollection);
NVAT_FREE_FUNCTION(attestation_ctx, AttestationContext);
NVAT_FREE_FUNCTION(gpu_verifier, IGpuVerifier);
NVAT_FREE_FUNCTION(gpu_local_verifier, LocalGpuVerifier);
NVAT_FREE_FUNCTION(gpu_nras_verifier, NvRemoteGpuVerifier);
NVAT_FREE_FUNCTION(switch_verifier, ISwitchVerifier);
NVAT_FREE_FUNCTION(switch_local_verifier, LocalSwitchVerifier);
NVAT_FREE_FUNCTION(switch_nras_verifier, NvRemoteSwitchVerifier);
NVAT_FREE_FUNCTION(str, std::string);

// === Core SDK ===

const char* nvat_rc_to_string(nvat_rc_t rc) {
    return to_string(nvat_rc_to_cpp(rc));
}

nvat_rc_t nvat_str_length(const nvat_str_t str, size_t* out_length) {
    NVAT_C_API_BEGIN
    if (str == nullptr) {
        return NVAT_RC_BAD_ARGUMENT;
    }
    std::string* cpp_str = nvat_str_to_cpp(str);
    *out_length = cpp_str->length();
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_str_get_data(const nvat_str_t str, char** out_data) {
    NVAT_C_API_BEGIN
    if (str == nullptr) {
        return NVAT_RC_BAD_ARGUMENT;
    }
    std::string* cpp_str = nvat_str_to_cpp(str);
    *out_data = const_cast<char*>(cpp_str->c_str());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_sdk_opts_create(nvat_sdk_opts_t* out_opts) {
    NVAT_C_API_BEGIN
    if (out_opts == nullptr) {
        // cannot log
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto cpp_opts = std::make_unique<SdkOptions>();
    *out_opts = nvat_sdk_opts_from_cpp(cpp_opts.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

void nvat_sdk_opts_free(nvat_sdk_opts_t* opts) {
    NVAT_C_API_BEGIN
    if (opts == nullptr || *opts == nullptr) {
        return;
    }
    SdkOptions* cpp_opts = nvat_sdk_opts_to_cpp(*opts);
    delete cpp_opts;
    *opts = nullptr;
    NVAT_C_API_END_VOID
}

void nvat_sdk_opts_set_logger(nvat_sdk_opts_t opts, nvat_logger_t* logger) {
    NVAT_C_API_BEGIN
    if (opts == nullptr || logger == nullptr || *logger == nullptr) {
        return;
    }
    SdkOptions* cpp_opts = nvat_sdk_opts_to_cpp(opts);
    ILogger* cpp_logger = nvat_logger_to_cpp(*logger);
    cpp_opts->logger = shared_ptr<ILogger>(cpp_logger);
    *logger = nullptr;
    NVAT_C_API_END_VOID
}

void nvat_sdk_opts_set_enabled_device_drivers(nvat_sdk_opts_t opts, const nvat_devices_t drivers) {
    NVAT_C_API_BEGIN
    if (opts == nullptr) {
        return;
    }
    SdkOptions* cpp_opts = nvat_sdk_opts_to_cpp(opts);
    cpp_opts->nvml_enabled = NVAT_DEVICE_IS_SET(drivers, NVAT_DEVICE_GPU);
    cpp_opts->nscq_enabled = NVAT_DEVICE_IS_SET(drivers, NVAT_DEVICE_NVSWITCH);
    NVAT_C_API_END_VOID
}

nvat_rc_t nvat_sdk_init(nvat_sdk_opts_t* opts) {
    NVAT_C_API_BEGIN
    nvat_sdk_opts_t opts_val = nullptr;
    if (opts != nullptr) { // deref C ptr if valid
        opts_val = *opts;
    }
    if (opts_val == nullptr) { // create default opts
        nvat_rc_t err = nvat_sdk_opts_create(&opts_val);
        if (err != NVAT_RC_OK) {
            return err;
        }
    }
    SdkOptions* cpp_opts = nvat_sdk_opts_to_cpp(opts_val);
    Error err = init(cpp_opts);
    if (err != Error::Ok) {
        return nvat_rc_from_cpp(err);
    }
    if (opts != nullptr) { // clear C ptr
        *opts = nullptr;
    }
    LOG_DEBUG("Successfully initialized NVIDIA Attestation SDK v" << NVAT_VERSION_STRING);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

void nvat_sdk_shutdown() {
    NVAT_C_API_BEGIN
    shutdown();
    NVAT_C_API_END_VOID
}

nvat_rc_t nvat_logger_spdlog_create(nvat_logger_t* out_logger, const char* c_name, nvat_log_level_t c_level) {
    NVAT_C_API_BEGIN
    if (out_logger == nullptr) {
        // cannot log
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (c_name == nullptr) {
        // cannot log
        return NVAT_RC_BAD_ARGUMENT;
    }
    std::string name = c_name;
    auto level = log_level_from_c(c_level);
    
    auto cpp_logger = make_unique<SpdLogLogger>(name, level);
    *out_logger = nvat_logger_from_cpp(cpp_logger.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_logger_callback_create(
    nvat_logger_t* out_logger,
    nvat_log_callback_t log_callback,
    nvat_should_log_callback_t should_log_callback,
    nvat_flush_callback_t flush_callback,
    void* user_data
) {
    NVAT_C_API_BEGIN
    if (out_logger == nullptr) {
        // cannot log
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto cpp_logger = make_unique<CallbackLogger>(
        should_log_callback,
        log_callback,
        flush_callback,
        user_data
    );
    *out_logger = nvat_logger_from_cpp(cpp_logger.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_http_options_create_default(nvat_http_options_t* http_options) {
    NVAT_C_API_BEGIN
    if (http_options == nullptr) {
        LOG_ERROR("http_options is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto cpp_options = make_unique<HttpOptions>();
    *http_options = nvat_http_options_from_cpp(cpp_options.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

void nvat_http_options_set_max_retry_count(nvat_http_options_t http_options, long max_retries) {
    NVAT_C_API_BEGIN
    if (http_options == nullptr) {
        return;
    }
    auto* cpp_options = nvat_http_options_to_cpp(http_options);
    cpp_options->set_max_retry_count(max_retries);
    NVAT_C_API_END_VOID
}

void nvat_http_options_set_base_backoff_ms(nvat_http_options_t http_options, long base_backoff_ms) {
    NVAT_C_API_BEGIN
    if (http_options == nullptr) {
        return;
    }
    auto* cpp_options = nvat_http_options_to_cpp(http_options);
    cpp_options->set_base_backoff_ms(base_backoff_ms);
    NVAT_C_API_END_VOID
}

void nvat_http_options_set_max_backoff_ms(nvat_http_options_t http_options, long max_backoff_ms) {
    NVAT_C_API_BEGIN
    if (http_options == nullptr) {
        return;
    }
    auto* cpp_options = nvat_http_options_to_cpp(http_options);
    cpp_options->set_max_backoff_ms(max_backoff_ms);
    NVAT_C_API_END_VOID
}

void nvat_http_options_set_connection_timeout_ms(nvat_http_options_t http_options, long connection_timeout_ms) {
    NVAT_C_API_BEGIN
    if (http_options == nullptr) {
        return;
    }
    auto* cpp_options = nvat_http_options_to_cpp(http_options);
    cpp_options->set_connection_timeout_ms(connection_timeout_ms);
    NVAT_C_API_END_VOID
}

void nvat_http_options_set_request_timeout_ms(nvat_http_options_t http_options, long request_timeout_ms) {
    NVAT_C_API_BEGIN
    if (http_options == nullptr) {
        return;
    }
    auto* cpp_options = nvat_http_options_to_cpp(http_options);
    cpp_options->set_request_timeout_ms(request_timeout_ms);
    NVAT_C_API_END_VOID
}

// === Attestation ===

nvat_rc_t nvat_relying_party_policy_create_default(nvat_relying_party_policy_t* rp_policy) {
    NVAT_C_API_BEGIN
    if (rp_policy == nullptr) {
        LOG_ERROR("rp_policy is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto cpp_rp_policy = make_unique<shared_ptr<IClaimsEvaluator>>(ClaimsEvaluatorFactory::create_default_claims_evaluator());
    *rp_policy = nvat_relying_party_policy_from_cpp(cpp_rp_policy.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_relying_party_policy_create_rego_from_str(nvat_relying_party_policy_t* rp_policy, const char* rego_str) {
    NVAT_C_API_BEGIN
    if (rego_str == nullptr) {
        LOG_ERROR("rego_str is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    std::string cpp_string = std::string(rego_str);
    auto cpp_rp_policy = make_unique<shared_ptr<IClaimsEvaluator>>(ClaimsEvaluatorFactory::create_rego_claims_evaluator(cpp_string));
    *rp_policy = nvat_relying_party_policy_from_cpp(cpp_rp_policy.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_apply_relying_party_policy(nvat_relying_party_policy_t policy, const nvat_claims_collection_t claims) {
    NVAT_C_API_BEGIN
    if (claims == nullptr) {
        LOG_ERROR("claims is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (policy == nullptr) {
        LOG_ERROR("policy is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_claims = nvat_claims_collection_to_cpp(claims);
    auto* cpp_policy = nvat_relying_party_policy_to_cpp(policy);
    bool cpp_match = false;
    Error err = (*cpp_policy)->evaluate_claims(*cpp_claims, cpp_match);
    if (err != Error::Ok) {
        LOG_ERROR("failed to evaluate claims");
        return nvat_rc_from_cpp(err);
    }
    if (!cpp_match) {
        LOG_ERROR("claims do not match relying party policy");
        return NVAT_RC_RP_POLICY_MISMATCH;
    }
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_ocsp_client_create_default(nvat_ocsp_client_t* out_client, const char* base_url, const nvat_http_options_t http_options) {
    NVAT_C_API_BEGIN
    if (out_client == nullptr) {
        LOG_ERROR("out_client is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    NvHttpOcspClient client;
    HttpOptions cpp_http_options{};
    if (http_options != nullptr) {
        cpp_http_options = *nvat_http_options_to_cpp(http_options);
    }
    Error err = NvHttpOcspClient::init_from_env(client, base_url, cpp_http_options);
    if (err != Error::Ok) {
        LOG_ERROR("failed to create OCSP client");
        return nvat_rc_from_cpp(err);
    }
    
    auto client_ptr = make_unique<shared_ptr<IOcspHttpClient>>(make_shared<NvHttpOcspClient>(std::move(client)));
    *out_client = nvat_ocsp_client_from_cpp(client_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_rim_store_create_remote(nvat_rim_store_t* out_store, const char* base_url, const nvat_http_options_t http_options) {
    NVAT_C_API_BEGIN
    if (out_store == nullptr) {
        LOG_ERROR("out_store is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    HttpOptions cpp_http_options{};
    if (http_options != nullptr) {
        cpp_http_options = *nvat_http_options_to_cpp(http_options);
    }
    auto store = NvRemoteRimStoreImpl{};
    Error err = NvRemoteRimStoreImpl::init_from_env(store, base_url, cpp_http_options);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to create remote RIM store");
        return nvat_rc_from_cpp(err);
    }
    
    auto store_ptr = make_unique<shared_ptr<IRimStore>>(make_shared<NvRemoteRimStoreImpl>(std::move(store)));
    *out_store = nvat_rim_store_from_cpp(store_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_rim_store_create_filesystem(nvat_rim_store_t* out_store, const char* base_path) {
    NVAT_C_API_BEGIN
    if (out_store == nullptr) {
        LOG_ERROR("out_store is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (base_path == nullptr) {
        LOG_ERROR("base_path is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    // TODO: uncomment when we have a filesystem implementation
    // std::string path = base_path;
    // auto store = make_unique<FilesystemRimStoreImpl>(path);
    // *out_store = nvat_rim_store_from_cpp(store.release());
    return NVAT_RC_INTERNAL_ERROR;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_create(nvat_attestation_ctx_t *ctx, nvat_devices_t enabled_devices) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx* cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (enabled_devices == 0) {
        LOG_ERROR("enabled_devices is empty. Must enable at least one device type.");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto ctx_ptr = std::make_unique<AttestationContext>(enabled_devices);
    *ctx = nvat_attestation_ctx_from_cpp(ctx_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_set_verifier_type(nvat_attestation_ctx_t ctx, nvat_verifier_type_t verifier_type) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    VerifierType cpp_verifier_type {};
    Error err = verifier_type_from_c(verifier_type, cpp_verifier_type);
    if (err != Error::Ok) {
        return nvat_rc_from_cpp(err);
    }
    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    cpp_ctx->set_verifier_type(cpp_verifier_type);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_set_evidence_policy(nvat_attestation_ctx_t ctx, nvat_evidence_policy_t* evidence_policy) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    if (evidence_policy == nullptr || *evidence_policy == nullptr) {
        cpp_ctx->set_evidence_policy(EvidencePolicy());
    } else {
        auto* cpp_evidence_policy = nvat_evidence_policy_to_cpp(*evidence_policy);
        cpp_ctx->set_evidence_policy(*cpp_evidence_policy);
    }
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_set_relying_party_policy(nvat_attestation_ctx_t ctx, nvat_relying_party_policy_t rp_policy) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (rp_policy == nullptr) {
        LOG_ERROR("rp_policy cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    auto* cpp_rp_policy = nvat_relying_party_policy_to_cpp(rp_policy);
    cpp_ctx->set_claims_evaluator(*cpp_rp_policy);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_set_default_ocsp_url(nvat_attestation_ctx_t ctx, const char * ocsp_url) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (ocsp_url == nullptr) {
        LOG_ERROR("ocsp_url cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    cpp_ctx->set_default_ocsp_url(ocsp_url);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_set_default_nras_url(nvat_attestation_ctx_t ctx, const char * nras_url) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (nras_url == nullptr) {
        LOG_ERROR("nras_url cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    cpp_ctx->set_default_nras_url(nras_url);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_set_default_rim_store_url(nvat_attestation_ctx_t ctx, const char * rim_store_url) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (rim_store_url == nullptr) {
        LOG_ERROR("rim_store_url cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    cpp_ctx->set_default_rim_store_url(rim_store_url);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_set_default_rim_store(nvat_attestation_ctx_t ctx, nvat_rim_store_t rim_store) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (rim_store == nullptr) {
        LOG_ERROR("rim_store cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    auto* cpp_rim_store = nvat_rim_store_to_cpp(rim_store);
    cpp_ctx->set_default_rim_store(std::move(*cpp_rim_store));
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_set_default_ocsp_client(nvat_attestation_ctx_t ctx, nvat_ocsp_client_t ocsp_client) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (ocsp_client == nullptr) {
        LOG_ERROR("ocsp_client cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    auto* cpp_ocsp_client = nvat_ocsp_client_to_cpp(ocsp_client);
    cpp_ctx->set_default_ocsp_client(std::move(*cpp_ocsp_client));
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_set_gpu_evidence_source_json_file(nvat_attestation_ctx_t ctx, const char* file_path) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (file_path == nullptr) {
        LOG_ERROR("file_path is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    std::string cpp_file_path = std::string(file_path);
    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    Error err = cpp_ctx->set_gpu_evidence_source_json_file(cpp_file_path);
    if (err != Error::Ok) {
        LOG_ERROR("failed to set GPU evidence source from JSON file");
        return nvat_rc_from_cpp(err);
    }
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_set_switch_evidence_source_json_file(nvat_attestation_ctx_t ctx, const char* file_path) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (file_path == nullptr) {
        LOG_ERROR("file_path is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    std::string cpp_file_path = std::string(file_path);
    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    Error err = cpp_ctx->set_switch_evidence_source_json_file(cpp_file_path);
    if (err != Error::Ok) {
        LOG_ERROR("failed to set switch evidence source from JSON file");
        return nvat_rc_from_cpp(err);
    }
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attest_system(
    const nvat_attestation_ctx_t ctx,
    const nvat_nonce_t nonce,
    nvat_claims_collection_t* out_claims
) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    auto* cpp_nonce = nvat_nonce_to_cpp(nonce);
    ClaimsCollection claims_collection {};
    Error err {};
    if (cpp_nonce != nullptr) {
        err = cpp_ctx->attest_system(*cpp_nonce, claims_collection);
    } else {
        err = cpp_ctx->attest_system({}, claims_collection);
    }
    if (err != Error::Ok) {
        LOG_ERROR("failed to perform system attestation");
        return nvat_rc_from_cpp(err);
    }
    if (out_claims == nullptr) {
        // discard claims
        return NVAT_RC_OK;
    }
    auto claims_collection_ptr = make_unique<ClaimsCollection>(std::move(claims_collection));
    *out_claims = nvat_claims_collection_from_cpp(claims_collection_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

// === Evidence Collection ===

nvat_rc_t nvat_nonce_create(nvat_nonce_t* out_nonce, size_t length) {
    NVAT_C_API_BEGIN
    if (out_nonce == nullptr) {
        LOG_ERROR("out_nonce is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto nonce = make_unique<vector<uint8_t>>(length, 0);
    if (length == 0) {
        return NVAT_RC_OK;
    }
    Error err = generate_nonce(*nonce);
    if (err != Error::Ok) {
        LOG_ERROR("failed to generate nonce of " << length << " bytes");
        return nvat_rc_from_cpp(err);
    }
    *out_nonce = nvat_nonce_from_cpp(nonce.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

size_t nvat_nonce_get_length(const nvat_nonce_t nonce) {
    if (nonce == nullptr) {
        return 0;
    }
    const std::vector<uint8_t>* cpp_nonce = nvat_nonce_to_cpp(nonce);
    return cpp_nonce->size();
}

nvat_rc_t nvat_nonce_hex_string(const nvat_nonce_t nonce, nvat_str_t* out_str) {
    NVAT_C_API_BEGIN
    if (nonce == nullptr) {
        LOG_ERROR("nonce is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_str == nullptr) {
        LOG_ERROR("out_str is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    const std::vector<uint8_t>* cpp_nonce = nvat_nonce_to_cpp(nonce);
    std::string hex_str = to_hex_string(*cpp_nonce);
    *out_str = nvat_str_from_cpp(new std::string(hex_str));
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_gpu_evidence_source_nvml_create(nvat_gpu_evidence_source_t* out_source) {
    NVAT_C_API_BEGIN
    if (out_source == nullptr) {
        LOG_ERROR("out_source is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    std::unique_ptr<std::shared_ptr<IGpuEvidenceSource>> gpu_evidence_source_ptr = make_unique<std::shared_ptr<IGpuEvidenceSource>>(make_shared<NvmlEvidenceCollector>());
    *out_source = nvat_gpu_evidence_source_from_cpp(gpu_evidence_source_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_gpu_evidence_source_from_json_file(nvat_gpu_evidence_source_t* out_source, const char* file_path) {
    NVAT_C_API_BEGIN
    if (out_source == nullptr) {
        LOG_ERROR("out_source is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (file_path == nullptr) {
        LOG_ERROR("file_path is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    GpuEvidenceSourceFromJsonFile gpu_evidence_source;
    Error err = GpuEvidenceSourceFromJsonFile::create(file_path, gpu_evidence_source);
    if (err != Error::Ok) {
        LOG_ERROR("failed to create GPU evidence source from JSON file");
        return nvat_rc_from_cpp(err);
    }
    std::unique_ptr<std::shared_ptr<IGpuEvidenceSource>> gpu_evidence_source_ptr = make_unique<std::shared_ptr<IGpuEvidenceSource>>(make_shared<GpuEvidenceSourceFromJsonFile>(std::move(gpu_evidence_source)));
    *out_source = nvat_gpu_evidence_source_from_cpp(gpu_evidence_source_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

size_t nvat_gpu_evidence_collection_get_length(const nvat_gpu_evidence_collection_t collection) {
    if (collection == nullptr) {
        return 0;
    }
    vector<GpuEvidence>* cpp_collection = nvat_gpu_evidence_collection_to_cpp(collection);
    return cpp_collection->size();
}

nvat_gpu_evidence_t nvat_gpu_evidence_collection_get_evidence(const nvat_gpu_evidence_collection_t collection, size_t index) {
    if (collection == nullptr) {
        return nullptr;
    }
    vector<GpuEvidence>* cpp_collection = nvat_gpu_evidence_collection_to_cpp(collection);
    if (index >= cpp_collection->size()) {
        return nullptr;
    }
    return nvat_gpu_evidence_from_cpp(&(*cpp_collection)[index]);
}

nvat_rc_t nvat_gpu_evidence_collect(const nvat_gpu_evidence_source_t source, const nvat_nonce_t nonce, nvat_gpu_evidence_collection_t* out_collection) {
    NVAT_C_API_BEGIN
    if (source == nullptr) {
        LOG_ERROR("source is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_collection == nullptr) {
        LOG_ERROR("out_collection is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    std::shared_ptr<IGpuEvidenceSource> cpp_source = *nvat_gpu_evidence_source_to_cpp(source);
    
    vector<uint8_t>* cpp_nonce_ptr = nvat_nonce_to_cpp(nonce);
    vector<uint8_t> cpp_nonce(0, 0);
    if (cpp_nonce_ptr != nullptr) {
        cpp_nonce = *cpp_nonce_ptr;
    }

    vector<GpuEvidence> evidence_list{};
    Error err = cpp_source->get_evidence(cpp_nonce, evidence_list);
    
    if (err != Error::Ok) {
        LOG_ERROR("failed to collect GPU evidence");
        return nvat_rc_from_cpp(err);
    }
    
    auto evidence_list_ptr = make_unique<vector<GpuEvidence>>(std::move(evidence_list));
    *out_collection = nvat_gpu_evidence_collection_from_cpp(evidence_list_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_gpu_evidence_serialize_json(
    const nvat_gpu_evidence_collection_t collection, 
    nvat_str_t* out_serialized_evidence
) {
    NVAT_C_API_BEGIN
    if (collection == nullptr) {
        LOG_ERROR("collection is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_serialized_evidence == nullptr) {
        LOG_ERROR("out_serialized_evidence is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    vector<GpuEvidence>* cpp_collection = nvat_gpu_evidence_collection_to_cpp(collection);
    std::string* json_string = new std::string("");
    Error err = GpuEvidence::collection_to_json(*cpp_collection, *json_string);
    if (err != Error::Ok) {
        LOG_ERROR("failed to serialize GPU evidence as JSON");
        return nvat_rc_from_cpp(err);
    }
    *out_serialized_evidence = nvat_str_from_cpp(json_string);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

// === Switch Evidence Collection ===

nvat_rc_t nvat_switch_evidence_source_nscq_create(nvat_switch_evidence_source_t* out_source) {
    NVAT_C_API_BEGIN
    if (out_source == nullptr) {
        LOG_ERROR("out_source is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    std::unique_ptr<std::shared_ptr<ISwitchEvidenceSource>> switch_evidence_source_ptr = make_unique<std::shared_ptr<ISwitchEvidenceSource>>(make_shared<NscqEvidenceCollector>());
    *out_source = nvat_switch_evidence_source_from_cpp(switch_evidence_source_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_switch_evidence_source_from_json_file(nvat_switch_evidence_source_t* out_source, const char* file_path) {
    NVAT_C_API_BEGIN
    if (out_source == nullptr) {
        LOG_ERROR("out_source is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (file_path == nullptr) {
        LOG_ERROR("file_path is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    SwitchEvidenceSourceFromJsonFile switch_evidence_source;
    Error err = SwitchEvidenceSourceFromJsonFile::create(file_path, switch_evidence_source);
    if (err != Error::Ok) {
        LOG_ERROR("failed to create switch evidence source from JSON file");
        return nvat_rc_from_cpp(err);
    }
    std::unique_ptr<std::shared_ptr<ISwitchEvidenceSource>> switch_evidence_source_ptr = make_unique<std::shared_ptr<ISwitchEvidenceSource>>(make_shared<SwitchEvidenceSourceFromJsonFile>(std::move(switch_evidence_source)));
    *out_source = nvat_switch_evidence_source_from_cpp(switch_evidence_source_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

size_t nvat_switch_evidence_collection_get_length(const nvat_switch_evidence_collection_t collection) {
    if (collection == nullptr) {
        return 0;
    }
    std::vector<SwitchEvidence>* cpp_collection = nvat_switch_evidence_collection_to_cpp(collection);
    return cpp_collection->size();
}

nvat_switch_evidence_t nvat_switch_evidence_collection_get_evidence(const nvat_switch_evidence_collection_t collection, size_t index) {
    if (collection == nullptr) {
        return nullptr;
    }
    std::vector<SwitchEvidence>* cpp_collection = nvat_switch_evidence_collection_to_cpp(collection);
    if (index >= cpp_collection->size()) {
        return nullptr;
    }
    return nvat_switch_evidence_from_cpp(&(*cpp_collection)[index]);
}

nvat_rc_t nvat_switch_evidence_collect(const nvat_switch_evidence_source_t source, const nvat_nonce_t nonce, nvat_switch_evidence_collection_t* out_collection) {
    NVAT_C_API_BEGIN
    if (source == nullptr) {
        LOG_ERROR("source is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (nonce == nullptr) {
        LOG_ERROR("nonce is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_collection == nullptr) {
        LOG_ERROR("out_collection is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    std::shared_ptr<ISwitchEvidenceSource> cpp_source = *nvat_switch_evidence_source_to_cpp(source);
    
    vector<uint8_t>* cpp_nonce_ptr = nvat_nonce_to_cpp(nonce);
    vector<uint8_t> cpp_nonce(0, 0);
    if (cpp_nonce_ptr != nullptr) {
        cpp_nonce = *cpp_nonce_ptr;
    }

    auto cpp_collection = std::make_unique<std::vector<SwitchEvidence>>();
    Error error = cpp_source->get_evidence(cpp_nonce, *cpp_collection);
    if (error != Error::Ok) {
        LOG_ERROR("failed to get switch evidence");
        return nvat_rc_from_cpp(error);
    }
    
    *out_collection = nvat_switch_evidence_collection_from_cpp(cpp_collection.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_switch_evidence_serialize_json(
    const nvat_switch_evidence_collection_t collection, 
    nvat_str_t* out_serialized_evidence
) {
    NVAT_C_API_BEGIN
    if (collection == nullptr) {
        LOG_ERROR("collection is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_serialized_evidence == nullptr) {
        LOG_ERROR("out_serialized_evidence is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    vector<SwitchEvidence>* cpp_collection = nvat_switch_evidence_collection_to_cpp(collection);
    std::string* json_string = new std::string("");
    Error err = SwitchEvidence::collection_to_json(*cpp_collection, *json_string);
    if (err != Error::Ok) {
        LOG_ERROR("failed to serialize switch evidence as JSON");
        return nvat_rc_from_cpp(err);
    }
    *out_serialized_evidence = nvat_str_from_cpp(json_string);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

// === Evidence Verification ===

nvat_rc_t nvat_claims_serialize_json(const nvat_claims_t claims, nvat_str_t* out_serialized_claims) {
    NVAT_C_API_BEGIN
    if (claims == nullptr) {
        LOG_ERROR("claims is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_serialized_claims == nullptr) {
        LOG_ERROR("out_serialized_claims is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    Claims* cpp_claims = nvat_claims_to_cpp(claims);
    std::string* json_string = new std::string("");
    Error err = cpp_claims->serialize_json(*json_string);
    if (err != Error::Ok) {
        LOG_ERROR("failed to serialize claims as JSON");
        return nvat_rc_from_cpp(err);
    }
    *out_serialized_claims = nvat_str_from_cpp(json_string);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_claims_collection_serialize_json(const nvat_claims_collection_t claims, nvat_str_t* out_serialized_claims) {
    NVAT_C_API_BEGIN
    if (claims == nullptr) {
        LOG_ERROR("claims is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_serialized_claims == nullptr) {
        LOG_ERROR("out_serialized_claims is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    ClaimsCollection* cpp_claims = nvat_claims_collection_to_cpp(claims);
    std::string* json_string = new std::string("");
    Error err = cpp_claims->serialize_json(*json_string);
    if (err != Error::Ok) {
        LOG_ERROR("failed to serialize claims as JSON");
        return nvat_rc_from_cpp(err);
    }
    *out_serialized_claims = nvat_str_from_cpp(json_string);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_evidence_policy_create_default(nvat_evidence_policy_t* out_policy) {
    NVAT_C_API_BEGIN
    if (out_policy == nullptr) {
        LOG_ERROR("out_policy is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto cpp_policy = make_unique<EvidencePolicy>();
    *out_policy = nvat_evidence_policy_from_cpp(cpp_policy.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

void nvat_evidence_policy_set_ocsp_allow_cert_hold(nvat_evidence_policy_t policy, bool allow_cert_hold) {
    NVAT_C_API_BEGIN
    if (policy == nullptr) {
        return;
    }
    EvidencePolicy* cpp_policy = nvat_evidence_policy_to_cpp(policy);
    cpp_policy->ocsp_options.set_allow_cert_hold(allow_cert_hold);
    NVAT_C_API_END_VOID
}

void nvat_evidence_policy_set_ocsp_check_nonce(nvat_evidence_policy_t policy, bool check_nonce) {
    NVAT_C_API_BEGIN
    if (policy == nullptr) {
        return;
    }
    EvidencePolicy* cpp_policy = nvat_evidence_policy_to_cpp(policy);
    cpp_policy->ocsp_options.set_nonce_enabled(check_nonce);
    NVAT_C_API_END_VOID
}

nvat_rc_t nvat_evidence_policy_set_gpu_claims_version(nvat_evidence_policy_t policy, nvat_gpu_claims_version_t version) {
    NVAT_C_API_BEGIN
    if (policy == nullptr) {
        LOG_ERROR("policy is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    EvidencePolicy* cpp_policy = nvat_evidence_policy_to_cpp(policy);
    GpuClaimsVersion cpp_version{};
    Error err = gpu_claims_version_from_c(version, cpp_version);
    if (err != Error::Ok) {
        return nvat_rc_from_cpp(err);
    }
    cpp_policy->gpu_claims_version = cpp_version;
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_evidence_policy_set_switch_claims_version(nvat_evidence_policy_t policy, nvat_switch_claims_version_t version) {
    NVAT_C_API_BEGIN
    if (policy == nullptr) {
        LOG_ERROR("policy is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    EvidencePolicy* cpp_policy = nvat_evidence_policy_to_cpp(policy);
    SwitchClaimsVersion cpp_version{};
    Error err = switch_claims_version_from_c(version, cpp_version);
    if (err != Error::Ok) {
        return nvat_rc_from_cpp(err);
    }
    cpp_policy->switch_claims_version = cpp_version;
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_gpu_nras_verifier_create(nvat_gpu_nras_verifier_t* out_verifier, const char* base_url, const nvat_http_options_t http_options) {
    NVAT_C_API_BEGIN
    if (out_verifier == nullptr) {
        LOG_ERROR("out_verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    HttpOptions cpp_http_options{};
    if (http_options != nullptr) {
        cpp_http_options = *nvat_http_options_to_cpp(http_options);
    }
    NvRemoteGpuVerifier verifier;
    Error err = NvRemoteGpuVerifier::init_from_env(verifier, base_url, cpp_http_options);
    if (err != Error::Ok) {
        LOG_ERROR("failed to create NRAS client");
        return nvat_rc_from_cpp(err);
    }

    auto verifier_ptr = make_unique<NvRemoteGpuVerifier>(std::move(verifier));
    *out_verifier = nvat_gpu_nras_verifier_from_cpp(verifier_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_switch_nras_verifier_create(nvat_switch_nras_verifier_t* out_verifier, const char* base_url, const nvat_http_options_t http_options) {
    NVAT_C_API_BEGIN
    if (out_verifier == nullptr) {
        LOG_ERROR("out_verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    HttpOptions cpp_http_options{};
    if (http_options != nullptr) {
        cpp_http_options = *nvat_http_options_to_cpp(http_options);
    }
    NvRemoteSwitchVerifier verifier;
    Error err = NvRemoteSwitchVerifier ::init_from_env(verifier, base_url, cpp_http_options);
    if (err != Error::Ok) {
        LOG_ERROR("failed to create NRAS client");
        return nvat_rc_from_cpp(err);
    }

    auto verifier_ptr = make_unique<NvRemoteSwitchVerifier>(std::move(verifier));
    *out_verifier = nvat_switch_nras_verifier_from_cpp(verifier_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_gpu_local_verifier_create(
    nvat_gpu_local_verifier_t* out_verifier,
    nvat_rim_store_t rim_store,
    nvat_ocsp_client_t ocsp_client
) {
    NVAT_C_API_BEGIN
    if (out_verifier == nullptr) {
        LOG_ERROR("out_verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (rim_store == nullptr) {
        LOG_ERROR("rim_store is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (ocsp_client == nullptr) {
        LOG_ERROR("ocsp_client is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    LocalGpuVerifier verifier;
    Error err = LocalGpuVerifier::create(
        verifier,
        *nvat_rim_store_to_cpp(rim_store),
        *nvat_ocsp_client_to_cpp(ocsp_client)
    );
    if (err != Error::Ok) {
        LOG_ERROR("failed to create local GPU verifier");
        return nvat_rc_from_cpp(err);
    }
    auto verifier_ptr = make_unique<LocalGpuVerifier>(verifier);
    *out_verifier = nvat_gpu_local_verifier_from_cpp(verifier_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_switch_local_verifier_create(
    nvat_switch_local_verifier_t* out_verifier,
    nvat_rim_store_t rim_store,
    nvat_ocsp_client_t ocsp_client
) {
    NVAT_C_API_BEGIN
    if (out_verifier == nullptr) {
        LOG_ERROR("out_verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (rim_store == nullptr) {
        LOG_ERROR("rim_store is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (ocsp_client == nullptr) {
        LOG_ERROR("ocsp_client is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    LocalSwitchVerifier verifier;
    Error err = LocalSwitchVerifier::create(
        verifier,
        *nvat_rim_store_to_cpp(rim_store),
        *nvat_ocsp_client_to_cpp(ocsp_client)
    );
    if (err != Error::Ok) {
        LOG_ERROR("failed to create local switch verifier");
        return nvat_rc_from_cpp(err);
    }
    auto verifier_ptr = make_unique<LocalSwitchVerifier>(verifier);
    *out_verifier = nvat_switch_local_verifier_from_cpp(verifier_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_gpu_verifier_t nvat_gpu_local_verifier_upcast(nvat_gpu_local_verifier_t verifier) {
    return reinterpret_cast<nvat_gpu_verifier_t>(verifier);
}

nvat_gpu_verifier_t nvat_gpu_nras_verifier_upcast(nvat_gpu_nras_verifier_t verifier) {
    return reinterpret_cast<nvat_gpu_verifier_t>(verifier);
}

nvat_switch_verifier_t nvat_switch_local_verifier_upcast(nvat_switch_local_verifier_t verifier) {
    return reinterpret_cast<nvat_switch_verifier_t>(verifier);
}

nvat_switch_verifier_t nvat_switch_nras_verifier_upcast(nvat_switch_nras_verifier_t verifier) {
    return reinterpret_cast<nvat_switch_verifier_t>(verifier);
}

nvat_rc_t nvat_verify_gpu_evidence(
    const nvat_gpu_verifier_t verifier,
    const nvat_gpu_evidence_collection_t evidence,
    const nvat_evidence_policy_t policy,
    nvat_claims_collection_t* out_claims
) {
    NVAT_C_API_BEGIN
    if (verifier == nullptr) {
        LOG_ERROR("verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (evidence == nullptr) {
        LOG_ERROR("evidence is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (policy == nullptr) {
        LOG_ERROR("policy is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_claims == nullptr) {
        LOG_ERROR("out_claims is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    IGpuVerifier* cpp_verifier = nvat_gpu_verifier_to_cpp(verifier);
    std::vector<GpuEvidence>* cpp_evidence = nvat_gpu_evidence_collection_to_cpp(evidence);
    EvidencePolicy* cpp_policy = nvat_evidence_policy_to_cpp(policy);

    ClaimsCollection cpp_claims;
    Error err = cpp_verifier->verify_evidence(*cpp_evidence, *cpp_policy, cpp_claims);
    if (err != Error::Ok) {
        LOG_ERROR("failed to verify GPU evidence");
        return nvat_rc_from_cpp(err);
    }

    auto claims_ptr = make_unique<ClaimsCollection>(std::move(cpp_claims));
    *out_claims = nvat_claims_collection_from_cpp(claims_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_verify_switch_evidence(
    const nvat_switch_verifier_t verifier,
    const nvat_switch_evidence_collection_t evidence,
    const nvat_evidence_policy_t policy,
    nvat_claims_collection_t* out_claims
) {
    NVAT_C_API_BEGIN
    if (verifier == nullptr) {
        LOG_ERROR("verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (evidence == nullptr) {
        LOG_ERROR("evidence is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (policy == nullptr) {
        LOG_ERROR("policy is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_claims == nullptr) {
        LOG_ERROR("out_claims is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    ISwitchVerifier* cpp_verifier = nvat_switch_verifier_to_cpp(verifier);
    std::vector<SwitchEvidence>* cpp_evidence = nvat_switch_evidence_collection_to_cpp(evidence);
    EvidencePolicy* cpp_policy = nvat_evidence_policy_to_cpp(policy);

    ClaimsCollection cpp_claims;
    Error err = cpp_verifier->verify_evidence(*cpp_evidence, *cpp_policy, cpp_claims);
    if (err != Error::Ok) {
        LOG_ERROR("failed to verify switch evidence");
        return nvat_rc_from_cpp(err);
    }

    auto claims_ptr = make_unique<ClaimsCollection>(std::move(cpp_claims));
    *out_claims = nvat_claims_collection_from_cpp(claims_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

} // extern "C"