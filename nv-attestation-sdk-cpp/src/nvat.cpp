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
#include <cctype>
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

NVAT_FREE_FUNCTION(logger, std::shared_ptr<ILogger>);
NVAT_FREE_FUNCTION(sdk_opts, std::shared_ptr<SdkOptions>);
NVAT_FREE_FUNCTION(nonce, std::vector<uint8_t>);
NVAT_FREE_FUNCTION(gpu_evidence, std::shared_ptr<GpuEvidence>);
NVAT_ARRAY_FREE_FUNCTION(gpu_evidence, num_evidences, std::shared_ptr<GpuEvidence>);
NVAT_FREE_FUNCTION(gpu_evidence_source, std::shared_ptr<IGpuEvidenceSource>);
NVAT_FREE_FUNCTION(switch_evidence, std::shared_ptr<SwitchEvidence>);
NVAT_ARRAY_FREE_FUNCTION(switch_evidence, num_evidences, std::shared_ptr<SwitchEvidence>);
NVAT_FREE_FUNCTION(switch_evidence_source, std::shared_ptr<ISwitchEvidenceSource>);
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
NVAT_FREE_FUNCTION(detached_eat_options, DetachedEATOptions);

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
    auto cpp_opts = std::make_unique<std::shared_ptr<SdkOptions>>(std::make_shared<SdkOptions>());
    *out_opts = nvat_sdk_opts_from_cpp(cpp_opts.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

void nvat_sdk_opts_set_logger(nvat_sdk_opts_t opts, nvat_logger_t logger) {
    NVAT_C_API_BEGIN
    if (opts == nullptr || logger == nullptr) {
        return;
    }
    std::shared_ptr<SdkOptions> cpp_opts = *nvat_sdk_opts_to_cpp(opts);
    std::shared_ptr<ILogger> cpp_logger = *nvat_logger_to_cpp(logger);
    cpp_opts->logger = cpp_logger;
    NVAT_C_API_END_VOID
}

nvat_rc_t nvat_sdk_init(nvat_sdk_opts_t opts) {
    NVAT_C_API_BEGIN
    std::shared_ptr<SdkOptions> cpp_opts = nullptr;
    if (opts != nullptr) {
        cpp_opts = *nvat_sdk_opts_to_cpp(opts);
    }
    Error err = init(cpp_opts);
    if (err != Error::Ok) {
        return nvat_rc_from_cpp(err);
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
    
    auto cpp_logger = make_unique<std::shared_ptr<ILogger>>(std::make_shared<SpdLogLogger>(name, level));
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
    auto cpp_logger = make_unique<std::shared_ptr<ILogger>>(std::make_shared<CallbackLogger>(
        should_log_callback,
        log_callback,
        flush_callback,
        user_data
    ));
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

nvat_rc_t nvat_attestation_ctx_create(nvat_attestation_ctx_t *ctx) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx* cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto ctx_ptr = std::make_unique<AttestationContext>();
    *ctx = nvat_attestation_ctx_from_cpp(ctx_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_set_device_type(nvat_attestation_ctx_t ctx, nvat_devices_t device_type) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    cpp_ctx->set_device_type(device_type);
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

nvat_rc_t nvat_attestation_ctx_set_detached_eat_options(nvat_attestation_ctx_t ctx, nvat_detached_eat_options_t detached_eat_options) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (detached_eat_options == nullptr) {
        LOG_ERROR("detached_eat_options cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    auto* cpp_detached_eat_options = nvat_detached_eat_options_to_cpp(detached_eat_options);
    cpp_ctx->set_detached_eat_options(*cpp_detached_eat_options);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attest_device(
    const nvat_attestation_ctx_t ctx,
    const nvat_nonce_t nonce,
    nvat_str_t* out_detached_eat,
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
    std::string* cpp_detached_eat = nullptr;
    if (out_detached_eat != nullptr) {
        cpp_detached_eat = new std::string("");
    }
    Error err {};
    if (cpp_nonce != nullptr) {
        err = cpp_ctx->attest_device(*cpp_nonce, cpp_detached_eat, claims_collection);
    } else {
        err = cpp_ctx->attest_device({}, cpp_detached_eat, claims_collection);
    }
    if (err != Error::Ok && err != Error::OverallResultFalse && err != Error::RelyingPartyPolicyMismatch) {
        LOG_ERROR("error while performing system attestation");
        return nvat_rc_from_cpp(err);
    }
    if (out_claims != nullptr) {
        auto claims_collection_ptr = make_unique<ClaimsCollection>(std::move(claims_collection));
        *out_claims = nvat_claims_collection_from_cpp(claims_collection_ptr.release());
    }
    if (out_detached_eat != nullptr) {
        *out_detached_eat = nvat_str_from_cpp(cpp_detached_eat);
    }
    return nvat_rc_from_cpp(err);
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

nvat_rc_t nvat_nonce_to_hex_string(const nvat_nonce_t nonce, nvat_str_t* out_str) {
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

nvat_rc_t nvat_nonce_from_hex(nvat_nonce_t* out_nonce, const char* hex_string) {
    NVAT_C_API_BEGIN
    if (out_nonce == nullptr) {
        LOG_ERROR("out_nonce is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (hex_string == nullptr) {
        LOG_ERROR("hex_string is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    std::string hex_no_prefix(hex_string);
    if (hex_no_prefix.rfind("0x", 0) == 0 || hex_no_prefix.rfind("0X", 0) == 0) {
        hex_no_prefix = hex_no_prefix.substr(2);
    }
    if (hex_no_prefix.empty() || (hex_no_prefix.size() % 2) != 0) {
        LOG_ERROR("hex_string must have an even number of hex digits");
        return NVAT_RC_BAD_ARGUMENT;
    }
    for (char ch : hex_no_prefix) {
        if (std::isxdigit(static_cast<unsigned char>(ch)) == 0) {
            LOG_ERROR("hex_string contains non-hex characters");
            return NVAT_RC_BAD_ARGUMENT;
        }
    }

    std::vector<uint8_t> bytes = hex_string_to_bytes(hex_no_prefix);
    if (bytes.size() < MIN_VALID_NONCE_LEN) {
        LOG_ERROR("nonce too short: " << bytes.size() << " bytes; minimum is " << MIN_VALID_NONCE_LEN);
        return NVAT_RC_BAD_ARGUMENT;
    }

    auto nonce = make_unique<vector<uint8_t>>(std::move(bytes));
    *out_nonce = nvat_nonce_from_cpp(nonce.release());
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

nvat_rc_t nvat_gpu_evidence_collect(const nvat_gpu_evidence_source_t source, const nvat_nonce_t nonce, nvat_gpu_evidence_t** out_gpu_evidence_array, size_t* out_num_evidences) {
    NVAT_C_API_BEGIN
    if (source == nullptr) {
        LOG_ERROR("source is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_gpu_evidence_array == nullptr) {
        LOG_ERROR("out_gpu_evidence_array is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_num_evidences == nullptr) {
        LOG_ERROR("out_num_evidences is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    *out_gpu_evidence_array = nullptr;
    *out_num_evidences = 0;
    
    std::shared_ptr<IGpuEvidenceSource> cpp_source = *nvat_gpu_evidence_source_to_cpp(source);
    
    vector<uint8_t>* cpp_nonce_ptr = nvat_nonce_to_cpp(nonce);
    vector<uint8_t> cpp_nonce(0, 0);
    if (cpp_nonce_ptr != nullptr) {
        cpp_nonce = *cpp_nonce_ptr;
    }

    vector<std::shared_ptr<GpuEvidence>> evidence_list{};
    Error err = cpp_source->get_evidence(cpp_nonce, evidence_list);
    
    if (err != Error::Ok) {
        LOG_ERROR("failed to collect GPU evidence");
        return nvat_rc_from_cpp(err);
    }

    *out_gpu_evidence_array = new nvat_gpu_evidence_t[evidence_list.size()];
    for (size_t i = 0; i < evidence_list.size(); i++) {
        auto* evidence_ptr = new std::shared_ptr<GpuEvidence>(evidence_list[i]);
        // the paranthesis are important. out_evidences is a pointer to an array pointer.
        // (*out_evidences) is the array pointer.
        // hence, (*out_evidences)[i] is the element of the array we wan to set
        // p.s for an array ptr, ptr[i] is the same as *(ptr + i), so to access an element, 
        // we could've also used *((*out_evidences) + i)
        (*out_gpu_evidence_array)[i] = nvat_gpu_evidence_from_cpp(evidence_ptr);
    }
    *out_num_evidences = evidence_list.size();
    
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_gpu_evidence_serialize_json(
    const nvat_gpu_evidence_t* gpu_evidence_array,
    size_t num_evidences,
    nvat_str_t* out_serialized_evidence
) {
    NVAT_C_API_BEGIN
    if (gpu_evidence_array == nullptr) {
        LOG_ERROR("gpu_evidence_array is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_serialized_evidence == nullptr) {
        LOG_ERROR("out_serialized_evidence is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    std::vector<std::shared_ptr<GpuEvidence>> cpp_evidences;
    for (size_t i = 0; i < num_evidences; i++) {
        if (gpu_evidence_array[i] == nullptr) {
            LOG_ERROR("gpu_evidence_array[" << i << "] is null");
            return NVAT_RC_BAD_ARGUMENT;
        }
        std::shared_ptr<GpuEvidence>* evidence_ptr = nvat_gpu_evidence_to_cpp(gpu_evidence_array[i]);
        cpp_evidences.push_back(*evidence_ptr);
    }
    std::string* json_string = new std::string("");
    Error err = GpuEvidence::collection_to_json(cpp_evidences, *json_string);
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

nvat_rc_t nvat_switch_evidence_collect(const nvat_switch_evidence_source_t source, const nvat_nonce_t nonce, nvat_switch_evidence_t** out_switch_evidence_array, size_t* out_num_evidences) {
    NVAT_C_API_BEGIN
    if (source == nullptr) {
        LOG_ERROR("source is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (nonce == nullptr) {
        LOG_ERROR("nonce is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_switch_evidence_array == nullptr) {
        LOG_ERROR("out_collection is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    std::shared_ptr<ISwitchEvidenceSource> cpp_source = *nvat_switch_evidence_source_to_cpp(source);
    
    vector<uint8_t>* cpp_nonce_ptr = nvat_nonce_to_cpp(nonce);
    vector<uint8_t> cpp_nonce(0, 0);
    if (cpp_nonce_ptr != nullptr) {
        cpp_nonce = *cpp_nonce_ptr;
    }

    std::vector<std::shared_ptr<SwitchEvidence>> cpp_collection;
    Error error = cpp_source->get_evidence(cpp_nonce, cpp_collection);
    if (error != Error::Ok) {
        LOG_ERROR("failed to get switch evidence");
        return nvat_rc_from_cpp(error);
    }
    
    *out_switch_evidence_array = new nvat_switch_evidence_t[cpp_collection.size()];
    for (size_t i = 0; i < cpp_collection.size(); i++) {
        auto* evidence_ptr = new std::shared_ptr<SwitchEvidence>(cpp_collection[i]);
        (*out_switch_evidence_array)[i] = nvat_switch_evidence_from_cpp(evidence_ptr);
    }
    *out_num_evidences = cpp_collection.size();
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_switch_evidence_serialize_json(
    const nvat_switch_evidence_t* switch_evidence_array,
    size_t num_evidences,
    nvat_str_t* out_serialized_evidence
) {
    NVAT_C_API_BEGIN
    if (switch_evidence_array == nullptr) {
        LOG_ERROR("collection is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_serialized_evidence == nullptr) {
        LOG_ERROR("out_serialized_evidence is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    vector<std::shared_ptr<SwitchEvidence>> cpp_collection;
    for (size_t i = 0; i < num_evidences; i++) {
        if (switch_evidence_array[i] == nullptr) {
            LOG_ERROR("switch_evidence_array[" << i << "] is null");
            return NVAT_RC_BAD_ARGUMENT;
        }
        std::shared_ptr<SwitchEvidence>* evidence_ptr = nvat_switch_evidence_to_cpp(switch_evidence_array[i]);
        cpp_collection.push_back(*evidence_ptr);
    }
    std::string* json_string = new std::string("");
    Error err = SwitchEvidence::collection_to_json(cpp_collection, *json_string);
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

nvat_rc_t nvat_claims_collection_extend(nvat_claims_collection_t nvat_claims_collection, const nvat_claims_collection_t other_claims_collection) {
    NVAT_C_API_BEGIN
    if (nvat_claims_collection == nullptr) {
        LOG_ERROR("nvat_claims_collection is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    if (other_claims_collection == nullptr) {
        LOG_ERROR("other_claims_collection is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    ClaimsCollection* cpp_claims = nvat_claims_collection_to_cpp(nvat_claims_collection);
    ClaimsCollection* cpp_other_claims = nvat_claims_collection_to_cpp(other_claims_collection);
    cpp_claims->extend(*cpp_other_claims);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_detached_eat_options_create(nvat_detached_eat_options_t* out_options, const char* private_key_pem, const char* issuer, const char* kid) {
    NVAT_C_API_BEGIN
    if (out_options == nullptr) {
        LOG_ERROR("out_options is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    DetachedEATOptions* cpp_options = new DetachedEATOptions();
    if (private_key_pem != nullptr) {
        cpp_options->m_private_key_pem = std::string(private_key_pem);
    }
    if (issuer != nullptr) {
        cpp_options->m_issuer = std::string(issuer);
    }
    if (kid != nullptr) {
        cpp_options->m_kid = std::string(kid);
    }
    *out_options = nvat_detached_eat_options_from_cpp(cpp_options);
    return NVAT_RC_OK;
    NVAT_C_API_END
}
nvat_rc_t nvat_get_detached_eat_es384(const nvat_claims_collection_t claims, const nvat_detached_eat_options_t options, nvat_str_t* out_detached_eat) {
    NVAT_C_API_BEGIN
    if (claims == nullptr) {
        LOG_ERROR("claims is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_detached_eat == nullptr) {
        LOG_ERROR("out_detached_eat is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    ClaimsCollection* cpp_claims = nvat_claims_collection_to_cpp(claims);

    std::string* detached_eat = new std::string("");
    DetachedEATOptions cpp_options = DetachedEATOptions();
    if (options != nullptr) {
        cpp_options = *nvat_detached_eat_options_to_cpp(options);
    }

    Error err = cpp_claims->get_detached_eat(*detached_eat, cpp_options);
    if (err != Error::Ok) {
        LOG_ERROR("failed to get detached EAT");
        return nvat_rc_from_cpp(err);
    }
    *out_detached_eat = nvat_str_from_cpp(detached_eat);
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
    nvat_ocsp_client_t ocsp_client,
    nvat_detached_eat_options_t detached_eat_options
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

    DetachedEATOptions detached_eat_cpp_options = DetachedEATOptions();
    if (detached_eat_options != nullptr) {
        detached_eat_cpp_options = *nvat_detached_eat_options_to_cpp(detached_eat_options);
    }

    LocalGpuVerifier verifier;
    Error err = LocalGpuVerifier::create(
        verifier,
        *nvat_rim_store_to_cpp(rim_store),
        *nvat_ocsp_client_to_cpp(ocsp_client),
        detached_eat_cpp_options
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
    nvat_ocsp_client_t ocsp_client,
    nvat_detached_eat_options_t detached_eat_options
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

    DetachedEATOptions detached_eat_cpp_options = DetachedEATOptions();
    if (detached_eat_options != nullptr) {
        detached_eat_cpp_options = *nvat_detached_eat_options_to_cpp(detached_eat_options);
    }

    LocalSwitchVerifier verifier;
    Error err = LocalSwitchVerifier::create(
        verifier,
        *nvat_rim_store_to_cpp(rim_store),
        *nvat_ocsp_client_to_cpp(ocsp_client),
        detached_eat_cpp_options
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
    const nvat_gpu_evidence_t* gpu_evidence_array,
    size_t num_evidences,
    const nvat_evidence_policy_t policy,
    nvat_str_t* out_detached_eat,
    nvat_claims_collection_t* out_claims
) {
    NVAT_C_API_BEGIN
    if (verifier == nullptr) {
        LOG_ERROR("verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (gpu_evidence_array == nullptr) {
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
    std::vector<std::shared_ptr<GpuEvidence>> cpp_evidences;
    for (size_t i = 0; i < num_evidences; i++) {
        if (gpu_evidence_array[i] == nullptr) {
            LOG_ERROR("gpu_evidence_array[" << i << "] is null");
            return NVAT_RC_BAD_ARGUMENT;
        }
        std::shared_ptr<GpuEvidence>* evidence_ptr = nvat_gpu_evidence_to_cpp(gpu_evidence_array[i]);
        cpp_evidences.push_back(*evidence_ptr);
    }
    EvidencePolicy* cpp_policy = nvat_evidence_policy_to_cpp(policy);

    ClaimsCollection cpp_claims;
    std::string cpp_detached_eat_str;
    std::string* cpp_detached_eat = nullptr;
    if (out_detached_eat != nullptr) {
        cpp_detached_eat = &cpp_detached_eat_str;
    }
    Error err = cpp_verifier->verify_evidence(cpp_evidences, *cpp_policy, cpp_detached_eat, cpp_claims);
    if (err != Error::Ok) {
        LOG_ERROR("failed to verify GPU evidence");
        return nvat_rc_from_cpp(err);
    }

    auto claims_ptr = make_unique<ClaimsCollection>(std::move(cpp_claims));
    *out_claims = nvat_claims_collection_from_cpp(claims_ptr.release());
    if (out_detached_eat != nullptr) {
        *out_detached_eat = nvat_str_from_cpp(new std::string(cpp_detached_eat_str));
    }
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_verify_switch_evidence(
    const nvat_switch_verifier_t verifier,
    const nvat_switch_evidence_t* switch_evidence_array,
    size_t num_evidences,
    const nvat_evidence_policy_t policy,
    nvat_str_t* out_detached_eat,
    nvat_claims_collection_t* out_claims
) {
    NVAT_C_API_BEGIN
    if (verifier == nullptr) {
        LOG_ERROR("verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (switch_evidence_array == nullptr) {
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
    std::vector<std::shared_ptr<SwitchEvidence>> cpp_evidences;
    for (size_t i = 0; i < num_evidences; i++) {
        if (switch_evidence_array[i] == nullptr) {
            LOG_ERROR("switch_evidence_array[" << i << "] is null");
            return NVAT_RC_BAD_ARGUMENT;
        }
        std::shared_ptr<SwitchEvidence>* evidence_ptr = nvat_switch_evidence_to_cpp(switch_evidence_array[i]);
        cpp_evidences.push_back(*evidence_ptr);
    }
    EvidencePolicy* cpp_policy = nvat_evidence_policy_to_cpp(policy);

    ClaimsCollection cpp_claims;
    std::string cpp_detached_eat_str;
    std::string* cpp_detached_eat = nullptr;
    if (out_detached_eat != nullptr) {
        cpp_detached_eat = &cpp_detached_eat_str;
    }
    Error err = cpp_verifier->verify_evidence(cpp_evidences, *cpp_policy, cpp_detached_eat, cpp_claims);
    if (err != Error::Ok) {
        LOG_ERROR("failed to verify switch evidence");
        return nvat_rc_from_cpp(err);
    }

    auto claims_ptr = make_unique<ClaimsCollection>(std::move(cpp_claims));
    *out_claims = nvat_claims_collection_from_cpp(claims_ptr.release());
    if (out_detached_eat != nullptr) {
        *out_detached_eat = nvat_str_from_cpp(new std::string(cpp_detached_eat_str));
    }
    return NVAT_RC_OK;
    NVAT_C_API_END
}

} // extern "C"