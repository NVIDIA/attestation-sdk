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
#include <limits>
#include <memory>
#include <cctype>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "nv_attestation/attestation.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/claims_evaluator.h"
#include "nv_attestation/cmw.h"
#include "nv_attestation/corim_verify.h"
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
#include "nv_attestation/verify.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/gpu/evidence.h"
#include "nv_attestation/switch/evidence.h"
#include "nv_attestation/nv_ocsp.h"
#include "nvat.h.in"

using namespace nvattestation;

extern "C" {

// === Free Functions ===

NVAT_PTR_CONVERSION_FUNCTIONS(ocsp_client_options, OcspClientOptions);
NVAT_PTR_CONVERSION_FUNCTIONS(jwt_validation_options, JwtValidationOptions);
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
NVAT_FREE_FUNCTION(jwt_validation_options, JwtValidationOptions);
NVAT_FREE_FUNCTION(ocsp_client_options, OcspClientOptions);
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
NVAT_FREE_FUNCTION(cmw_collection, CmwCollection);
NVAT_FREE_FUNCTION(corim_store, CorimStore);
NVAT_FREE_FUNCTION(local_corim_verifier, LocalCorimVerifier);

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

void nvat_http_options_set_tls_ca_cert(nvat_http_options_t http_options, const char* tls_ca_cert) {
    NVAT_C_API_BEGIN
    if (http_options == nullptr || tls_ca_cert == nullptr) {
        return;
    }
    auto* cpp_options = nvat_http_options_to_cpp(http_options);
    cpp_options->set_tls_ca_cert(std::string(tls_ca_cert));
    NVAT_C_API_END_VOID
}

void nvat_http_options_set_tls_ca_path(nvat_http_options_t http_options, const char* tls_ca_path) {
    NVAT_C_API_BEGIN
    if (http_options == nullptr || tls_ca_path == nullptr) {
        return;
    }
    auto* cpp_options = nvat_http_options_to_cpp(http_options);
    cpp_options->set_tls_ca_path(std::string(tls_ca_path));
    NVAT_C_API_END_VOID
}

nvat_rc_t nvat_jwt_validation_options_create_default(
    nvat_jwt_validation_options_t* out_options) {
    NVAT_C_API_BEGIN
    if (out_options == nullptr) {
        LOG_ERROR("out_options is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto cpp_options = make_unique<JwtValidationOptions>();
    *out_options = nvat_jwt_validation_options_from_cpp(cpp_options.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

void nvat_jwt_validation_options_set_clock_skew_leeway_seconds(
    nvat_jwt_validation_options_t options, uint64_t seconds) {
    NVAT_C_API_BEGIN
    if (options == nullptr) {
        return;
    }
    if (seconds > std::numeric_limits<std::size_t>::max()) {
        LOG_ERROR("clock skew leeway exceeds size_t range");
        return;
    }
    nvat_jwt_validation_options_to_cpp(options)->clock_skew_leeway_seconds =
        static_cast<std::size_t>(seconds);
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
        LOG_ERROR("Failed to evaluate claims");
        return nvat_rc_from_cpp(err);
    }
    if (!cpp_match) {
        LOG_ERROR("Claims do not match relying party policy");
        return NVAT_RC_RP_POLICY_MISMATCH;
    }
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_apply_relying_party_policy_to_ear(
    nvat_relying_party_policy_t policy,
    const char* ear_json) {
    NVAT_C_API_BEGIN
    if (policy == nullptr) {
        LOG_ERROR("policy is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (ear_json == nullptr) {
        LOG_ERROR("ear_json is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    const auto parsed = nlohmann::json::parse(ear_json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        LOG_ERROR("ear_json must contain a JSON object");
        return NVAT_RC_BAD_ARGUMENT;
    }

    auto* cpp_policy = nvat_relying_party_policy_to_cpp(policy);
    bool match = false;
    Error err = (*cpp_policy)->evaluate_json(parsed.dump(), match);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to evaluate EAR");
        return nvat_rc_from_cpp(err);
    }
    if (!match) {
        LOG_ERROR("EAR does not match relying party policy");
        return NVAT_RC_RP_POLICY_MISMATCH;
    }
    return NVAT_RC_OK;
    NVAT_C_API_END
}

static JwtValidationOptions jwt_validation_options_or_default(
    const nvat_jwt_validation_options_t options) {
    return options == nullptr ? JwtValidationOptions{}
                              : *nvat_jwt_validation_options_to_cpp(options);
}

nvat_rc_t nvat_verify_attestation_result(
    const char* eat, const char* nras_base_url, const char* service_key,
    nvat_nonce_t expected_nonce, const nvat_http_options_t http_options,
    const nvat_jwt_validation_options_t jwt_validation_options,
    nvat_claims_collection_t* out_claims) {
    NVAT_C_API_BEGIN
    if (eat == nullptr) {
        LOG_ERROR("eat is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (nras_base_url == nullptr || *nras_base_url == '\0') {
        LOG_ERROR("nras_base_url is null or empty");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_claims == nullptr) {
        LOG_ERROR("out_claims is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    HttpOptions cpp_http_options{};
    if (http_options != nullptr) {
        cpp_http_options = *nvat_http_options_to_cpp(http_options);
    }
    const JwtValidationOptions cpp_jwt_options =
        jwt_validation_options_or_default(jwt_validation_options);

    // An empty expected nonce means the relying party did not request a nonce
    // check; verify_attestation_result skips the comparison in that case.
    std::vector<uint8_t> cpp_nonce;
    if (expected_nonce != nullptr) {
        cpp_nonce = *nvat_nonce_to_cpp(expected_nonce);
    }

    const std::string cpp_service_key = service_key != nullptr ? std::string(service_key) : "";

    auto cpp_claims = make_unique<ClaimsCollection>();
    Error err = verify_attestation_result(
        std::string(eat), std::string(nras_base_url), cpp_service_key,
        cpp_http_options, cpp_jwt_options, cpp_nonce, *cpp_claims);
    if (err != Error::Ok && err != Error::OverallResultFalse) {
        LOG_ERROR("Failed to verify NRAS attestation result");
        return nvat_rc_from_cpp(err);
    }

    *out_claims = nvat_claims_collection_from_cpp(cpp_claims.release());
    return nvat_rc_from_cpp(err);
    NVAT_C_API_END
}

nvat_rc_t nvat_verify_ear(
    const char* ear_jwt, const char* verifier_base_url,
    const char* service_key, nvat_nonce_t expected_nonce,
    const nvat_http_options_t http_options,
    const nvat_jwt_validation_options_t jwt_validation_options,
    nvat_str_t* out_ear_json) {
    NVAT_C_API_BEGIN
    if (out_ear_json == nullptr) {
        return NVAT_RC_BAD_ARGUMENT;
    }
    *out_ear_json = nullptr;
    if (ear_jwt == nullptr || *ear_jwt == '\0' ||
        verifier_base_url == nullptr || *verifier_base_url == '\0') {
        return NVAT_RC_BAD_ARGUMENT;
    }

    HttpOptions cpp_http_options{};
    if (http_options != nullptr) {
        cpp_http_options = *nvat_http_options_to_cpp(http_options);
    }
    const JwtValidationOptions cpp_jwt_options =
        jwt_validation_options_or_default(jwt_validation_options);
    std::vector<uint8_t> cpp_nonce;
    if (expected_nonce != nullptr) {
        cpp_nonce = *nvat_nonce_to_cpp(expected_nonce);
    }

    auto verified = make_unique<std::string>();
    const Error err = verify_ear(
        ear_jwt, verifier_base_url,
        service_key == nullptr ? "" : service_key,
        cpp_http_options, cpp_jwt_options, cpp_nonce, *verified);
    if (err != Error::Ok) {
        return nvat_rc_from_cpp(err);
    }

    *out_ear_json = nvat_str_from_cpp(verified.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

static Error ocsp_hash_from_c(nvat_ocsp_cert_id_hash_algorithm_t value,
                              OcspCertIdHashAlgorithm& out) {
    switch (value) {
        case NVAT_OCSP_CERT_ID_HASH_SHA256:
            out = OcspCertIdHashAlgorithm::Sha256;
            return Error::Ok;
        case NVAT_OCSP_CERT_ID_HASH_SHA1:
            out = OcspCertIdHashAlgorithm::Sha1;
            return Error::Ok;
        case NVAT_OCSP_CERT_ID_HASH_SHA384:
            out = OcspCertIdHashAlgorithm::Sha384;
            return Error::Ok;
    }
    return Error::BadArgument;
}

static nvat_ocsp_cert_id_hash_algorithm_t ocsp_hash_to_c(
    OcspCertIdHashAlgorithm value) {
    switch (value) {
        case OcspCertIdHashAlgorithm::Sha1:
            return NVAT_OCSP_CERT_ID_HASH_SHA1;
        case OcspCertIdHashAlgorithm::Sha256:
            return NVAT_OCSP_CERT_ID_HASH_SHA256;
        case OcspCertIdHashAlgorithm::Sha384:
            return NVAT_OCSP_CERT_ID_HASH_SHA384;
    }
    return NVAT_OCSP_CERT_ID_HASH_SHA256;
}

static OcspClientOptions ocsp_client_options_or_default(
    const nvat_ocsp_client_options_t options) {
    return options == nullptr
        ? OcspClientOptions{}
        : *nvat_ocsp_client_options_to_cpp(options);
}

static nvat_rc_t nvat_ocsp_client_create_impl(
    nvat_ocsp_client_t* out_client,
    const char* base_url,
    const char* service_key,
    const nvat_http_options_t http_options,
    bool use_cert_aia_responder,
    const char* const* rewrite_patterns,
    const char* const* rewrite_replacements,
    size_t num_rewrites,
    const OcspClientOptions* options) {
    if (out_client == nullptr) {
        LOG_ERROR("out_client is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (use_cert_aia_responder && num_rewrites > 0 &&
        (rewrite_patterns == nullptr || rewrite_replacements == nullptr)) {
        LOG_ERROR("rewrite arrays are null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    NvHttpOcspClient client;
    HttpOptions cpp_http_options{};
    if (http_options != nullptr) {
        cpp_http_options = *nvat_http_options_to_cpp(http_options);
    }
    const std::string cpp_service_key =
        service_key != nullptr ? std::string(service_key) : "";
    Error err = options == nullptr
        ? NvHttpOcspClient::init_from_env(
              client, base_url, cpp_service_key, cpp_http_options)
        : NvHttpOcspClient::init_from_env(
              client, base_url, cpp_service_key, cpp_http_options, *options);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to create OCSP client");
        return nvat_rc_from_cpp(err);
    }

    if (use_cert_aia_responder) {
        client.set_use_cert_aia_responder(true);
        for (size_t i = 0; i < num_rewrites; ++i) {
            if (rewrite_patterns[i] == nullptr ||
                rewrite_replacements[i] == nullptr) {
                LOG_ERROR("rewrite entry is null");
                return NVAT_RC_BAD_ARGUMENT;
            }
            err = client.add_url_rewrite(std::string(rewrite_patterns[i]),
                                         std::string(rewrite_replacements[i]));
            if (err != Error::Ok) {
                return nvat_rc_from_cpp(err);
            }
        }
    }

    auto client_ptr = make_unique<shared_ptr<IOcspHttpClient>>(
        make_shared<NvHttpOcspClient>(std::move(client)));
    *out_client = nvat_ocsp_client_from_cpp(client_ptr.release());
    return NVAT_RC_OK;
}

nvat_rc_t nvat_ocsp_client_options_create_default(
    nvat_ocsp_client_options_t* out_options) {
    NVAT_C_API_BEGIN
    if (out_options == nullptr) {
        LOG_ERROR("out_options is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto options = std::make_unique<OcspClientOptions>();
    *out_options = nvat_ocsp_client_options_from_cpp(options.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_ocsp_cert_id_hash_algorithm_from_name(
    const char* name,
    nvat_ocsp_cert_id_hash_algorithm_t* out_algorithm) {
    NVAT_C_API_BEGIN
    if (name == nullptr || out_algorithm == nullptr) {
        return NVAT_RC_BAD_ARGUMENT;
    }
    OcspCertIdHashAlgorithm cpp_algorithm{};
    const Error err = ocsp_cert_id_hash_algorithm_from_name(
        std::string(name), cpp_algorithm);
    if (err != Error::Ok) {
        return nvat_rc_from_cpp(err);
    }
    *out_algorithm = ocsp_hash_to_c(cpp_algorithm);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_ocsp_client_options_set_cert_id_hash_algorithm(
    nvat_ocsp_client_options_t options,
    nvat_ocsp_cert_id_hash_algorithm_t algorithm) {
    NVAT_C_API_BEGIN
    if (options == nullptr) {
        LOG_ERROR("options is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    OcspCertIdHashAlgorithm cpp_algorithm{};
    const Error err = ocsp_hash_from_c(algorithm, cpp_algorithm);
    if (err != Error::Ok) {
        return nvat_rc_from_cpp(err);
    }
    nvat_ocsp_client_options_to_cpp(options)->cert_id_hash_algorithm =
        cpp_algorithm;
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_ocsp_client_create_default(
    nvat_ocsp_client_t* out_client,
    const char* base_url,
    const char* service_key,
    const nvat_http_options_t http_options) {
    NVAT_C_API_BEGIN
    return nvat_ocsp_client_create_impl(
        out_client, base_url, service_key, http_options, false, nullptr,
        nullptr, 0, nullptr);
    NVAT_C_API_END
}

nvat_rc_t nvat_ocsp_client_create_default_with_options(
    nvat_ocsp_client_t* out_client,
    const char* base_url,
    const char* service_key,
    const nvat_http_options_t http_options,
    const nvat_ocsp_client_options_t options) {
    NVAT_C_API_BEGIN
    const OcspClientOptions cpp_options =
        ocsp_client_options_or_default(options);
    return nvat_ocsp_client_create_impl(
        out_client, base_url, service_key, http_options, false, nullptr,
        nullptr, 0, &cpp_options);
    NVAT_C_API_END
}

nvat_rc_t nvat_ocsp_client_create_cached(nvat_ocsp_client_t* out_client, const nvat_ocsp_client_t inner_client, uint64_t max_size_bytes, time_t ttl_seconds) {
    NVAT_C_API_BEGIN
    if (out_client == nullptr) {
        LOG_ERROR("out_client is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (inner_client == nullptr) {
        LOG_ERROR("inner_client is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    std::shared_ptr<IOcspHttpClient> inner_client_ptr = *nvat_ocsp_client_to_cpp(inner_client);
    std::shared_ptr<IOcspHttpClient> out_client_ptr;
    Error err = NvHttpOcspCacheClient::create(inner_client_ptr, max_size_bytes, ttl_seconds, out_client_ptr);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to create cached OCSP client");
        return nvat_rc_from_cpp(err);
    }
    std::shared_ptr<IOcspHttpClient>* client_ptr = new std::shared_ptr<IOcspHttpClient>(out_client_ptr);
    *out_client = nvat_ocsp_client_from_cpp(client_ptr);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_ocsp_client_create_aia(
    nvat_ocsp_client_t* out_client,
    const char* base_url,
    const char* service_key,
    const nvat_http_options_t http_options,
    const char* const* rewrite_patterns,
    const char* const* rewrite_replacements,
    size_t num_rewrites,
    const nvat_ocsp_client_options_t options
) {
    NVAT_C_API_BEGIN
    const OcspClientOptions cpp_options =
        ocsp_client_options_or_default(options);
    return nvat_ocsp_client_create_impl(
        out_client, base_url, service_key, http_options, true,
        rewrite_patterns, rewrite_replacements, num_rewrites, &cpp_options);
    NVAT_C_API_END
}

nvat_rc_t nvat_rim_store_create_remote(nvat_rim_store_t* out_store, const char* base_url, const char* service_key, const nvat_http_options_t http_options) {
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
    const std::string cpp_service_key = service_key != nullptr ? std::string(service_key) : "";
    Error err = NvRemoteRimStoreImpl::init_from_env(store, base_url, cpp_service_key, cpp_http_options);
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

    auto store = std::make_unique<shared_ptr<IRimStore>>(std::make_shared<FilesystemRimStoreImpl>(base_path));
    *out_store = nvat_rim_store_from_cpp(store.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_rim_store_create_cached(nvat_rim_store_t* out_store, const nvat_rim_store_t inner_store, uint64_t max_size_bytes, time_t ttl_seconds) {
    NVAT_C_API_BEGIN
    if (out_store == nullptr) {
        LOG_ERROR("out_store is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (inner_store == nullptr) {
        LOG_ERROR("inner_store is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    std::shared_ptr<IRimStore> store = std::make_shared<InMemoryCachingRimStoreImpl>(*nvat_rim_store_to_cpp(inner_store), max_size_bytes, ttl_seconds);
    std::shared_ptr<IRimStore>* store_ptr = new std::shared_ptr<IRimStore>(store);
    *out_store = nvat_rim_store_from_cpp(store_ptr);
    return NVAT_RC_OK;
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
        delete cpp_evidence_policy;
        cpp_evidence_policy = nullptr;
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
        LOG_ERROR("Failed to set GPU evidence source from JSON file");
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
        LOG_ERROR("Failed to set switch evidence source from JSON file");
        return nvat_rc_from_cpp(err);
    }
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_attestation_ctx_set_service_key(nvat_attestation_ctx_t ctx, const char* service_key) {
    NVAT_C_API_BEGIN
    if (ctx == nullptr) {
        LOG_ERROR("ctx cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_ctx = nvat_attestation_ctx_to_cpp(ctx);
    if (service_key == nullptr) {
        LOG_ERROR("service_key cannot be null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    cpp_ctx->set_service_key(std::string(service_key));
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
    std::unique_ptr<std::string> cpp_detached_eat;
    if (out_detached_eat != nullptr) {
        cpp_detached_eat = make_unique<std::string>("");
    }
    Error err {};
    if (cpp_nonce != nullptr) {
        err = cpp_ctx->attest_device(*cpp_nonce, cpp_detached_eat.get(), claims_collection);
    } else {
        err = cpp_ctx->attest_device({}, cpp_detached_eat.get(), claims_collection);
    }
    if (err != Error::Ok && err != Error::OverallResultFalse && err != Error::RelyingPartyPolicyMismatch) {
        LOG_ERROR("Error while performing device attestation");
        return nvat_rc_from_cpp(err);
    }
    if (out_claims != nullptr) {
        auto claims_collection_ptr = make_unique<ClaimsCollection>(std::move(claims_collection));
        *out_claims = nvat_claims_collection_from_cpp(claims_collection_ptr.release());
    }
    if (out_detached_eat != nullptr) {
        *out_detached_eat = nvat_str_from_cpp(cpp_detached_eat.release());
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
    if (length < MIN_VALID_NONCE_LEN) {
        LOG_ERROR("nonce too short: " << length << " bytes; minimum is " << MIN_VALID_NONCE_LEN);
        return NVAT_RC_BAD_ARGUMENT;
    }

    auto nonce = make_unique<vector<uint8_t>>(length, 0);
    if (length == 0) {
        return NVAT_RC_OK;
    }
    Error err = generate_nonce(*nonce);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to generate nonce of " << length << " bytes");
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

nvat_rc_t nvat_nonce_get_bytes(const nvat_nonce_t nonce, char* bytes, size_t bytes_len) {
    NVAT_C_API_BEGIN
    if (nonce == nullptr) {
        LOG_ERROR("nonce is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (bytes == nullptr) {
        LOG_ERROR("bytes is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    const std::vector<uint8_t>* cpp_nonce = nvat_nonce_to_cpp(nonce);
    if (bytes_len != cpp_nonce->size()) {
        LOG_ERROR("bytes_len (" << bytes_len << ") does not match nonce length (" << cpp_nonce->size() << ")");
        return NVAT_RC_BAD_ARGUMENT;
    }

    std::memcpy(bytes, cpp_nonce->data(), bytes_len);
    return NVAT_RC_OK;
    NVAT_C_API_END
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

nvat_rc_t nvat_nonce_from_bytes(nvat_nonce_t* out_nonce, const char* input_bytes, size_t length) {
    NVAT_C_API_BEGIN
    if (out_nonce == nullptr) {
        LOG_ERROR("out_nonce is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (input_bytes == nullptr) {
        LOG_ERROR("input_bytes is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (length < MIN_VALID_NONCE_LEN) {
        LOG_ERROR("nonce too short: " << length << " bytes; minimum is " << MIN_VALID_NONCE_LEN);
        return NVAT_RC_BAD_ARGUMENT;
    }

    auto nonce = make_unique<vector<uint8_t>>(reinterpret_cast<const uint8_t*>(input_bytes), 
                                               reinterpret_cast<const uint8_t*>(input_bytes) + length);
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

nvat_rc_t nvat_gpu_evidence_source_corelib_create(nvat_gpu_evidence_source_t* out_source, const char* gpu_architecture) {
    NVAT_C_API_BEGIN
    if (out_source == nullptr) {
        LOG_ERROR("out_source is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (gpu_architecture == nullptr) {
        LOG_ERROR("gpu_architecture is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    // Parse architecture string
    GpuArchitecture arch = GpuArchitecture::Unknown;
    from_string(std::string(gpu_architecture), arch);
    if (arch == GpuArchitecture::Unknown) {
        LOG_ERROR("Invalid GPU architecture: " << gpu_architecture);
        return NVAT_RC_BAD_ARGUMENT;
    }

    // Currently only Blackwell supported
    if (arch != GpuArchitecture::Blackwell) {
        LOG_ERROR("Corelib only supports Blackwell architecture, got: " << gpu_architecture);
        return NVAT_RC_GPU_ARCHITECTURE_NOT_SUPPORTED;
    }

    std::unique_ptr<std::shared_ptr<IGpuEvidenceSource>> gpu_evidence_source_ptr = make_unique<std::shared_ptr<IGpuEvidenceSource>>(make_shared<CorelibEvidenceCollector>(arch));
    *out_source = nvat_gpu_evidence_source_from_cpp(gpu_evidence_source_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_gpu_evidence_source_from_json_string(nvat_gpu_evidence_source_t* out_source, const char* json_string) {
    NVAT_C_API_BEGIN
    if (out_source == nullptr) {
        LOG_ERROR("out_source is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (json_string == nullptr) {
        LOG_ERROR("json_string is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    GpuEvidenceSourceFromJsonString gpu_evidence_source;
    Error err = GpuEvidenceSourceFromJsonString::create(json_string, gpu_evidence_source);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to create GPU evidence source from JSON string");
        return nvat_rc_from_cpp(err);
    }
    std::unique_ptr<std::shared_ptr<IGpuEvidenceSource>> gpu_evidence_source_ptr = make_unique<std::shared_ptr<IGpuEvidenceSource>>(make_shared<GpuEvidenceSourceFromJsonString>(std::move(gpu_evidence_source)));
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
        LOG_ERROR("Failed to create GPU evidence source from JSON file");
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
    
    // todo (p2): push the nonce generation by default to the evidence collector
    vector<uint8_t>* cpp_nonce_ptr=nullptr;
    vector<uint8_t> local_nonce(GPU_SPDM_REQ_NONCE_SIZE, 0);
    if (nonce != nullptr) {
        cpp_nonce_ptr = nvat_nonce_to_cpp(nonce);
    } else {
        Error err = generate_nonce(local_nonce);
        if (err != Error::Ok) {
            LOG_ERROR("Failed to generate nonce of " << GPU_SPDM_REQ_NONCE_SIZE << " bytes");
            return nvat_rc_from_cpp(err);
        }
        cpp_nonce_ptr = &local_nonce;
    }

    vector<std::shared_ptr<GpuEvidence>> evidence_list{};
    Error err = cpp_source->get_evidence(*cpp_nonce_ptr, evidence_list);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to collect GPU evidence");
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
    auto json_string = make_unique<std::string>();
    Error err = GpuEvidence::collection_to_json(cpp_evidences, *json_string);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to serialize GPU evidence as JSON");
        return nvat_rc_from_cpp(err);
    }
    *out_serialized_evidence = nvat_str_from_cpp(json_string.release());
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

nvat_rc_t nvat_switch_evidence_source_from_json_string(nvat_switch_evidence_source_t* out_source, const char* json_string) {
    NVAT_C_API_BEGIN
    if (out_source == nullptr) {
        LOG_ERROR("out_source is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (json_string == nullptr) {
        LOG_ERROR("json_string is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    SwitchEvidenceSourceFromJsonString switch_evidence_source;
    Error err = SwitchEvidenceSourceFromJsonString::create(json_string, switch_evidence_source);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to create switch evidence source from JSON string");
        return nvat_rc_from_cpp(err);
    }
    std::unique_ptr<std::shared_ptr<ISwitchEvidenceSource>> switch_evidence_source_ptr = make_unique<std::shared_ptr<ISwitchEvidenceSource>>(make_shared<SwitchEvidenceSourceFromJsonString>(std::move(switch_evidence_source)));
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
        LOG_ERROR("Failed to create switch evidence source from JSON file");
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
    if (out_switch_evidence_array == nullptr) {
        LOG_ERROR("out_collection is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (out_num_evidences == nullptr) {
        LOG_ERROR("out_num_evidences is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    std::shared_ptr<ISwitchEvidenceSource> cpp_source = *nvat_switch_evidence_source_to_cpp(source);
    
    // todo (p2): push the nonce generation by default to the evidence collector
    vector<uint8_t>* cpp_nonce_ptr=nullptr;
    vector<uint8_t> local_nonce(SWITCH_SPDM_REQ_NONCE_SIZE, 0);
    if (nonce != nullptr) {
        cpp_nonce_ptr = nvat_nonce_to_cpp(nonce);
    } else {
        Error err = generate_nonce(local_nonce);
        if (err != Error::Ok) {
            LOG_ERROR("Failed to generate nonce of " << SWITCH_SPDM_REQ_NONCE_SIZE << " bytes");
            return nvat_rc_from_cpp(err);
        }
        cpp_nonce_ptr = &local_nonce;
    }

    std::vector<std::shared_ptr<SwitchEvidence>> cpp_collection;
    Error error = cpp_source->get_evidence(*cpp_nonce_ptr, cpp_collection);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to collect nvswitch evidence");
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
    auto json_string = make_unique<std::string>();
    Error err = SwitchEvidence::collection_to_json(cpp_collection, *json_string);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to serialize switch evidence as JSON");
        return nvat_rc_from_cpp(err);
    }
    *out_serialized_evidence = nvat_str_from_cpp(json_string.release());
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
    auto json_string = make_unique<std::string>();
    Error err = cpp_claims->serialize_json(*json_string);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to serialize claims as JSON");
        return nvat_rc_from_cpp(err);
    }
    *out_serialized_claims = nvat_str_from_cpp(json_string.release());
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
    auto json_string = make_unique<std::string>();
    Error err = cpp_claims->serialize_json(*json_string);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to serialize claims as JSON");
        return nvat_rc_from_cpp(err);
    }
    *out_serialized_claims = nvat_str_from_cpp(json_string.release());
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

    DetachedEATOptions cpp_options = DetachedEATOptions();
    if (options != nullptr) {
        cpp_options = *nvat_detached_eat_options_to_cpp(options);
    }

    auto detached_eat = make_unique<std::string>();
    Error err = cpp_claims->get_detached_eat(*detached_eat, cpp_options);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to get detached EAT");
        return nvat_rc_from_cpp(err);
    }
    *out_detached_eat = nvat_str_from_cpp(detached_eat.release());
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

void nvat_evidence_policy_set_verify_rim_signature(nvat_evidence_policy_t policy, bool verify_rim_signature) {
    NVAT_C_API_BEGIN
    if (policy == nullptr) {
        return;
    }
    EvidencePolicy* cpp_policy = nvat_evidence_policy_to_cpp(policy);
    cpp_policy->verify_rim_signature = verify_rim_signature;
    NVAT_C_API_END_VOID
}

void nvat_evidence_policy_set_verify_rim_cert_chain(nvat_evidence_policy_t policy, bool verify_rim_cert_chain) {
    NVAT_C_API_BEGIN
    if (policy == nullptr) {
        return;
    }
    EvidencePolicy* cpp_policy = nvat_evidence_policy_to_cpp(policy);
    cpp_policy->verify_rim_cert_chain = verify_rim_cert_chain;
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

nvat_rc_t nvat_gpu_nras_verifier_create(nvat_gpu_nras_verifier_t* out_verifier, const char* base_url, const char* service_key, const nvat_http_options_t http_options) {
    NVAT_C_API_BEGIN
    if (out_verifier == nullptr) {
        LOG_ERROR("out_verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    
    HttpOptions cpp_http_options{};
    if (http_options != nullptr) {
        cpp_http_options = *nvat_http_options_to_cpp(http_options);
    }
    const std::string cpp_service_key = service_key != nullptr ? std::string(service_key) : "";
    NvRemoteGpuVerifier verifier;
    Error err = NvRemoteGpuVerifier::init_from_env(verifier, base_url, cpp_service_key, cpp_http_options);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to create NRAS client");
        return nvat_rc_from_cpp(err);
    }

    auto verifier_ptr = make_unique<NvRemoteGpuVerifier>(std::move(verifier));
    *out_verifier = nvat_gpu_nras_verifier_from_cpp(verifier_ptr.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_switch_nras_verifier_create(nvat_switch_nras_verifier_t* out_verifier, const char* base_url, const char* service_key, const nvat_http_options_t http_options) {
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
    const std::string cpp_service_key = service_key != nullptr ? std::string(service_key) : "";
    Error err = NvRemoteSwitchVerifier ::init_from_env(verifier, base_url, cpp_service_key, cpp_http_options);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to create NRAS client");
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
        LOG_ERROR("Failed to create local GPU verifier");
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
        LOG_ERROR("Failed to create local switch verifier");
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
    if (err == Error::Ok || err == Error::OverallResultFalse) {
        auto claims_ptr = make_unique<ClaimsCollection>(std::move(cpp_claims));
        *out_claims = nvat_claims_collection_from_cpp(claims_ptr.release());
        if (out_detached_eat != nullptr) {
            *out_detached_eat = nvat_str_from_cpp(new std::string(cpp_detached_eat_str));
        }
        return nvat_rc_from_cpp(err);
    }

    LOG_ERROR("failed to verify GPU evidence");
    return nvat_rc_from_cpp(err);

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
    if (err == Error::Ok || err == Error::OverallResultFalse) {
        auto claims_ptr = make_unique<ClaimsCollection>(std::move(cpp_claims));
        *out_claims = nvat_claims_collection_from_cpp(claims_ptr.release());
        if (out_detached_eat != nullptr) {
            *out_detached_eat = nvat_str_from_cpp(new std::string(cpp_detached_eat_str));
        }
        return nvat_rc_from_cpp(err);
    }
    
    LOG_ERROR("failed to verify switch evidence");
    return nvat_rc_from_cpp(err);

    return NVAT_RC_OK;
    NVAT_C_API_END
}

// === V2 Input + Local CoRIM Verifier ===

static Error cmw_format_from_c(nvat_cmw_format_t format, CmwFormat& out_format) {
    switch (format) {
    case NVAT_CMW_FORMAT_CBOR:
        out_format = CmwFormat::kCbor;
        return Error::Ok;
    case NVAT_CMW_FORMAT_JSON:
        out_format = CmwFormat::kJson;
        return Error::Ok;
    default:
        LOG_ERROR("Invalid CMW format: " << static_cast<int>(format));
        return Error::BadArgument;
    }
}

nvat_rc_t nvat_cmw_collection_create_from_gpu_evidence(
    nvat_cmw_collection_t* out,
    const nvat_gpu_evidence_t* gpu_evidence_array,
    size_t num_evidences,
    const nvat_nonce_t nonce
) {
    NVAT_C_API_BEGIN
    if (out == nullptr) {
        LOG_ERROR("out is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (gpu_evidence_array == nullptr || num_evidences == 0) {
        LOG_ERROR("gpu_evidence_array is null or empty");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (nonce == nullptr) {
        LOG_ERROR("nonce is null");
        return NVAT_RC_BAD_ARGUMENT;
    }

    auto cmw = make_unique<CmwCollection>();
    cmw->set_nonce(*nvat_nonce_to_cpp(nonce));

    for (size_t i = 0; i < num_evidences; ++i) {
        if (gpu_evidence_array[i] == nullptr) {
            LOG_ERROR("gpu_evidence_array[" << i << "] is null");
            return NVAT_RC_BAD_ARGUMENT;
        }
        const auto& evidence = **nvat_gpu_evidence_to_cpp(gpu_evidence_array[i]);
        const std::vector<uint8_t>& spdm_bytes = evidence.get_attestation_report();
        const std::string& cert_pem = evidence.get_attestation_cert_chain();

        CmwEvidenceItem item;
        item.nonce = *nvat_nonce_to_cpp(nonce);
        item.evidence = CmwRecord(kCmwMediaSpdmTranscript, spdm_bytes);
        item.certificate = std::unique_ptr<CmwRecord>(new CmwRecord(
            kCmwMediaPemCertChain,
            std::vector<uint8_t>(cert_pem.begin(), cert_pem.end())));
        cmw->add_evidence_item("gpu_" + std::to_string(i), std::move(item));
    }
    *out = nvat_cmw_collection_from_cpp(cmw.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_cmw_collection_create_from_spdm_transcript(
    nvat_cmw_collection_t* out,
    const char* label,
    const uint8_t* transcript,
    size_t transcript_len,
    const uint8_t* cert_pem,
    size_t cert_pem_len,
    const nvat_nonce_t nonce
) {
    NVAT_C_API_BEGIN
    if (out == nullptr) {
        LOG_ERROR("out is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (label == nullptr) {
        LOG_ERROR("label is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (transcript == nullptr || transcript_len == 0) {
        LOG_ERROR("transcript is null or empty");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (cert_pem == nullptr || cert_pem_len == 0) {
        LOG_ERROR("cert_pem is null or empty");
        return NVAT_RC_BAD_ARGUMENT;
    }

    auto cmw = make_unique<CmwCollection>();
    std::vector<uint8_t> nonce_bytes;
    if (nonce != nullptr) {
        nonce_bytes = *nvat_nonce_to_cpp(nonce);
        cmw->set_nonce(nonce_bytes);
    }

    CmwEvidenceItem item;
    if (nonce != nullptr) {
        item.nonce = nonce_bytes;
    }
    item.evidence = CmwRecord(kCmwMediaSpdmTranscript,
                              std::vector<uint8_t>(transcript,
                                                   transcript + transcript_len));
    item.certificate = std::unique_ptr<CmwRecord>(new CmwRecord(
        kCmwMediaPemCertChain,
        std::vector<uint8_t>(cert_pem, cert_pem + cert_pem_len)));
    cmw->add_evidence_item(label, std::move(item));

    *out = nvat_cmw_collection_from_cpp(cmw.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_cmw_collection_create_from_eat(
    nvat_cmw_collection_t* out,
    const char* label,
    const uint8_t* signed_cwt,
    size_t signed_cwt_len,
    const nvat_nonce_t nonce
) {
    NVAT_C_API_BEGIN
    if (out == nullptr) {
        LOG_ERROR("out is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (label == nullptr) {
        LOG_ERROR("label is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (signed_cwt == nullptr || signed_cwt_len == 0) {
        LOG_ERROR("signed_cwt is null or empty");
        return NVAT_RC_BAD_ARGUMENT;
    }

    auto cmw = make_unique<CmwCollection>();
    std::vector<uint8_t> nonce_bytes;
    if (nonce != nullptr) {
        nonce_bytes = *nvat_nonce_to_cpp(nonce);
        cmw->set_nonce(nonce_bytes);
    }

    CmwEvidenceItem item;
    if (nonce != nullptr) {
        item.nonce = nonce_bytes;
    }
    item.evidence = CmwRecord(kCmwMediaEatCwt,
                              std::vector<uint8_t>(signed_cwt,
                                                   signed_cwt + signed_cwt_len));
    cmw->add_evidence_item(label, std::move(item));

    *out = nvat_cmw_collection_from_cpp(cmw.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_cmw_collection_serialize(
    const nvat_cmw_collection_t cmw,
    nvat_cmw_format_t format,
    nvat_str_t* out_serialized
) {
    NVAT_C_API_BEGIN
    if (cmw == nullptr || out_serialized == nullptr) {
        LOG_ERROR("cmw or out_serialized is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_cmw = nvat_cmw_collection_to_cpp(cmw);
    CmwFormat cpp_format{};
    Error err = cmw_format_from_c(format, cpp_format);
    if (err != Error::Ok) {
        return nvat_rc_from_cpp(err);
    }
    std::vector<uint8_t> serialized;
    err = cpp_cmw->serialize(cpp_format, serialized);
    if (err != Error::Ok) {
        return nvat_rc_from_cpp(err);
    }
    auto out_str =
        make_unique<std::string>(serialized.begin(), serialized.end());
    *out_serialized = nvat_str_from_cpp(out_str.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_corim_store_create(
    nvat_corim_store_t* out_store,
    const char* service_key,
    const nvat_http_options_t http_options
) {
    NVAT_C_API_BEGIN
    if (out_store == nullptr) {
        LOG_ERROR("out_store is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    HttpOptions cpp_http_options{};
    if (http_options != nullptr) {
        cpp_http_options = *nvat_http_options_to_cpp(http_options);
    }
    std::string cpp_service_key =
        service_key != nullptr ? std::string(service_key) : "";
    auto store = make_unique<CorimStore>(std::move(cpp_http_options),
                                         std::move(cpp_service_key));
    *out_store = nvat_corim_store_from_cpp(store.release());
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_corim_store_add_url_rewrite(
    nvat_corim_store_t store,
    const char* pattern,
    const char* replacement
) {
    NVAT_C_API_BEGIN
    if (store == nullptr || pattern == nullptr || replacement == nullptr) {
        LOG_ERROR("store, pattern, or replacement is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    Error err = nvat_corim_store_to_cpp(store)->add_url_rewrite(
        std::string(pattern), std::string(replacement));
    return nvat_rc_from_cpp(err);
    NVAT_C_API_END
}

nvat_rc_t nvat_corim_store_add_allowed_url_prefix(
    nvat_corim_store_t store,
    const char* prefix
) {
    NVAT_C_API_BEGIN
    if (store == nullptr || prefix == nullptr) {
        LOG_ERROR("store or prefix is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    Error err = nvat_corim_store_to_cpp(store)->add_allowed_url_prefix(
        std::string(prefix));
    return nvat_rc_from_cpp(err);
    NVAT_C_API_END
}

nvat_rc_t nvat_corim_store_enable_in_memory_cache(
    nvat_corim_store_t store,
    uint64_t           max_size_bytes,
    time_t             ttl_seconds
) {
    NVAT_C_API_BEGIN
    if (store == nullptr) {
        LOG_ERROR("store is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (max_size_bytes == 0) {
        LOG_ERROR("max_size_bytes must be > 0");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (ttl_seconds < 0) {
        LOG_ERROR("ttl_seconds must be >= 0");
        return NVAT_RC_BAD_ARGUMENT;
    }
    nvat_corim_store_to_cpp(store)->enable_in_memory_cache(max_size_bytes, ttl_seconds);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_local_corim_verifier_create(
    nvat_local_corim_verifier_t* out_verifier,
    nvat_corim_store_t* corim_store,
    nvat_ocsp_client_t ocsp_client
) {
    NVAT_C_API_BEGIN
    if (out_verifier == nullptr || corim_store == nullptr || *corim_store == nullptr) {
        LOG_ERROR("out_verifier or corim_store is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    std::shared_ptr<IOcspHttpClient> cpp_ocsp;
    if (ocsp_client != nullptr) {
        cpp_ocsp = *nvat_ocsp_client_to_cpp(ocsp_client);
    }
    auto verifier = make_unique<LocalCorimVerifier>(
        std::move(*nvat_corim_store_to_cpp(*corim_store)), std::move(cpp_ocsp));
    *out_verifier = nvat_local_corim_verifier_from_cpp(verifier.release());
    nvat_corim_store_free(corim_store);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_local_corim_verifier_verify_cmw(
    const nvat_local_corim_verifier_t verifier,
    const uint8_t* cmw_data,
    size_t cmw_len,
    nvat_cmw_format_t format,
    nvat_ear_signing_options_t ear_signing_options,
    nvat_str_t* out_ear_jwt,
    nvat_str_t* out_ear_json
) {
    NVAT_C_API_BEGIN
    if (verifier == nullptr) {
        LOG_ERROR("verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (cmw_data == nullptr) {
        LOG_ERROR("cmw_data is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_verifier = nvat_local_corim_verifier_to_cpp(verifier);
    CmwFormat cpp_format{};
    Error err = cmw_format_from_c(format, cpp_format);
    if (err != Error::Ok) {
        return nvat_rc_from_cpp(err);
    }

    const DetachedEATOptions* cpp_options_ptr = nullptr;
    if (ear_signing_options != nullptr) {
        cpp_options_ptr = nvat_detached_eat_options_to_cpp(ear_signing_options);
    }

    CorimAttestationResult result{};
    std::string ear_jwt;
    std::string* ear_jwt_ptr = (out_ear_jwt != nullptr) ? &ear_jwt : nullptr;
    std::string ear_json;
    std::string* ear_json_ptr = (out_ear_json != nullptr) ? &ear_json : nullptr;
    err = cpp_verifier->verify_cmw(cmw_data, cmw_len, cpp_format, result,
                                   cpp_options_ptr, ear_jwt_ptr, ear_json_ptr);
    if (err == Error::Ok && out_ear_jwt != nullptr) {
        auto serialized = make_unique<std::string>(std::move(ear_jwt));
        *out_ear_jwt = nvat_str_from_cpp(serialized.release());
    }
    if (err == Error::Ok && out_ear_json != nullptr) {
        auto serialized = make_unique<std::string>(std::move(ear_json));
        *out_ear_json = nvat_str_from_cpp(serialized.release());
    }
    return nvat_rc_from_cpp(err);
    NVAT_C_API_END
}

nvat_rc_t nvat_local_corim_verifier_set_verify_rim_signature(
    nvat_local_corim_verifier_t verifier,
    bool enabled
) {
    NVAT_C_API_BEGIN
    if (verifier == nullptr) {
        LOG_ERROR("verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_verifier = nvat_local_corim_verifier_to_cpp(verifier);
    cpp_verifier->set_verify_rim_signature(enabled);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_local_corim_verifier_set_verify_coev_signature(
    nvat_local_corim_verifier_t verifier,
    bool enabled
) {
    NVAT_C_API_BEGIN
    if (verifier == nullptr) {
        LOG_ERROR("verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_verifier = nvat_local_corim_verifier_to_cpp(verifier);
    cpp_verifier->set_verify_coev_signature(enabled);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_local_corim_verifier_set_verify_evidence_signature(
    nvat_local_corim_verifier_t verifier,
    bool enabled
) {
    NVAT_C_API_BEGIN
    if (verifier == nullptr) {
        LOG_ERROR("verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_verifier = nvat_local_corim_verifier_to_cpp(verifier);
    cpp_verifier->set_verify_evidence_signature(enabled);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_local_corim_verifier_set_verify_revocation(
    nvat_local_corim_verifier_t verifier,
    bool enabled
) {
    NVAT_C_API_BEGIN
    if (verifier == nullptr) {
        LOG_ERROR("verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_verifier = nvat_local_corim_verifier_to_cpp(verifier);
    cpp_verifier->set_verify_revocation(enabled);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_local_corim_verifier_set_backup_spdm_coev(
    nvat_local_corim_verifier_t verifier,
    const uint8_t* coev_data,
    size_t coev_len
) {
    NVAT_C_API_BEGIN
    if (verifier == nullptr) {
        LOG_ERROR("verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_verifier = nvat_local_corim_verifier_to_cpp(verifier);
    return nvat_rc_from_cpp(cpp_verifier->set_backup_spdm_coev(coev_data, coev_len));
    NVAT_C_API_END
}

nvat_rc_t nvat_local_corim_verifier_add_backup_rim_locator(
    nvat_local_corim_verifier_t verifier,
    const char* uri
) {
    NVAT_C_API_BEGIN
    if (verifier == nullptr) {
        LOG_ERROR("verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (uri == nullptr || *uri == '\0') {
        LOG_ERROR("uri is null or empty");
        return NVAT_RC_BAD_ARGUMENT;
    }
    auto* cpp_verifier = nvat_local_corim_verifier_to_cpp(verifier);
    cpp_verifier->add_backup_rim_locator(uri);
    return NVAT_RC_OK;
    NVAT_C_API_END
}

nvat_rc_t nvat_local_corim_verifier_set_default_hash_algorithms(
    nvat_local_corim_verifier_t verifier,
    const nvat_hash_algorithm_t* algs,
    size_t num_algs
) {
    NVAT_C_API_BEGIN
    if (verifier == nullptr) {
        LOG_ERROR("verifier is null");
        return NVAT_RC_BAD_ARGUMENT;
    }
    if (num_algs > 0 && algs == nullptr) {
        LOG_ERROR("algs is null but num_algs > 0");
        return NVAT_RC_BAD_ARGUMENT;
    }
    std::vector<HashAlgorithm> cpp_algs;
    cpp_algs.reserve(num_algs);
    for (size_t i = 0; i < num_algs; ++i) {
        switch (algs[i]) {
            case NVAT_HASH_ALGORITHM_SHA256: cpp_algs.push_back(HashAlgorithm::Sha256); break;
            case NVAT_HASH_ALGORITHM_SHA384: cpp_algs.push_back(HashAlgorithm::Sha384); break;
            case NVAT_HASH_ALGORITHM_SHA512: cpp_algs.push_back(HashAlgorithm::Sha512); break;
            default:
                LOG_ERROR("unknown hash algorithm: " << algs[i]);
                return NVAT_RC_BAD_ARGUMENT;
        }
    }
    auto* cpp_verifier = nvat_local_corim_verifier_to_cpp(verifier);
    cpp_verifier->set_default_hash_algorithms(std::move(cpp_algs));
    return NVAT_RC_OK;
    NVAT_C_API_END
}

} // extern "C"
