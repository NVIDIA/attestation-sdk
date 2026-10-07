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

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include "spdlog/spdlog.h"

#include "ear_status.h"
#include "nvat.h"
#include "nvattest_types.h"
#include "utils.h"
#include "verify_token.h"
#include "verify_token_output.h"

namespace nvattest {

    nlohmann::json VerifyTokenOutput::to_json() const {
        // JSON shaping lives in verify_token_build_json (libnvat-free, so it is
        // unit-tested by the CLI test binary). The result_message comes from
        // nvat_rc_to_string here, in the binary that links libnvat.
        if (ear_output) {
            return verify_token_build_ear_json(
                result_code, nvat_rc_to_string(result_code), ear, include_ear);
        }
        return verify_token_build_json(result_code, nvat_rc_to_string(result_code), claims);
    }

    VerifyTokenOutput VerifyTokenOutput::from_ear(
        nvat_rc_t rc, const std::string& ear, bool include_ear) {
        VerifyTokenOutput output(rc);
        output.ear = ear;
        output.include_ear = include_ear;
        output.ear_output = true;
        return output;
    }

    CLI::App* create_verify_token_subcommand(
        CLI::App& app,
        VerifyTokenOptions& options,
        EvidenceVerificationOptions& verification_options) {

        auto* subcommand = app.add_subcommand("verify-token");
        subcommand->description(
            "Verify a detached EAT (Entity Attestation Token) or signed EAR produced by a previous attestation.\n\n"
            "The token can be read from a file via --token-file, "
            "or piped via stdin. Results are printed to standard out. "
            "Control output format through the global --format option."
        );

        subcommand->add_option("--token-file", options.token_file,
            "Path to a file containing the token. Use \"-\" to read from stdin.")
            ->default_str("");

        subcommand->add_option("--token-type", options.token_type,
            "Token format: detached-eat or ear")
            ->check(CLI::IsMember({"detached-eat", "ear"}))
            ->default_val("detached-eat");

        subcommand->add_option("--clock-skew-leeway-seconds",
            options.clock_skew_leeway_seconds,
            "JWT clock-skew leeway for EAR iat, nbf, and exp time claims; "
            "default 60 seconds; zero means strict validation")
            ->default_val(60);

        subcommand->add_option("--nonce", options.nonce,
            "Expected nonce in hex; if set, the token's eat_nonce must match")
            ->default_str("");

        add_evidence_verification_options(subcommand, verification_options);

        return subcommand;
    }

    int handle_verify_token_subcommand(
        CliLogger& logger,
        const VerifyTokenOptions& options,
        const EvidenceVerificationOptions& verification_options,
        const CommonOptions& common_options) {

        // Emit a VerifyTokenOutput and format/print it once at the end.
        // Helper lambda to finalize output and return the documented exit code.
        auto emit_and_exit = [&](const VerifyTokenOutput& out) -> int {
            if (common_options.format == "json") {
                std::cout << out.to_json().dump(4) << std::endl;
            } else {
                if (!out.claims.empty() && verify_token_result_has_claims(out.result_code)) {
                    std::cout << out.claims << std::endl;
                }
                if (out.include_ear) {
                    std::cout << out.ear << std::endl;
                }
                if (out.result_code == NVAT_RC_OK) {
                    SPDLOG_INFO("Token verification was successful");
                } else {
                    SPDLOG_CRITICAL("Token verification failed!");
                    print_error_help(logger, out.result_code);
                }
            }
            return verify_token_exit_code(out.result_code);
        };

        auto error_output = [&](nvat_rc_t rc) {
            return options.token_type == "ear"
                ? VerifyTokenOutput::from_ear(rc, "", false)
                : VerifyTokenOutput(rc);
        };

        // Read the EAT from --token-file or stdin.
        std::string eat;
        {
            std::istream* source = nullptr;
            std::ifstream token_file_stream;

            if (!options.token_file.empty() && options.token_file != "-") {
                token_file_stream.open(options.token_file);
                if (!token_file_stream) {
                    std::cerr << "Failed to open token file: " << options.token_file << std::endl;
                    return emit_and_exit(error_output(NVAT_RC_BAD_ARGUMENT));
                }
                source = &token_file_stream;
            } else {
                // "--token-file -" or no --token-file: read stdin
                source = &std::cin;
            }

            std::ostringstream ss;
            ss << source->rdbuf();
            eat = ss.str();
        }

        if (options.token_type == "ear") {
            trim_ascii_whitespace(eat);
        }

        if (eat.empty()) {
            SPDLOG_ERROR("No token provided. Use --token-file <path> or pipe via stdin.");
            return emit_and_exit(error_output(NVAT_RC_BAD_ARGUMENT));
        }

        nvat_rc_t err = init_sdk(logger, common_options);
        if (err != NVAT_RC_OK) {
            nvat_sdk_shutdown();
            return emit_and_exit(error_output(err));
        }

        if (options.token_type == "ear") {
            const VerifyTokenOutput output = [&]() {
                nvat_http_options_t http_options_raw = nullptr;
                nv_unique_ptr<nvat_http_options_t> http_options_guard;
                nvat_rc_t ear_err = make_http_options(
                    verification_options, http_options_raw);
                if (ear_err != NVAT_RC_OK) {
                    return error_output(ear_err);
                }
                if (http_options_raw != nullptr) {
                    http_options_guard.reset(&http_options_raw);
                }

                nvat_nonce_t nonce_raw = nullptr;
                nv_unique_ptr<nvat_nonce_t> nonce_guard;
                if (!options.nonce.empty()) {
                    ear_err = nvat_nonce_from_hex(&nonce_raw, options.nonce.c_str());
                    if (ear_err != NVAT_RC_OK) {
                        return error_output(ear_err);
                    }
                    nonce_guard.reset(&nonce_raw);
                }

                nvat_jwt_validation_options_t jwt_options_raw = nullptr;
                nv_unique_ptr<nvat_jwt_validation_options_t> jwt_options;
                ear_err = nvat_jwt_validation_options_create_default(
                    &jwt_options_raw);
                if (ear_err != NVAT_RC_OK) {
                    return error_output(ear_err);
                }
                jwt_options.reset(&jwt_options_raw);
                nvat_jwt_validation_options_set_clock_skew_leeway_seconds(
                    jwt_options_raw, options.clock_skew_leeway_seconds);

                const char* service_key = verification_options.service_key.empty()
                    ? nullptr : verification_options.service_key.c_str();
                nvat_str_t raw_ear = nullptr;
                ear_err = nvat_verify_ear(
                    eat.c_str(), verification_options.nras_url.c_str(), service_key,
                    nonce_raw, http_options_raw, jwt_options_raw, &raw_ear);
                if (ear_err != NVAT_RC_OK) {
                    return error_output(ear_err);
                }
                nv_unique_ptr<nvat_str_t> verified_ear;
                verified_ear.reset(&raw_ear);

                char* ear_data = nullptr;
                ear_err = nvat_str_get_data(raw_ear, &ear_data);
                if (ear_err != NVAT_RC_OK || ear_data == nullptr) {
                    return error_output(
                        ear_err == NVAT_RC_OK ? NVAT_RC_INTERNAL_ERROR : ear_err);
                }

                const std::string ear_json(ear_data);
                const nlohmann::json parsed =
                    nlohmann::json::parse(ear_json, nullptr, false);
                nvat_rc_t final_rc =
                    !parsed.is_discarded() && ear_is_affirming(parsed)
                    ? NVAT_RC_OK
                    : NVAT_RC_OVERALL_RESULT_FALSE;
                if (!verification_options.relying_party_policy.empty()) {
                    nvat_relying_party_policy_t rp_raw = nullptr;
                    ear_err = load_relying_party_policy(
                        verification_options.relying_party_policy, rp_raw);
                    if (ear_err != NVAT_RC_OK) {
                        return VerifyTokenOutput::from_ear(ear_err, ear_json, true);
                    }
                    nv_unique_ptr<nvat_relying_party_policy_t> rp;
                    rp.reset(&rp_raw);
                    const nvat_rc_t policy_rc =
                        nvat_apply_relying_party_policy_to_ear(
                        rp_raw, ear_json.c_str());
                    if (policy_rc != NVAT_RC_OK) {
                        final_rc = policy_rc;
                    }
                }
                return VerifyTokenOutput::from_ear(final_rc, ear_json, true);
            }();
            nvat_sdk_shutdown();
            return emit_and_exit(output);
        }

        // Build http_options from TLS CA settings if provided.
        nvat_http_options_t http_options_raw = nullptr;
        nv_unique_ptr<nvat_http_options_t> http_options_guard;
        err = make_http_options(verification_options, http_options_raw);
        if (err != NVAT_RC_OK) {
            nvat_sdk_shutdown();
            return emit_and_exit(error_output(err));
        }
        if (http_options_raw != nullptr) {
            http_options_guard.reset(&http_options_raw);
        }

        const char* nras_url = verification_options.nras_url.empty() ? nullptr : verification_options.nras_url.c_str();

        // Optional expected nonce: if supplied, the token's eat_nonce must match.
        nvat_nonce_t nonce_raw = nullptr;
        nv_unique_ptr<nvat_nonce_t> nonce_guard;
        if (!options.nonce.empty()) {
            err = nvat_nonce_from_hex(&nonce_raw, options.nonce.c_str());
            if (err != NVAT_RC_OK) {
                nvat_sdk_shutdown();
                return emit_and_exit(error_output(err));
            }
            nonce_guard.reset(&nonce_raw);
        }

        // Optional service key for the JWKS fetch. The public NRAS JWKS endpoint
        // does not require one; only sent if the user supplied --service-key.
        const char* service_key = verification_options.service_key.empty()
            ? nullptr : verification_options.service_key.c_str();

        nvat_claims_collection_t raw_claims = nullptr;
        err = nvat_verify_attestation_result(eat.c_str(), nras_url, service_key,
                                              nonce_raw, http_options_raw,
                                              /*jwt_validation_options=*/nullptr,
                                              &raw_claims);

        // NVAT_RC_OK and NVAT_RC_OVERALL_RESULT_FALSE both yield populated claims.
        if (err != NVAT_RC_OK && err != NVAT_RC_OVERALL_RESULT_FALSE) {
            nvat_sdk_shutdown();
            return emit_and_exit(VerifyTokenOutput(err));
        }
        nv_unique_ptr<nvat_claims_collection_t> claims;
        claims.reset(&raw_claims);

        nvat_rc_t final_rc = err;

        // Apply relying party policy if provided.
        if (!verification_options.relying_party_policy.empty()) {
            nvat_relying_party_policy_t rp_raw = nullptr;
            nvat_rc_t rp_err = load_relying_party_policy(
                verification_options.relying_party_policy, rp_raw);
            if (rp_err != NVAT_RC_OK) {
                nvat_sdk_shutdown();
                return emit_and_exit(VerifyTokenOutput(rp_err));
            }
            nv_unique_ptr<nvat_relying_party_policy_t> rp;
            rp.reset(&rp_raw);

            rp_err = nvat_apply_relying_party_policy(*(rp.get()), *(claims.get()));
            if (rp_err != NVAT_RC_OK) {
                // NVAT_RC_RP_POLICY_MISMATCH: claims are still serialized below.
                final_rc = rp_err;
            }
        }

        // Serialize claims.
        nvat_str_t raw_serialized_claims = nullptr;
        nvat_rc_t ser_err = nvat_claims_collection_serialize_json(*(claims.get()), &raw_serialized_claims);
        if (ser_err != NVAT_RC_OK) {
            nvat_sdk_shutdown();
            return emit_and_exit(VerifyTokenOutput(ser_err));
        }
        nv_unique_ptr<nvat_str_t> serialized_claims;
        serialized_claims.reset(&raw_serialized_claims);

        char* serialized_claims_data = nullptr;
        nvat_rc_t data_err = nvat_str_get_data(*(serialized_claims.get()), &serialized_claims_data);
        if (data_err != NVAT_RC_OK) {
            nvat_sdk_shutdown();
            return emit_and_exit(VerifyTokenOutput(data_err));
        }

        VerifyTokenOutput output(final_rc, std::string(serialized_claims_data));
        nvat_sdk_shutdown();
        return emit_and_exit(output);
    }

} // namespace nvattest
