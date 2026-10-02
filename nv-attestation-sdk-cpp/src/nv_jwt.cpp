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

#include <chrono>
#include <jwt-cpp/jwt.h>
#include "jwt-cpp/traits/nlohmann-json/traits.h"

#include <mutex>
#include <nlohmann/json.hpp>
#include "nv_attestation/nv_jwt.h"
#include "nv_attestation/nv_http.h"
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/nv_x509.h"

namespace nvattestation {

    namespace {
        struct FixedClock {
            std::chrono::system_clock::time_point current_time;
            std::chrono::system_clock::time_point now() const {
                return current_time;
            }
        };

        void log_time_failure(
            const jwt::decoded_jwt<jwt::traits::nlohmann_json>& token,
            std::chrono::system_clock::time_point now,
            std::size_t leeway_seconds) {
            const auto leeway = std::chrono::seconds(leeway_seconds);
            // jwt-cpp reports expired, future-issued, and not-yet-valid claims
            // with one error; inspect signed claims for an actionable diagnostic.
            if (token.has_expires_at() && now > token.get_expires_at() + leeway) {
                LOG_ERROR("JWT expired");
            } else if (token.has_not_before() &&
                       now < token.get_not_before() - leeway) {
                LOG_ERROR("JWT not yet valid (nbf)");
            } else if (token.has_issued_at() &&
                       now < token.get_issued_at() - leeway) {
                LOG_ERROR("JWT issued in the future (iat)");
            } else {
                LOG_ERROR("JWT time-claim validation failed");
            }
        }
    }

    Error NvJwt::validate_and_decode(
        const std::string& jwt_token,
        const Jwk& jwk,
        const JwtValidationOptions& options,
        const std::string& expected_issuer,
        Error invalid_token_error,
        bool require_nonempty_kid,
        std::chrono::system_clock::time_point now,
        std::string& out_payload) {
        out_payload.clear();
        try {
            auto decoded_jwt =
                jwt::decode<jwt::traits::nlohmann_json>(jwt_token);
            const auto decoded_header =
                nlohmann::json::parse(decoded_jwt.get_header());
            const auto decoded_payload =
                nlohmann::json::parse(decoded_jwt.get_payload());
            if (!decoded_header.is_object() || !decoded_payload.is_object()) {
                return invalid_token_error;
            }

            const auto& algorithm = decoded_header.at("alg");
            const auto& kid_claim = decoded_header.at("kid");
            const auto& issuer_claim = decoded_payload.at("iss");
            if (!algorithm.is_string() ||
                algorithm.get_ref<const std::string&>() != "ES384" ||
                !kid_claim.is_string() ||
                (require_nonempty_kid &&
                 kid_claim.get_ref<const std::string&>().empty()) ||
                !issuer_claim.is_string() ||
                issuer_claim.get_ref<const std::string&>() !=
                    expected_issuer) {
                return invalid_token_error;
            }

            LOG_DEBUG("Verifying JWT signature");
            auto verifier = jwt::verify<FixedClock, jwt::traits::nlohmann_json>(
                                FixedClock{now})
                .leeway(options.clock_skew_leeway_seconds)
                .allow_algorithm(jwt::algorithm::es384(jwk.pem_public_key));
            std::error_code verification_error;
            verifier.verify(decoded_jwt, verification_error);
            if (verification_error) {
                if (verification_error ==
                    jwt::error::token_verification_error::token_expired) {
                    log_time_failure(
                        decoded_jwt, now,
                        options.clock_skew_leeway_seconds);
                } else {
                    LOG_ERROR("JWT signature or claim validation failed");
                }
                return invalid_token_error;
            }

            out_payload = decoded_jwt.get_payload();
            return Error::Ok;
        } catch (const std::exception&) {
            LOG_ERROR("JWT validation error");
            return invalid_token_error;
        } catch (...) {
            LOG_ERROR("JWT validation error");
            return invalid_token_error;
        }
    }

    Error NvJwt::validate_and_decode(
        const std::string& jwt_token,
        std::shared_ptr<JwkStore>& jwk_store,
        const std::string& expected_issuer,
        std::string& out_payload,
        const JwtValidationOptions& options,
        Error invalid_token_error,
        bool require_nonempty_kid,
        std::chrono::system_clock::time_point now) {
        out_payload.clear();
        try {
            const auto decoded_jwt =
                jwt::decode<jwt::traits::nlohmann_json>(jwt_token);
            const auto decoded_header =
                nlohmann::json::parse(decoded_jwt.get_header());
            const auto decoded_payload =
                nlohmann::json::parse(decoded_jwt.get_payload());
            if (!decoded_header.is_object() || !decoded_payload.is_object()) {
                return invalid_token_error;
            }
            const auto& algorithm = decoded_header.at("alg");
            const auto& kid_claim = decoded_header.at("kid");
            const auto& issuer_claim = decoded_payload.at("iss");
            if (!algorithm.is_string() ||
                algorithm.get_ref<const std::string&>() != "ES384" ||
                !kid_claim.is_string() ||
                (require_nonempty_kid &&
                 kid_claim.get_ref<const std::string&>().empty()) ||
                !issuer_claim.is_string() ||
                issuer_claim.get_ref<const std::string&>() != expected_issuer) {
                return invalid_token_error;
            }

            Jwk jwk;
            const Error err = jwk_store->get_jwk_by_kid(
                kid_claim.get_ref<const std::string&>(), jwk);
            if (err != Error::Ok) {
                return err;
            }
            return validate_and_decode(
                jwt_token, jwk, options, expected_issuer, invalid_token_error,
                require_nonempty_kid, now, out_payload);
        } catch (const std::exception&) {
            LOG_ERROR("JWT validation error");
            return invalid_token_error;
        } catch (...) {
            LOG_ERROR("JWT validation error");
            return invalid_token_error;
        }
    }

    Error JwkStore::init_from_env(std::shared_ptr<JwkStore>& jwk_store, const std::string& jwks_url, const std::string& service_key, const HttpOptions& http_options, long long cache_duration_ms) {
        jwk_store->m_jwks_url = jwks_url;
        jwk_store->m_last_update_unix_ms = 0;
        jwk_store->m_cache_duration_ms = cache_duration_ms;
        Error err = NvHttpClient::create(jwk_store->m_http_client, service_key, http_options);
        if (err != Error::Ok) {
            return err;
        }
        return Error::Ok;
    }

    Error JwkStore::create_from_issuer(std::shared_ptr<JwkStore>& jwk_store, const std::string& issuer, const std::string& service_key, const HttpOptions& http_options, long long cache_duration_ms) {
        jwk_store = std::make_shared<JwkStore>();
        return init_from_env(
            jwk_store, issuer + "/.well-known/jwks.json", service_key,
            http_options, cache_duration_ms);
    }

    Error JwkStore::get_jwk_by_kid(const std::string& kid, Jwk& out_jwk) {
        std::lock_guard<std::mutex> lock{m_lock};
        auto now_ms = time_since_epoch_ms();
        auto cache_expired = m_last_update_unix_ms + m_cache_duration_ms < now_ms;
        auto cache_miss = m_jwks.count(kid) < 1;
        LOG_DEBUG("Fetching JWK by kid");
        if (cache_expired || cache_miss) {
            LOG_DEBUG("Fetching JWK set at " << m_jwks_url);
            m_jwks.clear();
            auto err = refresh_jwks();
            m_last_update_unix_ms = now_ms;
            if (err != Error::Ok) {
                return err;
            }
        } else {
            LOG_DEBUG("JWK set is up to date");
        }
        if (m_jwks.count(kid) < 1) {
            LOG_ERROR("No matching JWK found");
            return Error::CertNotFound;
        }
        out_jwk = m_jwks.at(kid);
        return Error::Ok;
    }

    Error JwkStore::refresh_jwks() {
        // assumes we already have the lock
        const size_t PEM_LINE_LENGTH = 64;

        long status = 0;
        std::string response;
        NvRequest request(m_jwks_url, NvHttpMethod::HTTP_METHOD_GET);
        Error error = m_http_client.do_request_as_string(
            request, status, response);
        if (error != Error::Ok) {
            return error == Error::InternalError ? Error::VerifierJwksError
                                                 : error;
        }
        if (!is_http_status_2xx(status)) {
            return Error::VerifierJwksError;
        }
        const auto jwks_response = nlohmann::json::parse(response, nullptr, false);
        if (jwks_response.is_discarded()) {
            LOG_ERROR("Invalid JWKS response");
            return Error::JsonSerializationError;
        }
        if (!jwks_response.is_object() ||
            !jwks_response.contains("keys") ||
            !jwks_response.at("keys").is_array()) {
            LOG_ERROR("Invalid JWKS response");
            return Error::VerifierJwksError;
        }
        const auto& keys = jwks_response.at("keys");

        // Preserve the legacy JWK path: jwt-cpp validates the certificate when
        // constructing the signature verifier and maps failures as token errors.
        auto wrap_to_pem = [&](const std::string& raw_b64) -> std::string {
            std::string pem = "-----BEGIN CERTIFICATE-----\n";
            for (size_t i = 0; i < raw_b64.size(); i += PEM_LINE_LENGTH) {
                pem += raw_b64.substr(i, PEM_LINE_LENGTH) + "\n";
            }
            pem += "-----END CERTIFICATE-----\n";
            return pem;
        };

        LOG_DEBUG(keys.size() << " keys in JWKS response");
        for (const auto& key : keys) {
            if (!key.contains("kid") || !key["kid"].is_string()) {
                continue;
            }
            if (!key.contains("x5c") || !key["x5c"].is_array() || key["x5c"].empty()) {
                continue;
            }
            std::string kid = key["kid"];
            if (!key["x5c"][0].is_string()) {
                LOG_ERROR("JWKS x5c leaf is not a string; skipping key");
                continue;
            }
            std::string wrapped_public_key =
                wrap_to_pem(key["x5c"][0].get<std::string>());

            if (key["x5c"].size() >= 2) {
                // Verify that the leaf (x5c[0]) is signed by the issuing CA (x5c[1]).
                // This prevents accepting a JWKS key whose stated issuer does not match
                // the actual signing chain.
                if (!key["x5c"][1].is_string()) {
                    LOG_ERROR("JWKS x5c issuer is not a string; skipping key");
                    continue;
                }
                std::string issuer_pem =
                    wrap_to_pem(key["x5c"][1].get<std::string>());
                X509CertChain chain;
                Error chain_err = X509CertChain::create(CertificateChainType::GENERIC, issuer_pem, chain);
                if (chain_err == Error::Ok) {
                    chain_err = chain.push_back(wrapped_public_key);
                }
                if (chain_err == Error::Ok) {
                    // TODO: Decide whether EAR JWKS x5c validation should enforce
                    // certificate validity dates independently of JWT clock skew.
                    chain_err = chain.verify(/*allow_partial_chain=*/true);
                }
                if (chain_err != Error::Ok) {
                    LOG_ERROR("JWKS x5c chain validation failed; skipping key");
                    continue;
                }
            } else {
                LOG_DEBUG("JWKS key has one x5c certificate");
            }

            m_jwks[kid] = Jwk{kid, wrapped_public_key};
        }
        return Error::Ok;
    }
    
}
