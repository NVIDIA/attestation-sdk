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

    Error NvJwt::validate_and_decode(const std::string &jwt_token, std::shared_ptr<JwkStore>& jwk_store, std::string &eat_issuer, std::string &out_payload) {
        auto decoded_jwt = jwt::decode<jwt::traits::nlohmann_json>(jwt_token);
        nlohmann::json decoded_header;
        nlohmann::json decoded_payload;
        std::string kid;
        std::string issuer;
        try {
            decoded_header = nlohmann::json::parse(decoded_jwt.get_header());
            decoded_payload = nlohmann::json::parse(decoded_jwt.get_payload());
            kid = decoded_header.at("kid");
            issuer = decoded_payload.at("iss");
        } catch (const nlohmann::json::exception& e) {
            LOG_ERROR("JSON parsing error: " << e.what());
            LOG_DEBUG("JWT token: " << jwt_token);
            return Error::NrasTokenInvalid;
        }

        if (issuer != eat_issuer) {
            LOG_ERROR("Issuer mismatch: " << issuer << " != " << eat_issuer);
            return Error::NrasTokenInvalid;
        }

        Jwk jwk;
        Error err = jwk_store->get_jwk_by_kid(kid, jwk);
        if (err != Error::Ok) {
            return err;
        }

        LOG_DEBUG("Verifying signature of NRAS token");
        auto verifier = jwt::verify<jwt::traits::nlohmann_json>()
            .allow_algorithm(jwt::algorithm::es384(jwk.pem_public_key));
        try {
            verifier.verify(decoded_jwt);
        } catch (const std::exception& e) {
            LOG_ERROR("Signature verification error: " << e.what());
            return Error::NrasTokenInvalid;
        } catch (...) {
            LOG_ERROR("Signature verification error");
            return Error::NrasTokenInvalid;
        }

        out_payload = decoded_jwt.get_payload();

        return Error::Ok;
    }

    Error JwkStore::init_from_env(std::shared_ptr<JwkStore>& jwk_store, const std::string& jwks_url, HttpOptions http_options, long long cache_duration_ms) {
        jwk_store->m_jwks_url = jwks_url;
        jwk_store->m_last_update_unix_ms = 0;
        jwk_store->m_cache_duration_ms = cache_duration_ms;
        Error err = NvHttpClient::create(jwk_store->m_http_client, http_options);
        if (err != Error::Ok) {
            return err;
        }
        return Error::Ok;
    }

    Error JwkStore::get_jwk_by_kid(const std::string& kid, Jwk& out_jwk) {
        std::lock_guard<std::mutex> lock{m_lock};
        auto now_ms = time_since_epoch_ms();
        auto cache_expired = m_last_update_unix_ms + m_cache_duration_ms < now_ms;
        auto cache_miss = m_jwks.count(kid) < 1;
        LOG_DEBUG("Fetching JWK with kid: " << kid);
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
            LOG_ERROR("No JWK found for kid: " << kid);
            return Error::CertNotFound;
        }
        out_jwk = m_jwks.at(kid);
        return Error::Ok;
    }

    Error JwkStore::refresh_jwks() {
        // assumes we already have the lock
        const size_t PEM_LINE_LENGTH = 64;
        
        NvRequest request(m_jwks_url, NvHttpMethod::HTTP_METHOD_GET);
        long status = 0;
        std::string response;
        Error error = m_http_client.do_request_as_string(request, status, response);
        if (error != Error::Ok) {
            return error;
        }
        nlohmann::json jwks_response;
        error = deserialize_from_json<nlohmann::json>(response, jwks_response);
        if (error != Error::Ok) {
            return error;
        }
        nlohmann::json keys;
        if(jwks_response.contains("keys")) {
            keys = jwks_response["keys"];
        } else {
            LOG_ERROR("No keys found in JWKS response");
            return Error::NrasAttestationError;
        }

        LOG_DEBUG(keys.size() << " keys in JWKS response");
        for (const auto& key : keys) {
            if (!key.contains("kid") || !key["kid"].is_string()) {
                continue;
            }
            if (!key.contains("x5c") || !key["x5c"].is_array() || key["x5c"].empty()) {
                continue;
            }
            std::string kid = key["kid"];
            std::string raw_public_key = key["x5c"][0].get<std::string>();
            std::string wrapped_public_key = "-----BEGIN CERTIFICATE-----\n";
            // PEM format requires base64 data to be broken into lines of 64 characters
            for (size_t i = 0; i < raw_public_key.size(); i += PEM_LINE_LENGTH) {
                wrapped_public_key += raw_public_key.substr(i, PEM_LINE_LENGTH) + "\n";
            }
            wrapped_public_key += "-----END CERTIFICATE-----\n";
            m_jwks[kid] = Jwk{kid, wrapped_public_key};
        }
        return Error::Ok;
    }
    
}