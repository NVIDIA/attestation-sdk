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

#pragma once

#include <string>
#include <unordered_map>

#include "nv_attestation/error.h"
#include "nv_attestation/nv_http.h"
#include "nlohmann/json.hpp"

namespace nvattestation {

class Jwk {
public:
    std::string kid;
    std::string pem_public_key;
};

class JwkStore {
public:
    static const long long DEFAULT_JWKS_CACHE_DURATION_MS = 900000; // 15 minutes

    JwkStore() {}
    static Error init_from_env(
        std::shared_ptr<JwkStore>& jwk_store,
        const std::string& jwks_url,
        HttpOptions http_options,
        long long cache_duration_ms = DEFAULT_JWKS_CACHE_DURATION_MS
    );
    ~JwkStore() = default;
    Error get_jwk_by_kid(const std::string& kid, Jwk& out_jwk);
private:
    std::mutex m_lock;
    std::string m_jwks_url;
    long long m_cache_duration_ms; // max time to retain the JWK set
    long long m_last_update_unix_ms; // last time cache was updated, as a unix timestamp
    std::unordered_map<std::string, Jwk> m_jwks;
    NvHttpClient m_http_client;

    Error refresh_jwks();
};


class NvJwt {
public:
    static Error validate_and_decode(
        const std::string &jwt_token,
        std::shared_ptr<JwkStore>& jwk_store,
        std::string &eat_issuer,
        std::string &out_payload
    );
};

} // namespace nvattestation