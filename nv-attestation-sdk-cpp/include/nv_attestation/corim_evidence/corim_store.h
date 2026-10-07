/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "nv_attestation/error.h"
#include "nv_attestation/nv_cache.h"
#include "nv_attestation/nv_http.h"

namespace nvattestation {

// Fetches a CoRIM body from a rim-locator URL.
//
// Raw (evidence-supplied) URLs must match an allowlist prefix before any
// rewrite runs. Rewrites redirect allowed prefixes to mirrors or file://
// fixtures. An optional INvCache deduplicates fetches within a session;
// the cache key is the effective URL after rewrites.
class CorimStore {
  public:
    // Seeds the allowlist with the NVIDIA RIM prefix.
    CorimStore();
    CorimStore(HttpOptions http_options, std::string service_key = {});

    Error add_allowed_url_prefix(std::string prefix);

    // Tries rules in insertion order; first prefix match wins.
    // PATTERN and REPLACEMENT must agree on a trailing '/'.
    Error add_url_rewrite(std::string pattern, std::string replacement);

    // Installs the default in-memory LRU+TTL cache backend.
    void enable_in_memory_cache(uint64_t max_size_bytes, time_t ttl_seconds);

    // Injects any INvCache implementation (useful for testing or custom backends).
    void set_cache(std::shared_ptr<INvCache> cache);

    // out_effective_url (optional) receives the post-rewrite URL, even on error.
    // A thin wrapper over fetch_impl() that discards any CoEV payload.
    Error fetch(const std::string &url,
                std::vector<uint8_t> &out_bytes,
                std::string *out_effective_url = nullptr) const;

    // Surfaces a CoEV payload (and sha256) from a RIM-service JSON envelope,
    // when present. Absent otherwise -- no coev field, file://, or raw CBOR/COSE.
    Error fetch_with_coev(const std::string &url,
                           std::vector<uint8_t> &out_corim_bytes,
                           std::vector<uint8_t> &out_coev_bytes,
                           bool &out_coev_present,
                           std::string &out_coev_sha256,
                           std::string *out_effective_url = nullptr) const;

  private:
    friend class LocalCorimVerifier;

    // Checks the raw URL against the allowlist and applies the first
    // matching rewrite rule. Shared by fetch() and fetch_with_coev().
    Error resolve_and_authorize(const std::string &url,
                                 std::string &out_effective) const;

    // Shared implementation behind fetch()/fetch_with_coev(). Caches CoRIM and
    // CoEV together so a cache hit can't hide a CoEV a live GET would surface.
    Error fetch_impl(const std::string &url,
                      std::vector<uint8_t> &out_corim_bytes,
                      std::vector<uint8_t> &out_coev_bytes,
                      bool &out_coev_present,
                      std::string &out_coev_sha256,
                      std::string *out_effective_url) const;

    std::vector<std::string> m_allowed_prefixes;
    std::vector<std::pair<std::string, std::string>> m_rewrites;
    HttpOptions m_http_options;
    NvHttpClient m_http_client;
    std::shared_ptr<INvCache> m_cache;
};

} // namespace nvattestation
