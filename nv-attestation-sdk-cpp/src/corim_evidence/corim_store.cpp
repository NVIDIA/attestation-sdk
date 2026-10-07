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

#include "nv_attestation/corim_evidence/corim_store.h"

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "nv_attestation/log.h"
#include "nv_attestation/nv_cache.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/utils.h"

namespace nvattestation {

namespace {

constexpr const char *kDefaultAllowedRawUrlPrefix =
    "https://rim.attestation.nvidia.com/";

constexpr const char *kHttpsPrefix = "https://";
constexpr const char *kHttpPrefix = "http://";
constexpr const char *kFilePrefix = "file://";
constexpr const char *kJsonContentType = "application/json";
constexpr const char *kCorimCborContentType = "application/rim+cbor";
constexpr const char *kCorimCoseContentType = "application/rim+cose";

// The RIM service wraps CoRIM (and optional CoEV) as base64 in a JSON
// envelope; other sources serve raw CoRIM bytes, same as a file:// fixture.
Error extract_rim_service_bytes_with_coev(const std::string &effective_url,
                                          const std::string &body,
                                          std::vector<uint8_t> &out_corim_bytes,
                                          std::vector<uint8_t> &out_coev_bytes,
                                          bool &out_coev_present,
                                          std::string &out_coev_sha256) {
    RimResponse rim_response;
    if (deserialize_from_json<RimResponse>(body, rim_response) != Error::Ok) {
        LOG_ERROR("RIM fetch: failed to parse RIM service response from "
                  "effective URL " << effective_url);
        return Error::RimInternalError;
    }
    if (decode_base64(rim_response.rim, out_corim_bytes) != Error::Ok) {
        LOG_ERROR("RIM fetch: failed to base64-decode RIM service response "
                  "from effective URL " << effective_url);
        return Error::RimInternalError;
    }
    out_coev_present = !rim_response.coev.empty();
    if (out_coev_present &&
        decode_base64(rim_response.coev, out_coev_bytes) != Error::Ok) {
        LOG_ERROR("RIM fetch: failed to base64-decode CoEV from effective "
                  "URL " << effective_url);
        return Error::RimInternalError;
    }
    if (out_coev_present) {
        out_coev_sha256 = rim_response.coev_sha256;
    } else {
        out_coev_sha256.clear();
    }
    return Error::Ok;
}

// Stored together so a cache hit can't hide a CoEV a live fetch would surface.
struct CachedRimEntry {
    std::vector<uint8_t> corim_bytes;
    std::vector<uint8_t> coev_bytes;
    bool coev_present = false;
    std::string coev_sha256;
};

Error read_file(const std::string &raw_url, const std::string &effective_url,
                const std::string &path, std::vector<uint8_t> &out_bytes) {
    if (readFileIntoBytes(path, out_bytes) != Error::Ok) {
        LOG_ERROR("RIM fetch: file read failed for effective URL "
                  << effective_url << " (path=" << path
                  << ", raw URL=" << raw_url << ")");
        return Error::RimNotFound;
    }
    return Error::Ok;
}

} // namespace

CorimStore::CorimStore()
    : CorimStore(HttpOptions{}) {}

CorimStore::CorimStore(HttpOptions http_options, std::string service_key)
    : m_http_options(std::move(http_options))
{
    m_allowed_prefixes.emplace_back(kDefaultAllowedRawUrlPrefix);
    NvHttpClient::create(m_http_client, std::move(service_key), m_http_options);
}

Error CorimStore::add_allowed_url_prefix(std::string prefix) {
    if (!starts_with(prefix, kHttpsPrefix)) {
        LOG_ERROR("RIM allowlist prefix must begin with https://");
        return Error::BadArgument;
    }
    m_allowed_prefixes.push_back(std::move(prefix));
    return Error::Ok;
}

void CorimStore::enable_in_memory_cache(uint64_t max_size_bytes, time_t ttl_seconds) {
    set_cache(std::make_shared<NvCache>(
        std::make_shared<NvCacheOptions>(max_size_bytes, ttl_seconds)));
}

void CorimStore::set_cache(std::shared_ptr<INvCache> cache) {
    m_cache = std::move(cache);
}

Error CorimStore::add_url_rewrite(std::string pattern,
                                    std::string replacement) {
    if (pattern.empty()) {
        LOG_ERROR("URL rewrite pattern must not be empty");
        return Error::BadArgument;
    }
    const bool pattern_slash = pattern.back() == '/';
    const bool replacement_slash =
        !replacement.empty() && replacement.back() == '/';
    if (pattern_slash != replacement_slash) {
        LOG_ERROR("URL rewrite PATTERN and REPLACEMENT must agree on a "
                  "trailing '/': pattern='" << pattern << "' replacement='"
                  << replacement << "'");
        return Error::BadArgument;
    }
    m_rewrites.emplace_back(std::move(pattern), std::move(replacement));
    return Error::Ok;
}

Error CorimStore::resolve_and_authorize(const std::string &url,
                                          std::string &out_effective) const {
    // Set before the allowlist check so callers still get a usable
    // effective-URL value (the raw URL) to log on a rejection.
    out_effective = url;
    bool allowed = false;
    for (const auto &prefix : m_allowed_prefixes) {
        if (starts_with(url, prefix)) {
            allowed = true;
            break;
        }
    }
    if (!allowed) {
        LOG_ERROR("RIM fetch: raw rim-locator URL is not in the allowlist: "
                  "raw URL=" << url);
        return Error::BadArgument;
    }
    for (const auto &rule : m_rewrites) {
        if (starts_with(out_effective, rule.first)) {
            out_effective.replace(0, rule.first.size(), rule.second);
            break;
        }
    }
    return Error::Ok;
}

Error CorimStore::fetch(const std::string &url,
                          std::vector<uint8_t> &out_bytes,
                          std::string *out_effective_url) const {
    std::vector<uint8_t> coev_bytes;
    bool coev_present = false;
    std::string coev_sha256;
    return fetch_impl(url, out_bytes, coev_bytes, coev_present, coev_sha256,
                       out_effective_url);
}

Error CorimStore::fetch_with_coev(const std::string &url,
                                    std::vector<uint8_t> &out_corim_bytes,
                                    std::vector<uint8_t> &out_coev_bytes,
                                    bool &out_coev_present,
                                    std::string &out_coev_sha256,
                                    std::string *out_effective_url) const {
    return fetch_impl(url, out_corim_bytes, out_coev_bytes, out_coev_present,
                       out_coev_sha256, out_effective_url);
}

Error CorimStore::fetch_impl(const std::string &url,
                              std::vector<uint8_t> &out_corim_bytes,
                              std::vector<uint8_t> &out_coev_bytes,
                              bool &out_coev_present,
                              std::string &out_coev_sha256,
                              std::string *out_effective_url) const {
    out_coev_present = false;
    out_coev_bytes.clear();
    out_coev_sha256.clear();
    if (out_effective_url != nullptr) {
        *out_effective_url = url;
    }
    std::string effective;
    Error resolve_err = resolve_and_authorize(url, effective);
    if (out_effective_url != nullptr) {
        *out_effective_url = effective;
    }
    if (resolve_err != Error::Ok) {
        return resolve_err;
    }

    if (m_cache) {
        std::shared_ptr<void> cached;
        if (m_cache->get(effective, cached) == Error::Ok) {
            auto cached_entry =
                std::static_pointer_cast<CachedRimEntry>(cached);
            if (cached_entry != nullptr) {
                out_corim_bytes = cached_entry->corim_bytes;
                out_coev_bytes = cached_entry->coev_bytes;
                out_coev_present = cached_entry->coev_present;
                out_coev_sha256 = cached_entry->coev_sha256;
                return Error::Ok;
            }
            LOG_ERROR("CorimStore: cache hit returned null payload for " << effective);
        }
    }

    Error err = Error::Ok;
    if (starts_with(effective, kFilePrefix)) {
        // Fixtures carry raw CoRIM bytes, not a JSON envelope -- no CoEV here.
        const std::string path =
            effective.substr(std::string(kFilePrefix).size());
        err = read_file(url, effective, path, out_corim_bytes);
    } else if (starts_with(effective, kHttpsPrefix) || starts_with(effective, kHttpPrefix)) {
        NvRequest request(effective, NvHttpMethod::HTTP_METHOD_GET);
        long status = 0;
        std::string body;
        std::string content_type;
        err = m_http_client.do_request_as_string(request, status, body, &content_type);
        if (err != Error::Ok) {
            LOG_ERROR("RIM fetch: HTTP request to effective URL "
                      << effective << " failed (raw URL=" << url << ")");
        } else if (status != HTTP_STATUS_OK) {
            LOG_ERROR("RIM fetch: HTTP " << status
                      << " from effective URL " << effective
                      << " (raw URL=" << url << ")");
            if (status == HTTP_STATUS_NOT_FOUND) {
                err = Error::RimNotFound;
            } else if (status == HTTP_STATUS_FORBIDDEN ||
                       status == HTTP_STATUS_UNAUTHORIZED) {
                err = Error::RimForbidden;
            } else {
                err = Error::RimInternalError;
            }
        } else if (starts_with(content_type, kJsonContentType)) {
            err = extract_rim_service_bytes_with_coev(
                effective, body, out_corim_bytes, out_coev_bytes,
                out_coev_present, out_coev_sha256);
        } else if (starts_with(content_type, kCorimCborContentType) ||
                   starts_with(content_type, kCorimCoseContentType)) {
            out_corim_bytes.assign(body.begin(), body.end());
        } else {
            LOG_ERROR("RIM fetch: unexpected Content-Type '" << content_type
                      << "' from effective URL " << effective
                      << " (raw URL=" << url << ")");
            err = Error::RimInvalidSchema;
        }
    } else {
        LOG_ERROR("RIM fetch: rewritten URL has unsupported scheme: "
                  "effective URL=" << effective << " (raw URL=" << url << ")");
        return Error::BadArgument;
    }

    if (err == Error::Ok && m_cache) {
        auto entry = std::make_shared<CachedRimEntry>();
        entry->corim_bytes = out_corim_bytes;
        entry->coev_bytes = out_coev_bytes;
        entry->coev_present = out_coev_present;
        entry->coev_sha256 = out_coev_sha256;
        m_cache->put(effective, entry,
                     entry->corim_bytes.size() + entry->coev_bytes.size());
    }
    return err;
}

} // namespace nvattestation
