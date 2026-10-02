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

#include <algorithm>
#include <curl/curl.h>
#include <memory>
#include <random>
#include <thread>
#include <chrono>

#include "nv_attestation/nv_http.h"
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"
#include "nv_attestation/nv_types.h"
#include "nv_attestation/utils.h"

namespace nvattestation {

namespace {

// Returns true only when it is safe to attach a Bearer credential: the URL
// must use HTTPS and target nvidia.com or a subdomain.
bool is_safe_service_key_target(const std::string& url) {
    CURLU* curl_url_handle = curl_url();
    if (curl_url_handle == nullptr) {
        return false;
    }
    if (curl_url_set(curl_url_handle, CURLUPART_URL, url.c_str(), 0) != CURLUE_OK) {
        curl_url_cleanup(curl_url_handle);
        return false;
    }
    char* scheme = nullptr;
    char* host = nullptr;
    CURLUcode rc_scheme = curl_url_get(curl_url_handle, CURLUPART_SCHEME, &scheme, 0);
    CURLUcode rc_host   = curl_url_get(curl_url_handle, CURLUPART_HOST,   &host,   0);
    curl_url_cleanup(curl_url_handle);

    std::string scheme_str = (rc_scheme == CURLUE_OK && scheme != nullptr) ? scheme : "";
    std::string host_str   = (rc_host   == CURLUE_OK && host   != nullptr) ? host   : "";
    curl_free(scheme);
    curl_free(host);

    std::transform(scheme_str.begin(), scheme_str.end(), scheme_str.begin(), ::tolower);
    std::transform(host_str.begin(),   host_str.end(),   host_str.begin(),   ::tolower);

    return scheme_str == "https" &&
           (host_str == "nvidia.com" || ends_with(host_str, ".nvidia.com"));
}

} // namespace

    Error NvHttpClient::create(NvHttpClient& out_client, std::string service_key, HttpOptions options) {
        out_client.m_service_key = std::move(service_key);
        out_client.m_options = std::move(options);

        return Error::Ok;
    }

    size_t NvHttpClient::curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
        // TODO: add a streaming size cap to limit download bandwidth.
        auto totalSize = size * nmemb;
        auto* str = static_cast<std::string*>(userp);
        str->append(static_cast<char*>(contents), totalSize);
        return totalSize;
    }
    
    constexpr const long MILLIS_PER_SECOND = 1000;

    Error NvHttpClient::do_request_as_string(const NvRequest& request, long& out_status, std::string& out_response, std::string* out_content_type) const {
        out_response.clear();
        if (out_content_type != nullptr) {
            out_content_type->clear();
        }
        /*
            todo (p0): optimize usage of curl handles

            use a thread local curl easy handle and then use a global curl share handle

            use curl share handle to share dns, ssl and cookies between curl easy handle

            this is the most performance we can get without using multi handle (async). 
            but exposing that to the client is pretty complex and an easier way would to 
            expose a http interface that the client can provide
        */ 
        // Keep the error buffer alive until after the curl handle is cleaned up.
        char curl_error_buffer[CURL_ERROR_SIZE] = {};
        nv_unique_ptr<CURL> curl_handle(curl_easy_init());

        curl_easy_reset(curl_handle.get());

        curl_easy_setopt(curl_handle.get(), CURLOPT_ERRORBUFFER, curl_error_buffer);
        curl_easy_setopt(curl_handle.get(), CURLOPT_WRITEFUNCTION, curl_write_callback);
        curl_easy_setopt(curl_handle.get(), CURLOPT_WRITEDATA, &out_response);
        curl_easy_setopt(curl_handle.get(), CURLOPT_CONNECTTIMEOUT_MS, m_options.connection_timeout_ms);
        curl_easy_setopt(curl_handle.get(), CURLOPT_TIMEOUT_MS, m_options.request_timeout_ms);

        if (!m_options.tls_ca_cert.empty()) {
            curl_easy_setopt(curl_handle.get(), CURLOPT_CAINFO, m_options.tls_ca_cert.c_str());
        }
        if (!m_options.tls_ca_path.empty()) {
            curl_easy_setopt(curl_handle.get(), CURLOPT_CAPATH, m_options.tls_ca_path.c_str());
        }

        curl_easy_setopt(curl_handle.get(), CURLOPT_URL, request.url.c_str());

        const char* method_str = nullptr;
        
        switch (request.method) {
            case NvHttpMethod::HTTP_METHOD_GET:
                method_str = "GET";
                break;
            case NvHttpMethod::HTTP_METHOD_POST:
                method_str = "POST";
                break;
            case NvHttpMethod::HTTP_METHOD_PUT:
                method_str = "PUT";
                break;
            case NvHttpMethod::HTTP_METHOD_DELETE:
                method_str = "DELETE";
                break;
        }
        curl_easy_setopt(curl_handle.get(), CURLOPT_CUSTOMREQUEST, method_str);

        std::string request_id;
        if (generate_request_id(request_id) != Error::Ok) {
            return Error::InternalError;
        }

        curl_slist* headers_list_raw = nullptr;
        for (const auto& header_pair : request.headers) {
            std::string header_string = header_pair.first + ": " + header_pair.second;
            headers_list_raw = curl_slist_append(headers_list_raw, header_string.c_str());
        }
        headers_list_raw = curl_slist_append(headers_list_raw, ("x-request-id: " + request_id).c_str());

        if (!m_service_key.empty()) {
            if (is_safe_service_key_target(request.url)) {
                LOG_TRACE("Service key provided, adding Authorization header");
                std::string service_key_header = "Authorization: Bearer " + m_service_key;
                headers_list_raw = curl_slist_append(headers_list_raw, service_key_header.c_str());
            } else {
                LOG_WARN("Service key suppressed: target URL is not an NVIDIA domain: " << request.url);
            }
        }

        curl_easy_setopt(curl_handle.get(), CURLOPT_HTTPHEADER, headers_list_raw);
        nv_unique_ptr<curl_slist> headers_list(headers_list_raw);

        if(!request.payload.empty()) {
            curl_easy_setopt(curl_handle.get(), CURLOPT_POSTFIELDS, request.payload.c_str());
            curl_easy_setopt(curl_handle.get(), CURLOPT_POSTFIELDSIZE, request.payload.size());
        }

        // Retry up to max_retry_count times.
        // Uses full jitter to calculate backoff.
        Error last_error = Error::InternalError;
        long cur_try = 0;
        long backoff_ms = m_options.base_backoff_ms;
        // todo (p0): make this thread local
        std::mt19937_64 rng{std::random_device{}()}; // for randomized backoff
        do {
            curl_error_buffer[0] = '\0';
            bool is_last_attempt = cur_try == m_options.max_retry_count; // for logging only
            if (cur_try > 0) { // this is a retry
                out_response.clear();
                long full_jitter_backoff_ms = std::uniform_int_distribution<long>(0, backoff_ms)(rng);
                LOG_TRACE("Retrying with jittered backoff of " << full_jitter_backoff_ms << "ms (base: " << backoff_ms << "ms)");
                std::this_thread::sleep_for(std::chrono::milliseconds(full_jitter_backoff_ms));
                backoff_ms *= 2;
                backoff_ms = std::min(backoff_ms, m_options.max_backoff_ms);
            }
            cur_try++;
            CURLcode curl_code = curl_easy_perform(curl_handle.get());
            if (curl_code != CURLE_OK) {
                std::string curl_error = curl_easy_strerror(curl_code);
                if (curl_error_buffer[0] != '\0') {
                    curl_error += ": ";
                    curl_error += curl_error_buffer;
                }
                if (is_last_attempt) {
                    LOG_ERROR("Final libcurl error: " << curl_error << " (" << curl_code << ")");
                }
                if (curl_code == CURLE_COULDNT_CONNECT 
                    || curl_code == CURLE_COULDNT_RESOLVE_HOST
                    || curl_code == CURLE_OPERATION_TIMEDOUT) {
                        LOG_DEBUG("Retryable libcurl error code: " << curl_error << " (" << curl_code << ")");
                        continue;
                }
                LOG_ERROR("Fatal libcurl error code: " << curl_error << " (" << curl_code << ")");
                return Error::InternalError;
            }

            curl_easy_getinfo(curl_handle.get(), CURLINFO_RESPONSE_CODE, &out_status);
            if (out_content_type != nullptr) {
                out_content_type->clear();
                char* content_type = nullptr;
                curl_easy_getinfo(curl_handle.get(), CURLINFO_CONTENT_TYPE, &content_type);
                if (content_type != nullptr) {
                    *out_content_type = content_type;
                }
            }
            if (is_http_status_2xx(out_status)) {
                return Error::Ok; // true success, exit early
            }
            if (!is_http_retryable(out_status)) {
                LOG_ERROR("Non-retryable HTTP response code: " << out_status << " (x-request-id: " << request_id << ")");
                return Error::Ok; // bad code, but cannot retry
            }
            // Technically OK because HTTP request succeeded.
            // Send another request to get a better response.
            last_error = Error::Ok;
            if (is_last_attempt && out_status == HTTP_STATUS_TOO_MANY_REQUESTS) {
                last_error = Error::RateLimited;
            }
            if (is_last_attempt) {
                LOG_ERROR("Final HTTP status after retries for " << method_str << " " << request.url << ": " << out_status << " (x-request-id: " << request_id << ")");
            } else {
                LOG_DEBUG("Retryable HTTP response code from server for " << method_str << " " << request.url << ": " << out_status);
                LOG_DEBUG("Failed HTTP response body: " << out_response);
            }
        } while (cur_try <= m_options.max_retry_count);
        LOG_ERROR("Gave up HTTP request after " << cur_try << " attempts for " << method_str << " " << request.url << " (x-request-id: " << request_id << ")");
        return last_error;
    }

}
