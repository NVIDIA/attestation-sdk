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

    Error NvHttpClient::create(NvHttpClient& out_client, HttpOptions options) {
        nv_unique_ptr<CURL> curl_handle(curl_easy_init());
        if (curl_handle == nullptr) {
            LOG_ERROR("Failed to initialize libcurl handle");
            return Error::InternalError;
        }

        out_client.m_curl_handle = std::move(curl_handle);

        out_client.m_options = options;

        return Error::Ok;
    }

    size_t NvHttpClient::curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
        auto totalSize = size * nmemb;
        auto* str = static_cast<std::string*>(userp);
        str->append(static_cast<char*>(contents), totalSize);
        return totalSize;
    }
    
    constexpr const long MILLIS_PER_SECOND = 1000;

    Error NvHttpClient::do_request_as_string(const NvRequest& request, long& out_status, std::string& out_response) {
        out_response.clear();

        curl_easy_reset(m_curl_handle.get());

        curl_easy_setopt(m_curl_handle.get(), CURLOPT_WRITEFUNCTION, curl_write_callback);
        curl_easy_setopt(m_curl_handle.get(), CURLOPT_WRITEDATA, &out_response);
        curl_easy_setopt(m_curl_handle.get(), CURLOPT_CONNECTTIMEOUT_MS, m_options.connection_timeout_ms);
        curl_easy_setopt(m_curl_handle.get(), CURLOPT_TIMEOUT_MS, m_options.request_timeout_ms);

        curl_easy_setopt(m_curl_handle.get(), CURLOPT_URL, request.url.c_str());

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
        curl_easy_setopt(m_curl_handle.get(), CURLOPT_CUSTOMREQUEST, method_str);

        curl_slist* headers_list_raw = nullptr;
        if(!request.headers.empty()) {
            for (const auto& header_pair : request.headers) {
                std::string header_string = header_pair.first + ": " + header_pair.second;
                headers_list_raw = curl_slist_append(headers_list_raw, header_string.c_str());
            }
            curl_easy_setopt(m_curl_handle.get(), CURLOPT_HTTPHEADER, headers_list_raw);
        }
        nv_unique_ptr<curl_slist> headers_list(headers_list_raw);

        if(!request.payload.empty()) {
            curl_easy_setopt(m_curl_handle.get(), CURLOPT_POSTFIELDS, request.payload.c_str());
            curl_easy_setopt(m_curl_handle.get(), CURLOPT_POSTFIELDSIZE, request.payload.size());
        }

        // Retry up to max_retry_count times.
        // Uses full jitter to calculate backoff.
        Error last_error = Error::InternalError;
        long cur_try = 0;
        long backoff_ms = m_options.base_backoff_ms;
        do {
            if (cur_try > 0) { // this is a retry
                out_response.clear();
                long full_jitter_backoff_ms = std::uniform_int_distribution<long>(0, backoff_ms)(m_rng);
                LOG_DEBUG("Retrying with jittered backoff of " << full_jitter_backoff_ms << "ms (base: " << backoff_ms << "ms)");
                std::this_thread::sleep_for(std::chrono::milliseconds(full_jitter_backoff_ms));
                backoff_ms *= 2;
                backoff_ms = std::min(backoff_ms, m_options.max_backoff_ms);
            }
            cur_try++;
            CURLcode curl_code = curl_easy_perform(m_curl_handle.get());
            if (curl_code != CURLE_OK) {
                if (curl_code == CURLE_COULDNT_CONNECT 
                    || curl_code == CURLE_COULDNT_RESOLVE_HOST
                    || curl_code == CURLE_OPERATION_TIMEDOUT) {
                        LOG_DEBUG("Retryable libcurl error code: " << curl_easy_strerror(curl_code) << " (" << curl_code << ")");
                        continue;
                }
                LOG_ERROR("Fatal libcurl error code: " << curl_easy_strerror(curl_code) << " (" << curl_code << ")");
                return Error::InternalError;
            }

            curl_easy_getinfo(m_curl_handle.get(), CURLINFO_RESPONSE_CODE, &out_status);
            if (is_http_status_2xx(out_status)) {
                return Error::Ok; // true success, exit early
            }
            if (!is_http_retryable(out_status)) {
                LOG_DEBUG("Non-retryable HTTP response code: " << out_status);
                return Error::Ok; // bad code, but cannot retry
            }
            // Technically OK because HTTP request succeeded.
            // Send another request to get a better response.
            last_error = Error::Ok; 
            LOG_DEBUG("Retryable HTTP response code from server: " << out_status);
            LOG_TRACE("Failed HTTP response body: " << out_response);
        } while (cur_try <= m_options.max_retry_count);
        LOG_ERROR("Gave up HTTP request after " << cur_try << " attempts");
        return last_error;
    }

}