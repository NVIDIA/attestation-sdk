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

#include <algorithm>
#include <map>
#include <random>
#include <string>
#include <unordered_map>

#include <curl/curl.h>

#include "nvat.h"
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"
#include <nlohmann/json.hpp>
#include "nv_attestation/nv_types.h"
#include "nv_attestation/utils.h"

namespace nvattestation {

    enum NvHttpStatus {
        HTTP_STATUS_OK = 200,
        HTTP_STATUS_NOT_FOUND = 404,
        HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
        HTTP_STATUS_BAD_REQUEST = 400,
        HTTP_STATUS_UNAUTHORIZED = 401,
        HTTP_STATUS_FORBIDDEN = 403,
        HTTP_STATUS_UNKNOWN = 0,
    };

    inline bool is_http_status_2xx(long code) {
        return 200 <= code and code < 300;
    }

    inline bool is_http_status_5xx(long code) {
        return 500 <= code;
    }

    inline bool is_http_retryable(long code) {
        switch(code) {
            case 408: 
            case 429:
            case 500:
            case 502: 
            case 503:
            case 504:
                return true;
            default: return false;
        }
    }

    enum class NvHttpMethod {
        HTTP_METHOD_GET,
        HTTP_METHOD_POST,
        HTTP_METHOD_PUT,
        HTTP_METHOD_DELETE,
    };

    class HttpOptions {
        public: 
            /** Maximum number of retries. */
            long max_retry_count;
            /** Base delay used for exponential backoff. Doubled after each failed attempt. */
            long base_backoff_ms;
            /** Maximum number of millisconds to back off after a failed attempt, in milliseconds. */
            long max_backoff_ms;
            /** Connection timeout, in milliseconds. */
            long connection_timeout_ms;
            /** Overall request timeout, in milliseconds. */
            long request_timeout_ms;

            HttpOptions() :
                max_retry_count(NVAT_HTTP_DEFAULT_RETRY_COUNT),
                base_backoff_ms(NVAT_HTTP_DEFAULT_BASE_BACKOFF_MS),
                max_backoff_ms(NVAT_HTTP_DEFAULT_MAX_BACKOFF_MS),
                connection_timeout_ms(NVAT_HTTP_DEFAULT_CONNECTION_TIMEOUT_MS),
                request_timeout_ms(NVAT_HTTP_DEFAULT_REQUEST_TIMEOUT_MS) {}

            HttpOptions(int retry, long base_backoff_ms, long max_backoff_ms, long connection_timeout_ms, long request_timeout_ms) : 
                max_retry_count(std::max(0, retry)),
                base_backoff_ms(std::max(0L, base_backoff_ms)),
                max_backoff_ms(std::max(0L, max_backoff_ms)),
                connection_timeout_ms(std::max(0L, connection_timeout_ms)),
                request_timeout_ms(std::max(0L, request_timeout_ms)) {}

            void set_max_retry_count(long retry) { this->max_retry_count = std::max(0l, retry); }
            void set_base_backoff_ms(long retry_backoff_ms) { this->base_backoff_ms = std::max(0L, retry_backoff_ms); }
            void set_max_backoff_ms(long max_backoff_ms) { this->max_backoff_ms = std::max(0L, max_backoff_ms); }
            void set_connection_timeout_ms(long connection_timeout_ms) { this->connection_timeout_ms = std::max(0L, connection_timeout_ms); }
            void set_request_timeout_ms(long request_timeout_ms) { this->request_timeout_ms = std::max(0L, request_timeout_ms); }
    };

    class NvRequest {
        public: 
            std::string url;
            NvHttpMethod method;
            std::unordered_map<std::string, std::string> headers;
            std::string payload;

            NvRequest(std::string url, NvHttpMethod method, std::unordered_map<std::string, std::string> headers = {}, std::string payload="") : 
                url(url),
                method(method),
                headers(headers),
                payload(payload) {}
    };

    class NvHttpClient {
        public: 
            static Error create(NvHttpClient& out_client, HttpOptions options = HttpOptions());

            Error do_request_as_string(const NvRequest& request, long& out_status, std::string& out_response);
            template<typename T>
            Error do_request_as_json_struct(const NvRequest& request, long& out_status, T& out_response);

            NvHttpClient()=default;

        private: 
            nv_unique_ptr<CURL> m_curl_handle;
            HttpOptions m_options;
            std::mt19937_64 m_rng{std::random_device{}()}; // for randomized backoff

            static size_t curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp);
    };

    template<typename T>
    Error NvHttpClient::do_request_as_json_struct(const NvRequest& request, long& out_status, T& out_response) {
        std::string response;
        Error error = do_request_as_string(request, out_status, response);
        if (error != Error::Ok) {
            return error;
        }
        error = deserialize_from_json(response, out_response);
        if (error != Error::Ok) {
            return error;
        }
        return Error::Ok;
    }

}