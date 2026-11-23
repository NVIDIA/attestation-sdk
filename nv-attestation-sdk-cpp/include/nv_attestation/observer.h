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

#pragma once

#include <nvat.h>

namespace nvattestation {

// Service and cache names reported to the observer.
constexpr const char* kServiceRim = "rim";
constexpr const char* kServiceOcsp = "ocsp";
constexpr const char* kServiceJwks = "jwks";
constexpr const char* kServiceNras = "nras";
constexpr const char* kServiceUnknown = "unknown";

// Caller-supplied callbacks that report SDK-internal HTTP calls and cache lookups.
struct Observer {
    nvat_http_call_callback_t http_call_callback = nullptr;
    nvat_cache_lookup_callback_t cache_lookup_callback = nullptr;
    void* user_data = nullptr;
};

void set_observer(const Observer& observer);
void destroy_observer();

// status is 0 and error non-null when no response was received.
void notify_http_call(const char* service, const char* method, const char* url, long status, const char* error, long duration_ms, size_t request_size, size_t response_size);
void notify_cache_lookup(const char* cache, bool hit);

}
