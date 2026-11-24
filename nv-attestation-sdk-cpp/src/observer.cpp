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

#include "nv_attestation/observer.h"

namespace nvattestation {

// Set once at init and cleared at shutdown.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): Must be mutable
static Observer g_observer;

void set_observer(const Observer& observer) {
    g_observer = observer;
}

void destroy_observer() {
    g_observer = Observer{};
}

void notify_http_call(const char* service, const char* method, const char* url, long status, const char* error, long duration_ms, size_t request_size, size_t response_size) {
    if (g_observer.http_call_callback != nullptr) {
        g_observer.http_call_callback(service, method, url, status, error, duration_ms, request_size, response_size, g_observer.user_data);
    }
}

void notify_cache_lookup(const char* cache, bool hit) {
    if (g_observer.cache_lookup_callback != nullptr) {
        g_observer.cache_lookup_callback(cache, hit, g_observer.user_data);
    }
}

}
