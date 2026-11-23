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

#include <algorithm>

#include "nv_attestation/request_id.h"

namespace nvattestation {

namespace {
std::string& request_id_slot() {
    thread_local std::string id;
    return id;
}
}

bool is_valid_request_id(const std::string& request_id) {
    if (request_id.empty() || request_id.size() > MAX_REQUEST_ID_LEN) {
        return false;
    }
    return std::all_of(request_id.begin(), request_id.end(),
                       [](char ch) { return ch >= '!' && ch <= '~'; });
}

const std::string& current_request_id() {
    return request_id_slot();
}

RequestIdScope::RequestIdScope(std::string request_id) {
    request_id_slot() = std::move(request_id);
}

RequestIdScope::~RequestIdScope() {
    request_id_slot().clear();
}

}
