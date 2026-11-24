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

#include <cstddef>
#include <string>

namespace nvattestation {

constexpr std::size_t MAX_REQUEST_ID_LEN = 128;

bool is_valid_request_id(const std::string& request_id);

// Request id of the appraisal running on this thread; empty when unset.
const std::string& current_request_id();

// Sets this thread's request id for the scope's lifetime, clearing it on exit.
class RequestIdScope {
public:
    explicit RequestIdScope(std::string request_id);
    ~RequestIdScope();
    RequestIdScope(const RequestIdScope&) = delete;
    RequestIdScope& operator=(const RequestIdScope&) = delete;
    RequestIdScope(RequestIdScope&&) = delete;
    RequestIdScope& operator=(RequestIdScope&&) = delete;
};

}
