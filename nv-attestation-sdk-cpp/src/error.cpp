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

#include <vector>
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"

namespace nvattestation {

// Define the thread-local variable.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
thread_local std::vector<ErrorRecord> ErrorStack::m_thread_errors;

std::vector<ErrorRecord>& ErrorStack::get_thread_errors() {
    return m_thread_errors;
}

void ErrorStack::push(Error code, const std::string& message) {
    get_thread_errors().emplace_back(ErrorRecord{code, message});
}

bool ErrorStack::has_errors() {
    return !get_thread_errors().empty();
}

ErrorRecord ErrorStack::pop() {
    auto& errors = get_thread_errors();
    if (errors.empty()) {
        return {Error::Ok, ""};
    }
    ErrorRecord err = errors.back();
    errors.pop_back();
    return err;
}

ErrorRecord ErrorStack::peek() {
    auto& errors = get_thread_errors();
    if (errors.empty()) {
        return {Error::Ok, ""};
    }
    return errors.back();
}

void ErrorStack::clear() {
    get_thread_errors().clear();
}

Error nv_get_error() {
    return ErrorStack::pop().code;
}

}
