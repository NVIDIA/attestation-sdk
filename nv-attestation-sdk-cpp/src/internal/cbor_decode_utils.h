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

#include <vector>
#include <memory>
#include <cstring>

#include "nv_attestation/error.h"
#include "nv_attestation/log.h"
#include "zcbor_print.h"

namespace nvattestation {

// Decode CBOR bytes into a heap-allocated zcbor struct, validating all input is consumed.
// DecodeFn signature: int(const uint8_t*, size_t, T*, size_t*)
// Int returned from DecodeFn must be a zcbor error code.
// `schema_error` is what an unparseable document means for this artifact; the
// decoder cannot tell which one it holds.
template<typename T, typename DecodeFn>
static Error decode_cbor(
    const std::vector<uint8_t>& bytes,
    const char* type_name,
    DecodeFn decode_fn,
    std::unique_ptr<T>& out,
    Error schema_error
) {
    if (bytes.empty()) {
        LOG_ERROR("Empty " << type_name << " bytes");
        return schema_error;
    }

    out.reset(new T());
    std::memset(out.get(), 0, sizeof(T));

    size_t payload_len_out = 0;
    LOG_DEBUG("Attempting to decode " << bytes.size() << " bytes of " << type_name << " data");

    int ret = decode_fn(bytes.data(), bytes.size(), out.get(), &payload_len_out);
    if (ret != 0) {
        LOG_ERROR("CBOR " << type_name << " decode failed with error code: " << ret
                  << " (" << zcbor_error_str(ret) << ") after consuming " << payload_len_out
                  << " bytes");
        return schema_error;
    }

    if (payload_len_out != bytes.size()) {
        LOG_ERROR(type_name << " decoder consumed " << payload_len_out
                  << " bytes but input was " << bytes.size() << " bytes");
        return schema_error;
    }

    LOG_DEBUG("Successfully parsed " << type_name);
    return Error::Ok;
}

} // namespace nvattestation
