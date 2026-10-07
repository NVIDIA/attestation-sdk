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

// SpdmIndirectMap lives in its own header (rather than in corim_evidence/coev.h)
// so that it can be included from corim.h, where MeasurementValues holds it
// via std::unique_ptr<SpdmIndirectMap>. The unique_ptr destructor instantiation
// needs the complete type at any TU that constructs or destroys a
// MeasurementValues, so this header has no dependencies on coev.h.

#include <cstdint>
#include <vector>

#include <nlohmann/json_fwd.hpp>

namespace nvattestation {

// TCG DICE Concise Evidence Binding for SPDM v1.1 §7.1: spdm-indirect-map.
// Holds the SPDM measurement-block indexes for indirect measurements — values
// located at SPDM measurement-block locations other than the manifest at
// L=0xFD. Populated by the CoEV parser when a measurement-values-map carries
// the optional spdm-indirect (key 12) field.
class SpdmIndirectMap {
public:
    SpdmIndirectMap() = default;
    explicit SpdmIndirectMap(std::vector<uint64_t> indexes);
    SpdmIndirectMap(const SpdmIndirectMap&) = default;
    SpdmIndirectMap(SpdmIndirectMap&&) = default;
    SpdmIndirectMap& operator=(const SpdmIndirectMap&) = default;
    SpdmIndirectMap& operator=(SpdmIndirectMap&&) = default;

    // Spec names the field `index` (singular); rendered as `indexes` here
    // because the CBOR value is an array.
    const std::vector<uint64_t>& getIndexes() const { return m_indexes; }

private:
    std::vector<uint64_t> m_indexes;
};

void to_json(nlohmann::json& json_out, const SpdmIndirectMap& v);

}  // namespace nvattestation
