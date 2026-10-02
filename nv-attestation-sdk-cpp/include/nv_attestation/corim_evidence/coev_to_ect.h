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

#include <cstdint>
#include <vector>

#include "nv_attestation/corim_evidence/coev.h"
#include "nv_attestation/corim_verify.h"
#include "nv_attestation/error.h"
#include "nv_attestation/spdm/spdm_measurement_records.hpp"

namespace nvattestation {

// DMTFSpecMeasurementValueType 0x00..max carries a digest; higher values are
// version/svn/raw-value (TCG DICE CoEV-SPDM v1.1, Table 7).
constexpr uint8_t kDmtfTypeDigestMax = 0x7F;

// Convert a single CoEV evidence-triple-record into an Ect. The triple's
// environment-map becomes the Ect environment; its measurement-map array
// becomes the Ect claims. Any MeasurementValues.m_spdm_indirect indexes are
// resolved against `spdm_records` per TCG DICE CoEV-SPDM v1.1 Table 7, and
// the resulting Ect carries resolved-only MeasurementValues
// (m_spdm_indirect always cleared). `hash_algorithm_id` is the
// SPDM-negotiated digest algorithm (IANA NI / COSE registry; 0 = "no
// digest-typed indirect refs expected" -- encountering one is a hard error).
Error evidence_triple_to_ect(
    const EvidenceTripleRecord& triple,
    const SpdmMeasurementRecordParser& spdm_records,
    int32_t hash_algorithm_id,
    Ect& out);

// Convert all evidence-triple-records carried by a ConciseEvidence into a
// vector of Ects, appended to `out` in record order. profile and
// evidence-id on the ConciseEvidence are not propagated. spdm-indirect
// resolution and hash-algorithm semantics match evidence_triple_to_ect.
Error concise_evidence_to_ects(
    const ConciseEvidence& ce,
    const SpdmMeasurementRecordParser& spdm_records,
    int32_t hash_algorithm_id,
    std::vector<Ect>& out);

// Convenience overload for self-contained concise-evidence with no SPDM
// measurement-record source (e.g. an OCP EAT). Equivalent to the overload above
// with no spdm-indirect resolution: a measurement carrying an spdm-indirect
// reference is a hard error (Error::BadArgument) because no records are
// available to resolve it.
Error concise_evidence_to_ects(
    const ConciseEvidence& ce,
    std::vector<Ect>& out);

// Convert every ConciseEvidence in an SpdmToc into Ects, appended to
// `ects_out` in document order. The toc's rim-locators are pass-through
// copied into `rim_locators_out` so the caller can drive CoRIM fetches.
// toc.profile is not propagated.
Error spdm_toc_to_ects(
    const SpdmToc& toc,
    const SpdmMeasurementRecordParser& spdm_records,
    int32_t hash_algorithm_id,
    std::vector<Ect>& ects_out,
    std::vector<CorimLocatorMap>& rim_locators_out);

}  // namespace nvattestation
