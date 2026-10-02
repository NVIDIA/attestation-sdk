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
#include "nv_attestation/corim_evidence/coev_to_ect.h"

#include <limits>
#include <string>
#include <unordered_set>

#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"

// SpdmToc.profile / ConciseEvidence.profile are not consumed by this
// mapper. Profile validation and rejection of unknown profiles belongs
// in the verifier layer.

namespace nvattestation {
namespace {

// DMTF measurement-value-type bytes (TCG DICE Concise Evidence Binding for
// SPDM v1.1, Table 7). kDmtfTypeDigestMax lives in coev_to_ect.h.
constexpr uint8_t kDmtfTypeVersion   = 0x86;   // raw firmware version (printable ASCII)
constexpr uint8_t kDmtfTypeSvn       = 0x87;   // little-endian SVN

// SPDM SVN field uses little-endian byte order; allow up to 8 bytes so that
// devices padding the value beyond uint32 width can still be parsed cleanly
// (anything beyond uint32 range is rejected as an invalidation).
constexpr size_t kMaxSvnByteCount = 8;
constexpr unsigned kBitsPerByte   = 8;

// Largest byte value treated as ASCII (high bit clear).
constexpr uint8_t kAsciiMax = 0x7F;

// Version strings from SPDM are expected to be ASCII; reject anything with
// the high bit set. Keeps the rule narrow and lets downstream JSON consumers
// stay strict-ASCII safe without inviting non-ASCII firmware version data.
bool is_ascii_bytes(const std::vector<uint8_t>& bytes) {
    return std::all_of(bytes.begin(), bytes.end(),
        [](uint8_t byte) { return byte <= kAsciiMax; });
}

// Resolve every spdm-indirect index on `in` against `records`, populating
// the matching typed field(s) on `out`. Direct fields already set on `in`
// carry through. The resulting `out` has m_spdm_indirect cleared.
//
// Per TCG DICE Concise Evidence Binding for SPDM v1.1 Table 7, with the
// underlying byte layout from DSP0274 (bit 7 = raw-bit-stream flag,
// bits[6:0] = DMTF measurement type):
//   0x00..0x7F  -> append to m_digests (alg = hash_algorithm_id)
//                 (bit 7 = 0; any digest type)
//   0x85        -> raw-value  (raw Device Mode)
//   0x86        -> version    (raw Version, ASCII text)
//   0x87        -> svn        (raw SVN, little-endian uint32)
//   any other   -> raw-value. Per DSP0274 every byte with bit 7 = 1 is
//                  a raw bit stream of some DMTF type (Immutable ROM,
//                  Mutable Firmware, Hardware Config, etc.). Table 7
//                  lists "0x80, 0xFF" as representative bookends and the
//                  prose ("If the SPDM measurement is not a debug mode,
//                  version, svn, or digest...") covers the rest of the
//                  raw-bit-stream range with raw-value.
//
// Per spec §6.5 "SHOULD be invalidated" semantics, three runtime conditions
// warn-log and drop the offending index (continuing with the rest):
//   - SPDM block not present at the requested index
//   - index appears more than once in the indirect list
//   - target field already populated by a direct measurement or earlier index
// A dropped index leaves the corresponding mvm field unset on the resolved
// MeasurementValues. If the dropped measurement was relevant to a reference
// value, the verifier catches the omission later when claims fail to match.
// A digest-typed indirect ref with hash_algorithm_id == 0 is a hard error
// (caller bug: SPDM-negotiated algorithm not supplied).
Error resolve_measurement_values(
    const MeasurementValues& in,
    const SpdmMeasurementRecordParser* records,
    int32_t hash_algorithm_id,
    MeasurementValues& out) {
    auto version = clone_unique(in.getVersion());
    auto flags = clone_unique(in.getFlags());
    auto raw_value = clone_unique(in.getRawValue());
    auto raw_value_mask = clone_unique(in.getRawValueMask());
    auto name = clone_unique(in.getName());
    auto int_range = clone_unique(in.getIntRange());
    auto svn = clone_unique(in.getSvn());
    auto digests = in.getDigests();

    if (in.getSpdmIndirect() != nullptr) {
        if (records == nullptr) {
            LOG_ERROR("CoEV->ECT: measurement carries an spdm-indirect reference "
                "but no SPDM measurement records were provided");
            return Error::BadArgument;
        }
        std::unordered_set<uint8_t> seen;
        for (uint64_t index_u64 : in.getSpdmIndirect()->getIndexes()) {
            if (index_u64 > std::numeric_limits<uint8_t>::max()) {
                LOG_WARN("CoEV->ECT: spdm-indirect index " + std::to_string(index_u64)
                    + " > 255; invalidating");
                continue;
            }
            auto index = static_cast<uint8_t>(index_u64);
            if (seen.count(index) != 0) {
                LOG_WARN("CoEV->ECT: spdm-indirect index " + std::to_string(index)
                    + " appears multiple times; invalidating duplicate");
                continue;
            }
            seen.insert(index);

            DmtfMeasurementBlock block;
            if (records->get_dmtf_measurement_block(index, block) != Error::Ok) {
                LOG_WARN("CoEV->ECT: spdm-indirect index " + std::to_string(index)
                    + " not present in SPDM measurement record; invalidating");
                continue;
            }

            const uint8_t dmtf = block.get_measurement_value_type();
            const std::vector<uint8_t>& bytes = block.get_measurement_value();

            if (dmtf <= kDmtfTypeDigestMax) {
                if (hash_algorithm_id == 0) {
                    LOG_ERROR("CoEV->ECT: digest-type indirect ref at index "
                        + std::to_string(index)
                        + " but hash_algorithm_id is 0");
                    return Error::BadArgument;
                }
                // SPDM negotiates a single hash algorithm for the entire
                // measurement record, so every digest-typed indirect ref
                // resolves under the same algorithm. The verifier treats
                // duplicate evidence digest algorithms as a spec-level
                // error (see compare_digests in corim_verify.cpp); guard
                // against that here by dropping any colliding index.
                bool dup_alg = false;
                for (const auto& existing : digests) {
                    int32_t existing_alg = 0;
                    if (existing.getAlgorithm(existing_alg)
                        && existing_alg == hash_algorithm_id) {
                        dup_alg = true;
                        break;
                    }
                }
                if (dup_alg) {
                    LOG_WARN("CoEV->ECT: collision on 'digests' field (algorithm "
                        + std::to_string(hash_algorithm_id)
                        + " already present); invalidating index "
                        + std::to_string(index));
                    continue;
                }
                digests.emplace_back(hash_algorithm_id, ByteString(bytes));
            } else if (dmtf == kDmtfTypeVersion) {
                if (version) {
                    LOG_WARN("CoEV->ECT: collision on 'version' field; invalidating index "
                        + std::to_string(index));
                    continue;
                }
                // SPDM version values are expected to be ASCII text;
                // anything with the high bit set is invalidated.
                if (!is_ascii_bytes(bytes)) {
                    LOG_WARN("CoEV->ECT: 0x86 version bytes at index "
                        + std::to_string(index)
                        + " contain non-ASCII bytes; invalidating");
                    continue;
                }
                version = std::unique_ptr<Version>(new Version(
                    std::string(bytes.begin(), bytes.end())));
            } else if (dmtf == kDmtfTypeSvn) {
                if (svn) {
                    LOG_WARN("CoEV->ECT: collision on 'svn' field; invalidating index "
                        + std::to_string(index));
                    continue;
                }
                if (bytes.size() > kMaxSvnByteCount) {
                    LOG_WARN("CoEV->ECT: 0x87 svn at index " + std::to_string(index)
                        + " is " + std::to_string(bytes.size())
                        + " bytes (> " + std::to_string(kMaxSvnByteCount)
                        + "); invalidating");
                    continue;
                }
                uint64_t svn_val = 0;
                for (size_t i = 0; i < bytes.size(); ++i) {
                    svn_val |= static_cast<uint64_t>(bytes[i]) << (kBitsPerByte * i);
                }
                if (svn_val > std::numeric_limits<uint32_t>::max()) {
                    LOG_WARN("CoEV->ECT: 0x87 svn at index " + std::to_string(index)
                        + " exceeds uint32 range; invalidating");
                    continue;
                }
                svn = std::unique_ptr<Svn>(new Svn(SvnKind::kExact,
                    static_cast<uint32_t>(svn_val)));
            } else {
                // 0x85, 0x80, 0x81, 0xFF, and gap bytes all map to raw-value
                // per Table 7 (the table row "0x80, 0xFF" is a catch-all by
                // its prose, not a literal byte list).
                if (raw_value) {
                    LOG_WARN("CoEV->ECT: collision on 'raw-value' field; invalidating index "
                        + std::to_string(index));
                    continue;
                }
                raw_value = std::unique_ptr<ByteString>(new ByteString(bytes));
            }
        }
    }

    out = MeasurementValues(
        std::move(version), std::move(flags), std::move(raw_value),
        std::move(raw_value_mask), std::move(name), std::move(int_range),
        std::move(svn), std::move(digests), nullptr);
    return Error::Ok;
}

// Core conversions parameterised on a nullable SPDM record source. A null
// `records` means "no SPDM measurement records available": a measurement that
// carries an spdm-indirect reference is then a hard error (see
// resolve_measurement_values), while fully self-contained evidence converts
// normally.
Error resolve_triple(
    const EvidenceTripleRecord& triple,
    const SpdmMeasurementRecordParser* records,
    int32_t hash_algorithm_id,
    Ect& out) {
    if (triple.getMeasurements().empty()) {
        LOG_ERROR("CoEV->ECT: evidence-triple-record has zero measurements");
        return Error::EvidenceMalformed;
    }
    std::vector<MeasurementMap> resolved_measurements;
    resolved_measurements.reserve(triple.getMeasurements().size());
    for (const auto& meas : triple.getMeasurements()) {
        MeasurementValues resolved;
        Error err = resolve_measurement_values(
            meas.getValues(), records, hash_algorithm_id, resolved);
        if (err != Error::Ok) {
            return err;
        }
        resolved_measurements.emplace_back(meas.getKey(), std::move(resolved));
    }
    out = Ect(triple.getEnvironment(), std::move(resolved_measurements));
    return Error::Ok;
}

Error resolve_concise(
    const ConciseEvidence& ce,
    const SpdmMeasurementRecordParser* records,
    int32_t hash_algorithm_id,
    std::vector<Ect>& out) {
    if (ce.getEvTriples().getEvidenceTriples().empty()) {
        LOG_ERROR("CoEV->ECT: ConciseEvidence has zero evidence-triples");
        return Error::EvidenceMalformed;
    }
    for (const auto& triple : ce.getEvTriples().getEvidenceTriples()) {
        Ect ect;
        Error err = resolve_triple(triple, records, hash_algorithm_id, ect);
        if (err != Error::Ok) {
            return err;
        }
        out.push_back(std::move(ect));
    }
    return Error::Ok;
}

}  // namespace

Error evidence_triple_to_ect(
    const EvidenceTripleRecord& triple,
    const SpdmMeasurementRecordParser& spdm_records,
    int32_t hash_algorithm_id,
    Ect& out) {
    return resolve_triple(triple, &spdm_records, hash_algorithm_id, out);
}

Error concise_evidence_to_ects(
    const ConciseEvidence& ce,
    const SpdmMeasurementRecordParser& spdm_records,
    int32_t hash_algorithm_id,
    std::vector<Ect>& out) {
    return resolve_concise(ce, &spdm_records, hash_algorithm_id, out);
}

Error concise_evidence_to_ects(
    const ConciseEvidence& ce,
    std::vector<Ect>& out) {
    return resolve_concise(ce, nullptr, /*hash_algorithm_id=*/0, out);
}

Error spdm_toc_to_ects(
    const SpdmToc& toc,
    const SpdmMeasurementRecordParser& spdm_records,
    int32_t hash_algorithm_id,
    std::vector<Ect>& ects_out,
    std::vector<CorimLocatorMap>& rim_locators_out) {
    for (const auto& ce : toc.getEvidence()) {
        Error err = concise_evidence_to_ects(ce, spdm_records, hash_algorithm_id, ects_out);
        if (err != Error::Ok) {
            return err;
        }
    }
    for (const auto& locator : toc.getRimLocators()) {
        rim_locators_out.push_back(locator);
    }
    return Error::Ok;
}

}  // namespace nvattestation
