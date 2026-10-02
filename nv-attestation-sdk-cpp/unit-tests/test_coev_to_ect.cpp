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
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "nv_attestation/corim_evidence/coev_to_ect.h"
#include "nv_attestation/spdm/spdm_measurement_records.hpp"
#include "test_utils.h"

namespace nvattestation {
namespace {

constexpr const char* kCoevFixtureDir = "testdata/sample_rims/coev";

std::string coev_golden_path(const std::string& name) {
    return std::string(kCoevFixtureDir) + "/golden/" + name + ".json";
}

// Load a .cbor fixture materialized by scripts/prepare-test-data.sh
// (build step + gtest Environment::SetUp() both invoke the prep script).
std::vector<uint8_t> load_coev_fixture(const std::string& name) {
    const std::string path = std::string(kCoevFixtureDir) + "/" + name + ".cbor";
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        ADD_FAILURE() << "Failed to open fixture: " << path;
        return {};
    }
    return std::vector<uint8_t>(
        (std::istreambuf_iterator<char>(stream)),
        std::istreambuf_iterator<char>());
}

// Default-constructed parser: empty m_dmtf_measurement_blocks map. Every
// get_dmtf_measurement_block(index, ...) call returns SpdmFieldNotFound,
// which the mapper handles as a spec-driven "invalidate the index" warn.
// Suitable for tests whose inputs carry no indirect refs.
SpdmMeasurementRecordParser empty_spdm_records() {
    return SpdmMeasurementRecordParser{};
}

constexpr int32_t kNoDigestAlg = 0;  // sentinel: "no digest-typed indirect refs expected"
constexpr int32_t kSha384Alg = 7;    // IANA NI / COSE alg ID for sha-384

// One block to put into a synthetic SPDM measurement-record blob.
struct DmtfBlockSpec {
    uint8_t index;           // SPDM measurement index (>= 1)
    uint8_t dmtf_type;       // DMTFSpecMeasurementValueType byte
    std::vector<uint8_t> value;
};

// Build a parsed SpdmMeasurementRecordParser from synthetic block specs.
// Wire format (per parse_measurement_block in spdm_measurement_records.cpp):
//   [ index(1), spec(0x01), inner_size_le(2),
//     dmtf_type(1), value_size_le(2), value_bytes... ]  -- repeated num_blocks times
std::unique_ptr<SpdmMeasurementRecordParser> make_spdm_records(
    const std::vector<DmtfBlockSpec>& blocks) {
    std::vector<uint8_t> record;
    for (const auto& b : blocks) {
        record.push_back(b.index);
        record.push_back(0x01);  // MeasurementSpecification: DMTF
        const auto value_size = static_cast<uint16_t>(b.value.size());
        const auto inner_size = static_cast<uint16_t>(value_size + 3);
        record.push_back(static_cast<uint8_t>(inner_size & 0xFFU));
        record.push_back(static_cast<uint8_t>((inner_size >> 8) & 0xFFU));
        record.push_back(b.dmtf_type);
        record.push_back(static_cast<uint8_t>(value_size & 0xFFU));
        record.push_back(static_cast<uint8_t>((value_size >> 8) & 0xFFU));
        record.insert(record.end(), b.value.begin(), b.value.end());
    }
    return SpdmMeasurementRecordParser::create(record, static_cast<uint8_t>(blocks.size()));
}

TEST(SpdmMeasurementRecordParser, DuplicateIndexesRejected) {
    auto records = make_spdm_records({
        {0xFD, 0x84, {0xAA}},
        {0xFD, 0x84, {0xBB}},
    });
    EXPECT_EQ(records, nullptr);
}

// Build a one-measurement EvidenceTripleRecord whose single MeasurementValues
// carries the given spdm-indirect index list. Used by the resolution tests.
EvidenceTripleRecord make_indirect_triple(std::vector<uint64_t> indirect_indexes) {
    auto indirect = std::unique_ptr<SpdmIndirectMap>(new SpdmIndirectMap(std::move(indirect_indexes)));
    MeasurementValues mv(
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        std::vector<Digest>{},
        std::move(indirect));
    std::vector<MeasurementMap> measurements;
    measurements.emplace_back(MeasurementMapKey::ofAbsent(), std::move(mv));
    return EvidenceTripleRecord(EnvironmentMap{}, std::move(measurements));
}

TEST(CoevToEct, SingleRecordSingleMeasurementBecomesOneEct) {
    EnvironmentMap env;
    std::vector<MeasurementMap> measurements;
    measurements.emplace_back();
    EvidenceTripleRecord triple(std::move(env), std::move(measurements));

    auto records = empty_spdm_records();
    Ect out;
    ASSERT_EQ(evidence_triple_to_ect(triple, records, kNoDigestAlg, out), Error::Ok);
    EXPECT_EQ(out.getClaims().size(), 1u);
}

TEST(CoevToEct, MultiMeasurementPreserved) {
    EnvironmentMap env;
    std::vector<MeasurementMap> measurements;
    measurements.emplace_back();
    measurements.emplace_back();
    measurements.emplace_back();
    EvidenceTripleRecord triple(std::move(env), std::move(measurements));

    auto records = empty_spdm_records();
    Ect out;
    ASSERT_EQ(evidence_triple_to_ect(triple, records, kNoDigestAlg, out), Error::Ok);
    EXPECT_EQ(out.getClaims().size(), 3u);
}

// ConciseEvidence with N evidence-triples produces N Ects appended to `out`.

TEST(CoevToEct, AppendsOneEctPerEvidenceTriple) {
    std::vector<EvidenceTripleRecord> records;
    {
        std::vector<MeasurementMap> m;
        m.emplace_back();
        records.emplace_back(EnvironmentMap{}, std::move(m));
    }
    {
        std::vector<MeasurementMap> m;
        m.emplace_back();
        m.emplace_back();
        records.emplace_back(EnvironmentMap{}, std::move(m));
    }
    ConciseEvidence ce(EvTriples(std::move(records)));

    auto spdm = empty_spdm_records();
    std::vector<Ect> out;
    ASSERT_EQ(concise_evidence_to_ects(ce, spdm, kNoDigestAlg, out), Error::Ok);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0].getClaims().size(), 1u);
    EXPECT_EQ(out[1].getClaims().size(), 2u);
}

TEST(CoevToEct, AppendsToExistingVector) {
    std::vector<EvidenceTripleRecord> records;
    {
        std::vector<MeasurementMap> m;
        m.emplace_back();
        records.emplace_back(EnvironmentMap{}, std::move(m));
    }
    ConciseEvidence ce(EvTriples(std::move(records)));

    auto spdm = empty_spdm_records();
    std::vector<Ect> out;
    out.emplace_back();   // pre-existing Ect; the mapper must not clobber it
    ASSERT_EQ(concise_evidence_to_ects(ce, spdm, kNoDigestAlg, out), Error::Ok);
    EXPECT_EQ(out.size(), 2u);
}

// Build a minimal ConciseEvidence with N evidence-triples, one measurement
// per triple, used to populate SpdmToc inputs in the tests below.
ConciseEvidence make_concise_evidence_with(size_t triple_count) {
    std::vector<EvidenceTripleRecord> records;
    records.reserve(triple_count);
    for (size_t i = 0; i < triple_count; ++i) {
        std::vector<MeasurementMap> m;
        m.emplace_back();
        records.emplace_back(EnvironmentMap{}, std::move(m));
    }
    return ConciseEvidence(EvTriples(std::move(records)));
}

// The no-SPDM overload converts self-contained concise-evidence (no
// spdm-indirect references) without any measurement-record source.
TEST(CoevToEct, NoSpdmOverloadConvertsSelfContained) {
    std::vector<Ect> out;
    ASSERT_EQ(concise_evidence_to_ects(make_concise_evidence_with(2), out), Error::Ok);
    EXPECT_EQ(out.size(), 2u);
}

// The no-SPDM overload rejects evidence carrying an spdm-indirect reference,
// since there are no records to resolve it against.
TEST(CoevToEct, NoSpdmOverloadRejectsIndirectRef) {
    std::vector<EvidenceTripleRecord> records;
    records.push_back(make_indirect_triple({1}));
    ConciseEvidence ce(EvTriples(std::move(records)));

    std::vector<Ect> out;
    EXPECT_EQ(concise_evidence_to_ects(ce, out), Error::BadArgument);
}

TEST(CoevToEct, SingleConciseEvidenceProducesEctsAndEmptyLocators) {
    std::vector<ConciseEvidence> evidence;
    evidence.push_back(make_concise_evidence_with(2));
    SpdmToc toc(std::move(evidence));

    auto spdm = empty_spdm_records();
    std::vector<Ect> ects;
    std::vector<CorimLocatorMap> locators;
    ASSERT_EQ(spdm_toc_to_ects(toc, spdm, kNoDigestAlg, ects, locators), Error::Ok);
    EXPECT_EQ(ects.size(), 2u);
    EXPECT_TRUE(locators.empty());
}

TEST(CoevToEct, MultipleConciseEvidencePreserveOrder) {
    std::vector<ConciseEvidence> evidence;
    evidence.push_back(make_concise_evidence_with(1));
    evidence.push_back(make_concise_evidence_with(3));
    SpdmToc toc(std::move(evidence));

    auto spdm = empty_spdm_records();
    std::vector<Ect> ects;
    std::vector<CorimLocatorMap> locators;
    ASSERT_EQ(spdm_toc_to_ects(toc, spdm, kNoDigestAlg, ects, locators), Error::Ok);
    EXPECT_EQ(ects.size(), 4u);   // 1 + 3, in order
}

// ============================================================================
// spdm-indirect resolution (§3.1 of design doc).
// Each test sets up a one-measurement triple with indirect indexes and a
// matching synthetic SPDM record, then verifies the resolved Ect's
// MeasurementValues carries the expected typed fields.
// ============================================================================

// Returns the (single) MeasurementValues from a freshly-resolved triple.
const MeasurementValues& resolved_mv(const Ect& ect) {
    EXPECT_EQ(ect.getClaims().size(), 1u);
    return ect.getClaims()[0].getValues();
}

TEST(CoevToEct, Dmtf85ProducesRawValue) {
    std::vector<uint8_t> bytes = {0xDE, 0xAD, 0xBE, 0xEF};
    auto records = make_spdm_records({{1, 0x85, bytes}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    ASSERT_NE(mv.getRawValue(), nullptr);
    EXPECT_EQ(mv.getRawValue()->size(), bytes.size());
    EXPECT_EQ(0, std::memcmp(mv.getRawValue()->data(), bytes.data(), bytes.size()));
    EXPECT_EQ(mv.getSpdmIndirect(), nullptr);   // D10: cleared after resolution
}

TEST(CoevToEct, Dmtf86ProducesVersionFromAscii) {
    const std::string text = "v1.2.3";
    std::vector<uint8_t> bytes(text.begin(), text.end());
    auto records = make_spdm_records({{1, 0x86, bytes}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    ASSERT_NE(mv.getVersion(), nullptr);
    EXPECT_EQ(mv.getVersion()->getValue(), text);
}

TEST(CoevToEct, Dmtf87ProducesSvnFromLittleEndian) {
    // SPDM SVN is little-endian per CoEV-SPDM v1.1 footnote 2.
    // Bytes {0x05, 0x06, 0x07, 0x08} -> uint32 0x08070605 = 134678021.
    std::vector<uint8_t> bytes = {0x05, 0x06, 0x07, 0x08};
    auto records = make_spdm_records({{1, 0x87, bytes}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    ASSERT_NE(mv.getSvn(), nullptr);
    EXPECT_EQ(mv.getSvn()->kind, SvnKind::kExact);
    EXPECT_EQ(mv.getSvn()->value, 0x08070605U);
}

TEST(CoevToEct, Dmtf87SvnShorterThanFourBytesZeroExtends) {
    // One byte 0x42 -> uint32 0x42.
    std::vector<uint8_t> bytes = {0x42};
    auto records = make_spdm_records({{1, 0x87, bytes}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    ASSERT_NE(mv.getSvn(), nullptr);
    EXPECT_EQ(mv.getSvn()->value, 0x42U);
}

TEST(CoevToEct, DmtfDigestRangeAppendsToDigests) {
    // Any byte in 0x00..0x7F is a digest. Pick 0x0B (typical for hashed firmware).
    // Use 48 bytes (sha-384 size, matching kSha384Alg).
    std::vector<uint8_t> bytes(48, 0xAB);
    auto records = make_spdm_records({{1, 0x0B, bytes}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kSha384Alg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    ASSERT_EQ(mv.getDigests().size(), 1u);
    int32_t alg = 0;
    ASSERT_TRUE(mv.getDigests()[0].getAlgorithm(alg));
    EXPECT_EQ(alg, kSha384Alg);
    EXPECT_EQ(mv.getDigests()[0].getValue().size(), bytes.size());
}

TEST(CoevToEct, Dmtf80MapsToRawValueCatchAll) {
    std::vector<uint8_t> bytes = {0xCA, 0xFE};
    auto records = make_spdm_records({{1, 0x80, bytes}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    ASSERT_NE(mv.getRawValue(), nullptr);
    EXPECT_EQ(mv.getRawValue()->size(), bytes.size());
}

TEST(CoevToEct, GapByteAlsoMapsToRawValueCatchAll) {
    // 0x83 falls in the gap range (0x82-0x84). Per Table 7's catch-all prose,
    // any DMTF byte not in {0x85, 0x86, 0x87, 0x00..0x7F} -> raw-value.
    std::vector<uint8_t> bytes = {0xAA, 0xBB, 0xCC};
    auto records = make_spdm_records({{1, 0x83, bytes}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    ASSERT_NE(mv.getRawValue(), nullptr);
    EXPECT_EQ(mv.getRawValue()->size(), bytes.size());
}

TEST(CoevToEct, MultiIndexComposesIntoDifferentFields) {
    // Index 1 -> version, index 2 -> svn, index 3 -> digest.
    // All three should land on the same resulting MeasurementValues.
    std::vector<uint8_t> version_bytes = {'1', '.', '0'};
    std::vector<uint8_t> svn_bytes = {0x07};
    std::vector<uint8_t> digest_bytes(48, 0x11);
    auto records = make_spdm_records({
        {1, 0x86, version_bytes},
        {2, 0x87, svn_bytes},
        {3, 0x42, digest_bytes},   // 0x42 is in the digest range
    });
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1, 2, 3});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kSha384Alg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    ASSERT_NE(mv.getVersion(), nullptr);
    EXPECT_EQ(mv.getVersion()->getValue(), "1.0");
    ASSERT_NE(mv.getSvn(), nullptr);
    EXPECT_EQ(mv.getSvn()->value, 7U);
    ASSERT_EQ(mv.getDigests().size(), 1u);
}

// ===== Invalidation paths (spec §6.5 "SHOULD be invalidated") =====

TEST(CoevToEct, MissingBlockInvalidatesIndex) {
    // Indirect ref points at index 5 but record has no block at 5.
    auto records = make_spdm_records({{1, 0x85, {0x01, 0x02}}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({5});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    EXPECT_EQ(mv.getRawValue(), nullptr);   // index dropped
    EXPECT_EQ(mv.getSpdmIndirect(), nullptr); // still cleared
}

TEST(CoevToEct, DuplicateIndexInvalidatesDuplicates) {
    // Two indexes both = 1; second occurrence dropped.
    auto records = make_spdm_records({{1, 0x86, {'v', '1'}}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1, 1});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    ASSERT_NE(mv.getVersion(), nullptr);
    EXPECT_EQ(mv.getVersion()->getValue(), "v1");
}

TEST(CoevToEct, MvmKeyCollisionDropsSecondIndex) {
    // Both indexes resolve to 'version'; the second collides and gets dropped.
    auto records = make_spdm_records({
        {1, 0x86, {'f', 'i', 'r', 's', 't'}},
        {2, 0x86, {'s', 'e', 'c', 'o', 'n', 'd'}},
    });
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1, 2});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    ASSERT_NE(mv.getVersion(), nullptr);
    EXPECT_EQ(mv.getVersion()->getValue(), "first");
}

TEST(CoevToEct, NonAsciiVersionBytesDropsIndex) {
    // Any byte with the high bit set is non-ASCII -> reject.
    std::vector<uint8_t> bad = {0xC3, 0x28};
    auto records = make_spdm_records({{1, 0x86, bad}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::Ok);

    EXPECT_EQ(resolved_mv(ect).getVersion(), nullptr);
}

TEST(CoevToEct, HighBitInOtherwiseAsciiVersionDropsIndex) {
    // Mostly-ASCII version string with one high-bit byte. Drop the index.
    std::vector<uint8_t> mixed = {'v', '1', '.', 0x80};
    auto records = make_spdm_records({{1, 0x86, mixed}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::Ok);

    EXPECT_EQ(resolved_mv(ect).getVersion(), nullptr);
}

// SPDM negotiates a single hash algorithm for the entire measurement
// record, so two digest-typed indirect indexes in the same
// MeasurementValues would produce two Digest entries under the same
// algorithm. The verifier rejects that as a spec error, so the resolver
// drops the second colliding index here.
TEST(CoevToEct, DuplicateDigestAlgInvalidatesSecondIndex) {
    const std::vector<uint8_t> first_digest(48, 0x11);
    const std::vector<uint8_t> second_digest(48, 0x22);
    auto records = make_spdm_records({
        {1, 0x42, first_digest},
        {2, 0x42, second_digest},
    });
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1, 2});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kSha384Alg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    ASSERT_EQ(mv.getDigests().size(), 1u);
    EXPECT_EQ(mv.getDigests()[0].getValue().size(), first_digest.size());
}

TEST(CoevToEct, SvnLargerThanFourBytesOverflowDrops) {
    // Eight bytes with high bit set -> exceeds uint32 -> invalidate.
    std::vector<uint8_t> svn_overflow = {0, 0, 0, 0, 1, 0, 0, 0};   // 0x1_00000000
    auto records = make_spdm_records({{1, 0x87, svn_overflow}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1});
    Ect ect;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::Ok);

    const auto& mv = resolved_mv(ect);
    EXPECT_EQ(mv.getSvn(), nullptr);
}

// ===== Hard error =====

TEST(CoevToEct, DigestWithoutHashAlgReturnsBadArgument) {
    std::vector<uint8_t> digest_bytes(32, 0x55);
    auto records = make_spdm_records({{1, 0x42, digest_bytes}});
    ASSERT_NE(records, nullptr);

    auto triple = make_indirect_triple({1});
    Ect ect;
    EXPECT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, ect), Error::BadArgument);
}

// ============================================================================
// Mapper-level structural error tests.
// ============================================================================

TEST(CoevToEct, EmptyEvTriplesReturnsEvidenceMalformed) {
    ConciseEvidence ce(EvTriples{});   // zero records
    auto spdm = empty_spdm_records();
    std::vector<Ect> out;
    EXPECT_EQ(concise_evidence_to_ects(ce, spdm, kNoDigestAlg, out), Error::EvidenceMalformed);
}

TEST(CoevToEct, EmptyTripleMeasurementsReturnsEvidenceMalformed) {
    EvidenceTripleRecord triple(EnvironmentMap{}, std::vector<MeasurementMap>{});
    auto spdm = empty_spdm_records();
    Ect out;
    EXPECT_EQ(evidence_triple_to_ect(triple, spdm, kNoDigestAlg, out), Error::EvidenceMalformed);
}

TEST(CoevToEct, RimLocatorsCopiedThrough) {
    std::vector<ConciseEvidence> evidence;
    evidence.push_back(make_concise_evidence_with(1));

    std::vector<CorimLocatorMap> input_locators;
    input_locators.emplace_back(std::vector<std::string>{"https://rim.example.com/a.corim"});
    input_locators.emplace_back(std::vector<std::string>{
        "https://rim.example.com/b.corim",
        "https://rim.example.com/b-mirror.corim"});
    SpdmToc toc(std::move(evidence), std::move(input_locators));

    auto spdm = empty_spdm_records();
    std::vector<Ect> ects;
    std::vector<CorimLocatorMap> locators;
    ASSERT_EQ(spdm_toc_to_ects(toc, spdm, kNoDigestAlg, ects, locators), Error::Ok);
    ASSERT_EQ(locators.size(), 2u);
    ASSERT_EQ(locators[0].getUris().size(), 1u);
    EXPECT_EQ(locators[0].getUris()[0], "https://rim.example.com/a.corim");
    ASSERT_EQ(locators[1].getUris().size(), 2u);
    EXPECT_EQ(locators[1].getUris()[1], "https://rim.example.com/b-mirror.corim");
}

// ============================================================================
// End-to-end scenario tests. Each builds a complete realistic input
// (SpdmToc + paired SPDM records), runs the full pipeline, and asserts every
// output field inline. A follow-up MR migrates these to a data-driven
// golden-JSON style; the inline assertions stay for now.
// ============================================================================

// Helper: build an EnvironmentMap carrying a typed ClassMap (vendor/model/layer),
// matching the shape an SPDM Responder cert chain would translate into.
EnvironmentMap make_env_class(const std::string& vendor,
                              const std::string& model,
                              uint32_t layer) {
    auto cls = std::unique_ptr<ClassMap>(new ClassMap(
        nullptr,
        std::unique_ptr<std::string>(new std::string(vendor)),
        std::unique_ptr<std::string>(new std::string(model)),
        std::unique_ptr<uint32_t>(new uint32_t(layer)),
        nullptr));
    return EnvironmentMap(std::move(cls), nullptr, nullptr);
}

// Models a Rubin-class device manifest: one ConciseEvidence carrying one
// evidence-triple, whose single MeasurementValues references four SPDM
// blocks via spdm-indirect. The blocks span every dispatch family so the
// resulting Ect carries raw-value, version, svn, and a digest together.
TEST(CoevToEct, RubinShapeManifestProducesComposedEct) {
    const std::vector<uint8_t> raw_bytes = {'r', 'a', 'w', 'b', 'i', 't', 's'};
    const std::vector<uint8_t> version_bytes = {'v', '2', '.', '1', '.', '0'};
    const std::vector<uint8_t> svn_bytes = {0x05, 0x00, 0x00, 0x00};   // LE -> 5
    const std::vector<uint8_t> digest_bytes(48, 0xAB);                 // sha-384 size
    auto records = make_spdm_records({
        {1, 0x85, raw_bytes},
        {2, 0x86, version_bytes},
        {3, 0x87, svn_bytes},
        {4, 0x42, digest_bytes},
    });
    ASSERT_NE(records, nullptr);

    auto env = make_env_class("NVIDIA", "Rubin", 0);
    auto indirect = std::unique_ptr<SpdmIndirectMap>(new SpdmIndirectMap({1, 2, 3, 4}));
    MeasurementValues mv(
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        std::vector<Digest>{}, std::move(indirect));
    std::vector<MeasurementMap> measurements;
    measurements.emplace_back(MeasurementMapKey::ofAbsent(), std::move(mv));
    std::vector<EvidenceTripleRecord> triples;
    triples.emplace_back(std::move(env), std::move(measurements));
    std::vector<ConciseEvidence> evidence;
    evidence.emplace_back(EvTriples(std::move(triples)));
    SpdmToc toc(std::move(evidence));

    std::vector<Ect> ects;
    std::vector<CorimLocatorMap> locators;
    ASSERT_EQ(spdm_toc_to_ects(toc, *records, kSha384Alg, ects, locators), Error::Ok);

    nlohmann::json j = {{"ects", ects}, {"rim_locators", locators}};
    compare_to_golden(j, coev_golden_path("scenarios_rubin_shape"));
}

// Models a multi-component SpdmToc: two ConciseEvidence entries, each
// describing a different SPDM-managed device component. The first uses a
// direct measurement (no indirect ref); the second uses indirect resolution.
// Order is preserved through the per-document walk.
TEST(CoevToEct, MultiCeProducesTwoEctsInOrder) {
    auto records = make_spdm_records({
        {1, 0x87, std::vector<uint8_t>{0x42, 0x00, 0x00, 0x00}},   // svn = 66
    });
    ASSERT_NE(records, nullptr);

    // First CE: direct version, no indirect.
    std::vector<EvidenceTripleRecord> triples_a;
    {
        auto version = std::unique_ptr<Version>(new Version(std::string("1.0")));
        MeasurementValues mv(
            std::move(version),
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            std::vector<Digest>{}, nullptr);
        std::vector<MeasurementMap> measurements;
        measurements.emplace_back(MeasurementMapKey::ofAbsent(), std::move(mv));
        triples_a.emplace_back(make_env_class("NVIDIA", "GSP", 1), std::move(measurements));
    }

    // Second CE: indirect resolution -> svn.
    std::vector<EvidenceTripleRecord> triples_b;
    {
        auto indirect = std::unique_ptr<SpdmIndirectMap>(new SpdmIndirectMap({1}));
        MeasurementValues mv(
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            std::vector<Digest>{}, std::move(indirect));
        std::vector<MeasurementMap> measurements;
        measurements.emplace_back(MeasurementMapKey::ofAbsent(), std::move(mv));
        triples_b.emplace_back(make_env_class("NVIDIA", "FSP", 2), std::move(measurements));
    }

    std::vector<ConciseEvidence> evidence;
    evidence.emplace_back(EvTriples(std::move(triples_a)));
    evidence.emplace_back(EvTriples(std::move(triples_b)));
    SpdmToc toc(std::move(evidence));

    std::vector<Ect> ects;
    std::vector<CorimLocatorMap> locators;
    ASSERT_EQ(spdm_toc_to_ects(toc, *records, kNoDigestAlg, ects, locators), Error::Ok);

    nlohmann::json j = {{"ects", ects}, {"rim_locators", locators}};
    compare_to_golden(j, coev_golden_path("scenarios_multi_ce"));
}

// A single MeasurementValues carrying both a direct field (version) AND a
// spdm-indirect ref pointing at a non-conflicting field (svn). Both end up
// on the resolved Ect's MV simultaneously.
TEST(CoevToEct, DirectAndIndirectComposeOnSameMv) {
    auto records = make_spdm_records({
        {1, 0x87, std::vector<uint8_t>{0x99, 0x00, 0x00, 0x00}},   // svn = 153
    });
    ASSERT_NE(records, nullptr);

    auto version = std::unique_ptr<Version>(new Version(std::string("3.14")));
    auto indirect = std::unique_ptr<SpdmIndirectMap>(new SpdmIndirectMap({1}));
    MeasurementValues mv(
        std::move(version),
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        std::vector<Digest>{}, std::move(indirect));
    std::vector<MeasurementMap> measurements;
    measurements.emplace_back(MeasurementMapKey::ofAbsent(), std::move(mv));
    EvidenceTripleRecord triple(EnvironmentMap{}, std::move(measurements));

    Ect out;
    ASSERT_EQ(evidence_triple_to_ect(triple, *records, kNoDigestAlg, out), Error::Ok);

    nlohmann::json j = out;
    compare_to_golden(j, coev_golden_path("scenarios_direct_and_indirect"));
}

// ============================================================================
// .diag fixture tests. These parse the CBOR-encoded fixtures shared with the
// CoEV parser tests (testdata/sample_rims/coev/*.diag, materialised to .cbor
// by scripts/prepare-test-data.sh), run the mapper, and assert on the result
// inline. Smaller surface than the follow-up's planned golden-JSON tests,
// but exercises the parser-to-mapper handoff with real CBOR.
// ============================================================================

// minimal.diag is a single ConciseEvidence carrying one evidence-triple
// whose measurement is a direct sha-256 digest. Mapper should produce a
// single Ect with the same class env and a single digest claim.
TEST(CoevToEct, MinimalFixtureMapsToOneEct) {
    auto bytes = load_coev_fixture("minimal");
    ASSERT_FALSE(bytes.empty());

    ConciseEvidence ce;
    ASSERT_EQ(parse_concise_evidence(bytes, ce), Error::Ok);

    auto spdm = empty_spdm_records();
    std::vector<Ect> ects;
    ASSERT_EQ(concise_evidence_to_ects(ce, spdm, kNoDigestAlg, ects), Error::Ok);

    nlohmann::json j = ects;
    compare_to_golden(j, coev_golden_path("minimal_ects"));
}

// direct_only.diag carries multiple typed direct fields (version, digest,
// name). All should pass through to the resolved Ect unchanged, with
// m_spdm_indirect remaining nullptr.
TEST(CoevToEct, DirectOnlyFixturePreservesAllTypedFields) {
    auto bytes = load_coev_fixture("direct_only");
    ASSERT_FALSE(bytes.empty());

    ConciseEvidence ce;
    ASSERT_EQ(parse_concise_evidence(bytes, ce), Error::Ok);

    auto spdm = empty_spdm_records();
    std::vector<Ect> ects;
    ASSERT_EQ(concise_evidence_to_ects(ce, spdm, kNoDigestAlg, ects), Error::Ok);

    nlohmann::json j = ects;
    compare_to_golden(j, coev_golden_path("direct_only_ects"));
}

// direct_and_indirect.diag has two measurements: one direct sha-256 digest
// and one spdm-indirect at index 49. Mapping requires an SPDM record with
// a block at that index. With a synthetic 0x86-typed block at index 49,
// the resolved Ect carries the direct digest AND a typed version field.
TEST(CoevToEct, DirectAndIndirectFixtureResolvesViaSpdmBlock) {
    auto bytes = load_coev_fixture("direct_and_indirect");
    ASSERT_FALSE(bytes.empty());

    ConciseEvidence ce;
    ASSERT_EQ(parse_concise_evidence(bytes, ce), Error::Ok);

    // Synthetic SPDM block at index 49 holding a version value.
    const std::vector<uint8_t> version_bytes = {'v', '3', '.', '0'};
    auto spdm = make_spdm_records({{49, 0x86, version_bytes}});
    ASSERT_NE(spdm, nullptr);

    std::vector<Ect> ects;
    ASSERT_EQ(concise_evidence_to_ects(ce, *spdm, kNoDigestAlg, ects), Error::Ok);

    nlohmann::json j = ects;
    compare_to_golden(j, coev_golden_path("direct_and_indirect_ects"));
}

// Rim-locator pass-through with full data: a SpdmToc carrying multi-URI
// locators AND a thumbprint should hand both through to rim_locators_out
// verbatim, separate from the produced Ects.
TEST(CoevToEct, RimLocatorsCarryUrisAndThumbprints) {
    std::vector<ConciseEvidence> evidence;
    evidence.push_back(make_concise_evidence_with(1));

    Digest thumbprint(kSha384Alg, ByteString(std::vector<uint8_t>(48, 0x44)));
    std::vector<CorimLocatorMap> input_locators;
    input_locators.emplace_back(
        std::vector<std::string>{
            "https://rim.example.com/primary.corim",
            "https://rim-mirror.example.com/primary.corim"},
        std::vector<Digest>{thumbprint});
    SpdmToc toc(std::move(evidence), std::move(input_locators));

    auto spdm = empty_spdm_records();
    std::vector<Ect> ects;
    std::vector<CorimLocatorMap> locators;
    ASSERT_EQ(spdm_toc_to_ects(toc, spdm, kNoDigestAlg, ects, locators), Error::Ok);

    nlohmann::json j = {{"ects", ects}, {"rim_locators", locators}};
    compare_to_golden(j, coev_golden_path("scenarios_rim_locators"));
}

}  // namespace
}  // namespace nvattestation
