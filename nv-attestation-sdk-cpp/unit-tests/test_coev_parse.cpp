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
#include <fstream>
#include <sstream>
#include <string>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "nv_attestation/corim_evidence/coev.h"
#include "nv_attestation/cose.h"
#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/nv_x509.h"
#include "test_utils.h"

namespace nvattestation {
namespace {

constexpr const char* kCoevFixtureDir = "testdata/sample_rims/coev";

// Load a fixture .cbor file (materialized from its .diag source by
// scripts/prepare-test-data.sh, which runs both via the make target and via
// the gtest Environment::SetUp() hook in main.cpp).
std::vector<uint8_t> load_fixture(const std::string& name) {
    std::string path = std::string(kCoevFixtureDir) + "/" + name + ".cbor";
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        ADD_FAILURE() << "Failed to open fixture: " << path;
        return {};
    }
    return std::vector<uint8_t>(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
}

std::string coev_golden_path(const std::string& name) {
    return std::string(kCoevFixtureDir) + "/golden/" + name + ".json";
}

TEST(SpdmIndirectMap, ConstructAndAccess) {
    SpdmIndirectMap m({40, 41, 45});
    EXPECT_EQ(m.getIndexes().size(), 3u);
    EXPECT_EQ(m.getIndexes()[0], 40u);
    EXPECT_EQ(m.getIndexes()[2], 45u);
}

TEST(SpdmIndirectMap, ToJsonSerializes) {
    SpdmIndirectMap m({49});
    nlohmann::json j;
    to_json(j, m);
    EXPECT_EQ(j["indexes"], nlohmann::json::array({49}));
}

TEST(SpdmIndirectMap, EmptyIndexes) {
    SpdmIndirectMap m;
    EXPECT_TRUE(m.getIndexes().empty());
}

// MeasurementValues was extended with an optional m_spdm_indirect field for
// the TCG DICE §7.1 extension. These tests verify the field carries through
// construction, deep-copy, and JSON serialization.

TEST(MeasurementValues, HoldsSpdmIndirectField) {
    auto indirect = std::unique_ptr<SpdmIndirectMap>(new SpdmIndirectMap({49, 50}));
    MeasurementValues mv(
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        std::vector<Digest>{},
        std::move(indirect));
    ASSERT_NE(mv.getSpdmIndirect(), nullptr);
    EXPECT_EQ(mv.getSpdmIndirect()->getIndexes(), (std::vector<uint64_t>{49, 50}));
}

TEST(MeasurementValues, CopyDeepClonesSpdmIndirect) {
    MeasurementValues a(
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        std::vector<Digest>{},
        std::unique_ptr<SpdmIndirectMap>(new SpdmIndirectMap({1, 2, 3})));
    MeasurementValues b(a);
    ASSERT_NE(b.getSpdmIndirect(), nullptr);
    EXPECT_NE(b.getSpdmIndirect(), a.getSpdmIndirect());
    EXPECT_EQ(b.getSpdmIndirect()->getIndexes(), (std::vector<uint64_t>{1, 2, 3}));
}

TEST(MeasurementValues, ToJsonOmitsSpdmIndirectWhenNull) {
    MeasurementValues mv;
    nlohmann::json j;
    to_json(j, mv);
    EXPECT_FALSE(j.contains("spdm_indirect"));
}

TEST(MeasurementValues, ToJsonIncludesSpdmIndirectWhenPresent) {
    MeasurementValues mv(
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        std::vector<Digest>{},
        std::unique_ptr<SpdmIndirectMap>(new SpdmIndirectMap({49})));
    nlohmann::json j;
    to_json(j, mv);
    ASSERT_TRUE(j.contains("spdm_indirect"));
    EXPECT_EQ(j["spdm_indirect"]["indexes"], nlohmann::json::array({49}));
}

TEST(CorimLocatorMap, ConstructAndAccess) {
    CorimLocatorMap loc(std::vector<std::string>{"https://rim.example.com/v1/foo.corim"});
    ASSERT_EQ(loc.getUris().size(), 1u);
    EXPECT_EQ(loc.getUris()[0], "https://rim.example.com/v1/foo.corim");
}

TEST(CorimLocatorMap, ToJsonSerializes) {
    CorimLocatorMap loc(std::vector<std::string>{
        "https://rim.example.com/x.corim",
        "https://rim.example.com/x-mirror.corim"});
    nlohmann::json j;
    to_json(j, loc);
    ASSERT_EQ(j["uris"].size(), 2u);
    EXPECT_EQ(j["uris"][0], "https://rim.example.com/x.corim");
    EXPECT_EQ(j["uris"][1], "https://rim.example.com/x-mirror.corim");
}

TEST(CorimLocatorMap, EmptyDefault) {
    CorimLocatorMap loc;
    EXPECT_TRUE(loc.getUris().empty());
}

TEST(EvidenceTripleRecord, ConstructAndAccess) {
    EnvironmentMap env;
    std::vector<MeasurementMap> meas;
    meas.emplace_back();
    EvidenceTripleRecord rec(std::move(env), std::move(meas));
    EXPECT_EQ(rec.getMeasurements().size(), 1u);
}

TEST(EvidenceTripleRecord, ToJsonHasEnvironmentAndMeasurements) {
    EnvironmentMap env;
    std::vector<MeasurementMap> meas;
    meas.emplace_back();
    meas.emplace_back();
    EvidenceTripleRecord rec(std::move(env), std::move(meas));
    nlohmann::json j;
    to_json(j, rec);
    EXPECT_TRUE(j.contains("environment"));
    ASSERT_TRUE(j.contains("measurements"));
    EXPECT_EQ(j["measurements"].size(), 2u);
}

TEST(EvTriples, ConstructAndAccess) {
    std::vector<EvidenceTripleRecord> records;
    records.emplace_back();
    EvTriples t(std::move(records));
    EXPECT_EQ(t.getEvidenceTriples().size(), 1u);
}

TEST(EvTriples, DefaultIsEmpty) {
    EvTriples t;
    EXPECT_TRUE(t.getEvidenceTriples().empty());
}

TEST(EvTriples, ToJsonHasEvidenceTriples) {
    std::vector<EvidenceTripleRecord> records;
    records.emplace_back();
    EvTriples t(std::move(records));
    nlohmann::json j;
    to_json(j, t);
    ASSERT_TRUE(j.contains("evidence_triples"));
    EXPECT_EQ(j["evidence_triples"].size(), 1u);
}

TEST(ConciseEvidence, ConstructMinimal) {
    ConciseEvidence ce(EvTriples{});
    EXPECT_TRUE(ce.getEvTriples().getEvidenceTriples().empty());
    EXPECT_EQ(ce.getEvidenceId(), nullptr);
    EXPECT_EQ(ce.getProfile(), nullptr);
}

TEST(ConciseEvidence, ConstructWithEvidenceId) {
    auto eid = std::unique_ptr<std::string>(new std::string("uuid:0123"));
    ConciseEvidence ce(EvTriples{}, std::move(eid));
    ASSERT_NE(ce.getEvidenceId(), nullptr);
    EXPECT_EQ(*ce.getEvidenceId(), "uuid:0123");
}

TEST(ConciseEvidence, CopyDeepClonesEvidenceId) {
    auto eid = std::unique_ptr<std::string>(new std::string("uuid:abc"));
    ConciseEvidence a(EvTriples{}, std::move(eid));
    ConciseEvidence b(a);
    ASSERT_NE(b.getEvidenceId(), nullptr);
    EXPECT_NE(b.getEvidenceId(), a.getEvidenceId());
    EXPECT_EQ(*b.getEvidenceId(), "uuid:abc");
}

TEST(SpdmToc, ConstructMinimal) {
    std::vector<ConciseEvidence> evidence;
    evidence.emplace_back();
    SpdmToc toc(std::move(evidence));
    EXPECT_EQ(toc.getEvidence().size(), 1u);
    EXPECT_TRUE(toc.getRimLocators().empty());
    EXPECT_EQ(toc.getProfile(), nullptr);
}

TEST(SpdmToc, ConstructWithRimLocators) {
    std::vector<ConciseEvidence> evidence;
    evidence.emplace_back();
    std::vector<CorimLocatorMap> locators;
    locators.emplace_back(std::vector<std::string>{"https://rim.example.com/x.corim"});
    SpdmToc toc(std::move(evidence), std::move(locators));
    ASSERT_EQ(toc.getRimLocators().size(), 1u);
    ASSERT_EQ(toc.getRimLocators()[0].getUris().size(), 1u);
    EXPECT_EQ(toc.getRimLocators()[0].getUris()[0], "https://rim.example.com/x.corim");
}

TEST(SpdmToc, ToJsonEmitsLocatorsWhenPresent) {
    std::vector<ConciseEvidence> evidence;
    evidence.emplace_back();
    std::vector<CorimLocatorMap> locators;
    locators.emplace_back(std::vector<std::string>{"https://rim.example.com/x.corim"});
    SpdmToc toc(std::move(evidence), std::move(locators));
    nlohmann::json j;
    to_json(j, toc);
    ASSERT_TRUE(j.contains("rim_locators"));
    EXPECT_EQ(j["rim_locators"].size(), 1u);
}

// Smoke tests for the parser entry points. Full happy-path snapshot tests
// will live in CoevSnapshot.* using .diag fixtures (added in later tasks).

TEST(ParseConciseEvidence, EmptyBufferReturnsError) {
    std::vector<uint8_t> empty;
    ConciseEvidence out;
    EXPECT_EQ(parse_concise_evidence(empty, out), Error::EvidenceMalformed);
}

TEST(ParseConciseEvidence, RandomBytesReturnsError) {
    std::vector<uint8_t> bytes{0xff, 0xff, 0xff, 0xff};
    ConciseEvidence out;
    EXPECT_EQ(parse_concise_evidence(bytes, out), Error::EvidenceMalformed);
}

TEST(ParseConciseEvidence, RejectsRfc9277TnTag) {
    // CBOR tag #6.1668557429 = TN(10571) for concise-evidence — we reject.
    std::vector<uint8_t> bytes{0xDA, 0x63, 0x74, 0x2A, 0x75, 0xA0};
    ConciseEvidence out;
    EXPECT_EQ(parse_concise_evidence(bytes, out), Error::EvidenceMalformed);
}

TEST(ParseSpdmToc, EmptyBufferReturnsError) {
    std::vector<uint8_t> empty;
    SpdmToc out;
    EXPECT_EQ(parse_spdm_toc(empty, out), Error::EvidenceMalformed);
}

TEST(ParseSpdmToc, RandomBytesReturnsError) {
    std::vector<uint8_t> bytes{0x82, 0xff, 0xff, 0xff};
    SpdmToc out;
    EXPECT_EQ(parse_spdm_toc(bytes, out), Error::EvidenceMalformed);
}

TEST(ParseSpdmToc, RejectsRfc9277TnTag) {
    // CBOR tag #6.1668557428 = TN(10570) for spdm-toc — we reject.
    std::vector<uint8_t> bytes{0xDA, 0x63, 0x74, 0x2A, 0x74, 0xA0};
    SpdmToc out;
    EXPECT_EQ(parse_spdm_toc(bytes, out), Error::EvidenceMalformed);
}

// Trailing-garbage rejection: a valid CBOR blob followed by one extra
// byte must fail. The decoder reports full success on the leading bytes;
// the entry point catches the unconsumed tail.
TEST(ParseConciseEvidence, TrailingGarbageRejected) {
    auto bytes = load_fixture("minimal");
    ASSERT_FALSE(bytes.empty());
    bytes.push_back(0xFF);
    ConciseEvidence ce;
    EXPECT_EQ(parse_concise_evidence(bytes, ce), Error::EvidenceMalformed);
}

TEST(ParseSpdmToc, TrailingGarbageRejected) {
    auto bytes = load_fixture("accept_locator_thumbprint_array");
    ASSERT_FALSE(bytes.empty());
    bytes.push_back(0xFF);
    SpdmToc toc;
    EXPECT_EQ(parse_spdm_toc(bytes, toc), Error::EvidenceMalformed);
}

// =====================================================================
// Snapshot tests: parse .diag fixtures, compare JSON dump to committed golden.
// =====================================================================

TEST(CoevSnapshot, Minimal) {
    auto bytes = load_fixture("minimal");
    ASSERT_FALSE(bytes.empty());
    ConciseEvidence ce;
    ASSERT_EQ(parse_concise_evidence(bytes, ce), Error::Ok);
    nlohmann::json j;
    to_json(j, ce);
    compare_to_golden(j, coev_golden_path("minimal"));
}

TEST(CoevSnapshot, DirectOnly) {
    auto bytes = load_fixture("direct_only");
    ASSERT_FALSE(bytes.empty());
    ConciseEvidence ce;
    ASSERT_EQ(parse_concise_evidence(bytes, ce), Error::Ok);
    nlohmann::json j;
    to_json(j, ce);
    compare_to_golden(j, coev_golden_path("direct_only"));
}

// One evidence-triple containing two separate measurement-maps — one with
// a direct digest and one with spdm-indirect. The two measurements coexist
// under different mkeys in the same evidence-triple.
TEST(CoevSnapshot, DirectAndIndirect) {
    auto bytes = load_fixture("direct_and_indirect");
    ASSERT_FALSE(bytes.empty());
    ConciseEvidence ce;
    ASSERT_EQ(parse_concise_evidence(bytes, ce), Error::Ok);
    nlohmann::json j;
    to_json(j, ce);
    compare_to_golden(j, coev_golden_path("direct_and_indirect"));
}

// True "mixed" measurement: a SINGLE measurement-values-map carries BOTH a
// direct field (digests) AND the spdm-indirect extension. The CDDL marks
// all measurement-values-map fields as optional, so this is structurally
// valid CBOR; the parser must accept it under the permissive-evidence rule.
TEST(CoevSnapshot, MixedMeasurement) {
    auto bytes = load_fixture("mixed_measurement");
    ASSERT_FALSE(bytes.empty());
    ConciseEvidence ce;
    ASSERT_EQ(parse_concise_evidence(bytes, ce), Error::Ok);
    nlohmann::json j;
    to_json(j, ce);
    compare_to_golden(j, coev_golden_path("mixed_measurement"));
}

// Production-shape CoEV fixture derived from a real attestation report.
// Exercises 23 evidence-triple-records, several with multi-measurement-map
// records using mkey-labelled sub-measurements, and 2 rim-locators. The
// .diag is the cbor-diag round-trip of the source bytes for human-readable
// diffs; the materialized .cbor is byte-identical to the original.
TEST(CoevSnapshot, FullProductionShape) {
    auto bytes = load_fixture("full_production");
    ASSERT_FALSE(bytes.empty());
    SpdmToc toc;
    ASSERT_EQ(parse_spdm_toc(bytes, toc), Error::Ok);
    ASSERT_EQ(toc.getEvidence().size(), 1u);
    EXPECT_EQ(toc.getEvidence()[0].getEvTriples().getEvidenceTriples().size(), 23u);
    EXPECT_EQ(toc.getRimLocators().size(), 2u);
    nlohmann::json j;
    to_json(j, toc);
    compare_to_golden(j, coev_golden_path("full_production"));
}

// =====================================================================
// Permissive-acceptance tests. Each fixture carries content the parser
// does not surface; assertion is that parsing succeeds and the surfaced
// content matches the golden. The per-skip warn-logs are emitted at
// parse time but not asserted (would tie tests to spdlog internals).

TEST(CoevSnapshot, AcceptExtraTriples) {
    auto bytes = load_fixture("accept_extra_triples");
    ASSERT_FALSE(bytes.empty());
    ConciseEvidence ce;
    ASSERT_EQ(parse_concise_evidence(bytes, ce), Error::Ok);
    nlohmann::json j;
    to_json(j, ce);
    compare_to_golden(j, coev_golden_path("accept_extra_triples"));
}

TEST(CoevSnapshot, AcceptLocatorThumbprintArray) {
    auto bytes = load_fixture("accept_locator_thumbprint_array");
    ASSERT_FALSE(bytes.empty());
    SpdmToc toc;
    ASSERT_EQ(parse_spdm_toc(bytes, toc), Error::Ok);
    nlohmann::json j;
    to_json(j, toc);
    compare_to_golden(j, coev_golden_path("accept_locator_thumbprint_array"));
}

TEST(CoevSnapshot, AcceptExtraMvmFields) {
    auto bytes = load_fixture("accept_extra_mvm_fields");
    ASSERT_FALSE(bytes.empty());
    ConciseEvidence ce;
    ASSERT_EQ(parse_concise_evidence(bytes, ce), Error::Ok);
    nlohmann::json j;
    to_json(j, ce);
    compare_to_golden(j, coev_golden_path("accept_extra_mvm_fields"));
}

// Structural-invariant reject: ev-triples-map must have at least one
// triple type populated. The shape-only fixture decodes cleanly at the
// zcbor layer; walk_ev_triples then surfaces the EvidenceMalformed.
TEST(ParseConciseEvidence, EmptyEvTriplesMapRejected) {
    auto bytes = load_fixture("reject_empty_ev_triples");
    ASSERT_FALSE(bytes.empty());
    ConciseEvidence ce;
    EXPECT_EQ(parse_concise_evidence(bytes, ce), Error::EvidenceMalformed);
}

// Same structural-invariant reject as above, but the empty ev-triples-map
// is nested inside a tagged-spdm-toc. Exercises the error-propagation path
// in parse_spdm_toc's per-evidence loop.
TEST(ParseSpdmToc, EmptyEvTriplesMapInNestedEvidenceRejected) {
    auto bytes = load_fixture("reject_empty_ev_triples_in_toc");
    ASSERT_FALSE(bytes.empty());
    SpdmToc toc;
    EXPECT_EQ(parse_spdm_toc(bytes, toc), Error::EvidenceMalformed);
}

// A member whose value fails schema validation is backtracked by zcbor and
// then absorbed by the `* int => any` extension entry, so the *_present flag
// alone cannot tell it apart from a member that was never sent. These fixtures
// pin the distinction: each carries a well-formed but schema-invalid member,
// and the parser must reject rather than treat it as absent.

// evidence-triples holds a record missing its mandatory measurement-map list.
//
// The return code alone does not pin this case: both before and after the
// shadowed-key check the parse yields EvidenceMalformed. What changed is *which*
// defect gets reported — previously "ev-triples-map is empty", which sends
// readers hunting a nonexistent problem in their generator. The diagnostic is
// the deliverable here, so the message is asserted. Logs go to stderr
// (log.cpp uses spdlog::stderr_color_mt), which gtest captures directly.
TEST(ParseConciseEvidence, MalformedEvidenceTriplesRejected) {
    auto bytes = load_fixture("reject_malformed_evidence_triples");
    ASSERT_FALSE(bytes.empty());
    ConciseEvidence ce;

    testing::internal::CaptureStderr();
    const Error err = parse_concise_evidence(bytes, ce);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::EvidenceMalformed);
    EXPECT_NE(logs.find("key 0 (evidence-triples) is malformed"), std::string::npos)
        << "expected the malformed-member diagnostic, got:\n" << logs;
    EXPECT_EQ(logs.find("ev-triples-map is empty"), std::string::npos)
        << "the misleading emptiness message must not be used for a member "
           "that was present but malformed:\n" << logs;
}

// rim-locators is a tstr instead of [ 1*8 corim-locator-map ]. Before the
// check this parsed clean with zero RIM URLs and no diagnostic at all.
TEST(ParseSpdmToc, MalformedRimLocatorsRejected) {
    auto bytes = load_fixture("reject_malformed_toc_rim_locators");
    ASSERT_FALSE(bytes.empty());
    SpdmToc toc;

    testing::internal::CaptureStderr();
    const Error err = parse_spdm_toc(bytes, toc);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::EvidenceMalformed);
    EXPECT_NE(logs.find("key 1 (rim-locators) is malformed"), std::string::npos)
        << "expected the malformed-member diagnostic, got:\n" << logs;
}

TEST(ParseSpdmToc, MalformedMemberDoesNotImplicateLaterMembers) {
    auto bytes = load_fixture("reject_malformed_rim_locators_with_valid_profile");
    ASSERT_FALSE(bytes.empty());
    SpdmToc toc;

    testing::internal::CaptureStderr();
    const Error err = parse_spdm_toc(bytes, toc);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::EvidenceMalformed);
    EXPECT_NE(logs.find("key 1 (rim-locators) is malformed"), std::string::npos)
        << "expected rim-locators to be named as the malformed member, got:\n"
        << logs;
    EXPECT_EQ(logs.find("key 2 (profile) is malformed"), std::string::npos)
        << "the profile is well-formed and must not be called malformed:\n"
        << logs;
}

// profile is an int instead of a profile-type-choice.
TEST(ParseSpdmToc, MalformedProfileRejected) {
    auto bytes = load_fixture("reject_malformed_toc_profile");
    ASSERT_FALSE(bytes.empty());
    SpdmToc toc;

    testing::internal::CaptureStderr();
    const Error err = parse_spdm_toc(bytes, toc);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::EvidenceMalformed);
    EXPECT_NE(logs.find("key 2 (profile) is malformed"), std::string::npos)
        << "expected the malformed-member diagnostic, got:\n" << logs;
}

// spdm-toc-map.tagged-evidence (key 0) is mandatory, so zcbor decodes it with
// an expect rather than a present_decode: a malformed value fails the whole map
// decode instead of backtracking into the extension array. It therefore cannot
// be shadowed and is deliberately absent from kSpdmTocSchemaKeys. Pinned here
// so the omission stays justified if the CDDL ever makes key 0 optional.
TEST(ParseSpdmToc, MalformedTaggedEvidenceRejectedByDecoder) {
    auto bytes = load_fixture("reject_malformed_tagged_evidence");
    ASSERT_FALSE(bytes.empty());
    SpdmToc toc;

    testing::internal::CaptureStderr();
    const Error err = parse_spdm_toc(bytes, toc);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::EvidenceMalformed);
    EXPECT_EQ(logs.find("key 0"), std::string::npos)
        << "a mandatory member must fail in the decoder, not surface as a "
           "shadowed extension key:\n" << logs;
}

// concise-evidence-map has its own extension array, separate from the
// enclosing spdm-toc-map's. Its ev-triples (key 0) is mandatory and so cannot
// be shadowed, leaving evidence-id and profile as the two droppable members.

// evidence-id is an int instead of a tagged-uuid-type.
TEST(ParseConciseEvidence, MalformedEvidenceIdRejected) {
    auto bytes = load_fixture("reject_malformed_evidence_id");
    ASSERT_FALSE(bytes.empty());
    ConciseEvidence ce;

    testing::internal::CaptureStderr();
    const Error err = parse_concise_evidence(bytes, ce);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::EvidenceMalformed);
    EXPECT_NE(logs.find("key 1 (evidence-id) is malformed"), std::string::npos)
        << "expected the malformed-member diagnostic, got:\n" << logs;
}

// concise-evidence-map.profile is an int instead of a profile-type-choice.
// Nested in a tagged-spdm-toc, so this also covers the parse_spdm_toc path
// reaching the check through convert_concise_evidence.
TEST(ParseSpdmToc, MalformedNestedConciseEvidenceProfileRejected) {
    auto bytes = load_fixture("reject_malformed_ce_profile");
    ASSERT_FALSE(bytes.empty());
    SpdmToc toc;

    testing::internal::CaptureStderr();
    const Error err = parse_spdm_toc(bytes, toc);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::EvidenceMalformed);
    EXPECT_NE(logs.find("concise-evidence-map: key 2 (profile) is malformed"),
              std::string::npos)
        << "expected the concise-evidence-map diagnostic (not the spdm-toc-map "
           "one), got:\n" << logs;
}

// spdm-indirect-map is a single optional member followed only by the
// extension rule, so a malformed index is shadowed rather than hard-failing.
// Without the check the measurement resolves to no SPDM block indexes at all.
TEST(ParseConciseEvidence, MalformedSpdmIndirectIndexRejected) {
    auto bytes = load_fixture("malformed_spdm_indirect_index");
    ASSERT_FALSE(bytes.empty());
    ConciseEvidence ce;

    testing::internal::CaptureStderr();
    const Error err = parse_concise_evidence(bytes, ce);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::EvidenceMalformed);
    EXPECT_NE(logs.find("key 0 (index) is malformed"), std::string::npos)
        << "expected the shadowed-member diagnostic, got:\n" << logs;
}

// Guard against over-rejection: genuinely unknown extension keys must still
// be tolerated, since both maps are declared extensible (§6.3.1, §6.3.2).
// Only a key our CDDL defines indicates a dropped member.
TEST(ParseSpdmToc, UnknownExtensionKeysStillAccepted) {
    auto bytes = load_fixture("accept_unknown_extension_keys");
    ASSERT_FALSE(bytes.empty());
    SpdmToc toc;
    EXPECT_EQ(parse_spdm_toc(bytes, toc), Error::Ok);
}

// Builder-API tests: verify CoEV objects can be constructed in C++
// without parsing any CBOR, so downstream consumers can unit-test
// against synthesized inputs.

TEST(CoevBuilder, ConstructWithoutParsing) {
    EnvironmentMap env;
    std::vector<MeasurementMap> measurements;
    measurements.emplace_back();

    std::vector<EvidenceTripleRecord> records;
    records.emplace_back(std::move(env), std::move(measurements));

    EvTriples triples(std::move(records));
    ConciseEvidence ce(std::move(triples));

    std::vector<ConciseEvidence> evidence;
    evidence.push_back(std::move(ce));

    std::vector<CorimLocatorMap> locators;
    locators.emplace_back(std::vector<std::string>{"https://rim.example.com/built.corim"});

    SpdmToc toc(std::move(evidence), std::move(locators));

    ASSERT_EQ(toc.getEvidence().size(), 1u);
    ASSERT_EQ(toc.getEvidence()[0].getEvTriples().getEvidenceTriples().size(), 1u);
    ASSERT_EQ(toc.getRimLocators().size(), 1u);
    ASSERT_EQ(toc.getRimLocators()[0].getUris().size(), 1u);
    EXPECT_EQ(toc.getRimLocators()[0].getUris()[0], "https://rim.example.com/built.corim");

    nlohmann::json j;
    to_json(j, toc);
    ASSERT_TRUE(j.contains("evidence"));
    EXPECT_EQ(j["evidence"].size(), 1u);
    ASSERT_TRUE(j.contains("rim_locators"));
    EXPECT_EQ(j["rim_locators"].size(), 1u);
}

TEST(CoevBuilder, ConstructWithSpdmIndirectMeasurement) {
    auto indirect = std::unique_ptr<SpdmIndirectMap>(new SpdmIndirectMap({40, 41, 45}));
    MeasurementValues mval(
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        std::vector<Digest>{}, std::move(indirect));
    MeasurementMap mm(MeasurementMapKey{}, std::move(mval));
    EnvironmentMap env;
    std::vector<MeasurementMap> measurements;
    measurements.push_back(std::move(mm));
    std::vector<EvidenceTripleRecord> records;
    records.emplace_back(std::move(env), std::move(measurements));
    ConciseEvidence ce(EvTriples(std::move(records)));

    nlohmann::json j;
    to_json(j, ce);
    auto& mvj = j["ev_triples"]["evidence_triples"][0]["measurements"][0]["values"];
    ASSERT_TRUE(mvj.contains("spdm_indirect"));
    EXPECT_EQ(mvj["spdm_indirect"]["indexes"], nlohmann::json::array({40, 41, 45}));
}

// operator= self-assignment + cross-assignment exercise the copy-assign
// guard and the move-after-copy path in ConciseEvidence / SpdmToc.
TEST(CoevBuilder, ConciseEvidenceCopyAssignment) {
    std::vector<EvidenceTripleRecord> records;
    records.emplace_back();
    ConciseEvidence a(EvTriples(std::move(records)));
    ConciseEvidence b;
    b = a;                                                       // cross-assign
    EXPECT_EQ(b.getEvTriples().getEvidenceTriples().size(), 1u);
    ConciseEvidence* self = &b;                                  // hide self-aliasing
    b = *self;                                                   // self-assign
    EXPECT_EQ(b.getEvTriples().getEvidenceTriples().size(), 1u);
}

TEST(CoevBuilder, SpdmTocCopyAssignmentAndNullProfileCopy) {
    std::vector<ConciseEvidence> evidence;
    evidence.emplace_back();
    SpdmToc a(std::move(evidence));                              // m_profile = nullptr
    SpdmToc b(a);                                                // copy-ctor nullptr branch
    EXPECT_EQ(b.getEvidence().size(), 1u);
    SpdmToc c;
    c = a;                                                       // cross-assign
    EXPECT_EQ(c.getEvidence().size(), 1u);
    SpdmToc* self = &c;                                          // hide self-aliasing
    c = *self;                                                   // self-assign
    EXPECT_EQ(c.getEvidence().size(), 1u);
}

class NoopOcspHttpClient : public IOcspHttpClient {
public:
    Error get_ocsp_response(
        const nv_unique_ptr<X509>& /*subject_cert*/,
        const nv_unique_ptr<X509>& /*issuer_cert*/,
        const nv_unique_ptr<stack_st_X509>& /*intermediates*/,
        const nv_unique_ptr<X509_STORE>& /*trust_store*/,
        NvOcspResponse& /*out_ocsp_response*/) override {
        return Error::InternalError;
    }
};

std::vector<uint8_t> load_coev_signed_fixture(const std::string& name) {
    std::string path = "testdata/sample_rims/coev_signed/" + name + ".cbor";
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        ADD_FAILURE() << "Failed to open fixture: " << path;
        return {};
    }
    return std::vector<uint8_t>(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
}

std::string coev_signing_trust_anchor() {
    std::string path = "testdata/x509_cert_chain/cose_signing_root.crt";
    std::ifstream f(path);
    if (!f) {
        ADD_FAILURE() << "Failed to open: " << path;
        return {};
    }
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

TEST(CoevSignatureVerify, ValidSignatureYieldsUnsignedPayload) {
    std::vector<uint8_t> signed_bytes =
        load_coev_signed_fixture("blackwell_fsp_real");
    std::vector<uint8_t> unsigned_bytes = load_fixture("blackwell_fsp_real");
    ASSERT_FALSE(signed_bytes.empty());
    ASSERT_FALSE(unsigned_bytes.empty());

    NoopOcspHttpClient ocsp_client;
    CoseSign1VerifyOptions options;
    options.verify_ocsp = false;
    options.root_cert_pem = coev_signing_trust_anchor();

    CoseSign1Result result;
    ASSERT_EQ(verify_cose_sign1(signed_bytes, options, ocsp_client, result),
              Error::Ok);
    EXPECT_EQ(result.payload, unsigned_bytes);
}

TEST(CoevSignatureVerify, RejectsBadSignature) {
    std::vector<uint8_t> signed_bytes =
        load_coev_signed_fixture("blackwell_fsp_real_bad_sig");
    ASSERT_FALSE(signed_bytes.empty());

    NoopOcspHttpClient ocsp_client;
    CoseSign1VerifyOptions options;
    options.verify_ocsp = false;
    options.root_cert_pem = coev_signing_trust_anchor();

    CoseSign1Result result;
    EXPECT_NE(verify_cose_sign1(signed_bytes, options, ocsp_client, result),
              Error::Ok);
}

}  // namespace
}  // namespace nvattestation
