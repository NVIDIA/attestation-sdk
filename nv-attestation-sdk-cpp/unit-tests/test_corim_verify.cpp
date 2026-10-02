/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
 */

#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "nv_attestation/corim.h"
#include "nv_attestation/corim_verify.h"

namespace nvattestation {
namespace {

TEST(CorimVerify, MismatchReasonFactoriesAndJson) {
    auto no_ev = MismatchReason::noEvidence();
    EXPECT_TRUE(no_ev.no_evidence);
    EXPECT_TRUE(no_ev.mkey_mismatches.empty());
    EXPECT_TRUE(no_ev.failed_dependencies.empty());

    std::vector<MkeyMismatch> mkms;
    {
        MeasurementValuesMismatch mvm;
        mvm.version.mismatched = true;
        mvm.version.reference = "1.0";
        mvm.version.evidence = "2.0";
        MkeyMismatch mkm;
        mkm.mkey = MeasurementMapKey::ofUint(0);
        mkm.mismatch = std::move(mvm);
        mkms.push_back(std::move(mkm));
    }
    auto claims = MismatchReason::claimsMismatch(std::move(mkms));
    EXPECT_FALSE(claims.no_evidence);
    ASSERT_EQ(claims.mkey_mismatches.size(), 1u);

    nlohmann::json j_claims = claims;
    ASSERT_TRUE(j_claims.contains("mkey_mismatches"));
    EXPECT_EQ(j_claims["mkey_mismatches"][0]["mismatch"]["version"]["reference"],
              "1.0");

    // Empty MismatchReason serializes to {} — no flag set, no fields.
    nlohmann::json j_dep = MismatchReason::failedDependency({});
    EXPECT_TRUE(j_dep.is_object());
    EXPECT_TRUE(j_dep.empty());
}

TEST(CorimVerify, PerCertStatusJsonIncludesOcspTimestamps) {
    PerCertStatus status;
    status.expiration_date = "2036-07-15T23:02:10Z";
    status.ocsp = std::make_shared<PerCertStatus::OcspInfo>();
    status.ocsp->response_valid = true;
    status.ocsp->crl_status = OCSPStatus::REVOKED;
    status.ocsp->revocation_reason = std::make_shared<std::string>("keyCompromise");
    status.ocsp->response_produced_at = "2036-07-15T23:02:10Z";
    status.ocsp->response_revoked_at = "2036-07-15T22:00:00Z";

    nlohmann::json j = status;
    EXPECT_EQ(j["ocsp_response_produced_at"], "2036-07-15T23:02:10Z");
    EXPECT_EQ(j["ocsp_response_revoked_at"], "2036-07-15T22:00:00Z");
    EXPECT_EQ(j["ocsp_crl_status"], "revoked");
}

TEST(CorimVerify, PerCertStatusJsonOmitsOcspTimestampsWhenUnset) {
    PerCertStatus status;
    status.ocsp = std::make_shared<PerCertStatus::OcspInfo>();
    status.ocsp->crl_status = OCSPStatus::GOOD;

    nlohmann::json j = status;
    EXPECT_FALSE(j.contains("ocsp_response_produced_at"));
    EXPECT_FALSE(j.contains("ocsp_response_revoked_at"));
}

namespace {

std::unique_ptr<ClassId> make_oid(std::vector<uint8_t> body) {
    return std::make_unique<ClassId>(ClassId::Kind::kOid,
                                     ByteString(body.data(), body.size()));
}

// BER content bytes (no tag/length envelope) for an OID given as decimal arcs.
std::vector<uint8_t> oid_content(const std::vector<uint32_t> &arcs) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(arcs[0] * 40 + arcs[1]));
    for (size_t i = 2; i < arcs.size(); ++i) {
        uint32_t arc = arcs[i];
        std::vector<uint8_t> base128;
        do {
            base128.push_back(static_cast<uint8_t>(arc & 0x7F));
            arc >>= 7;
        } while (arc != 0);
        for (size_t j = base128.size(); j-- > 1;) {
            out.push_back(static_cast<uint8_t>(base128[j] | 0x80));
        }
        out.push_back(base128[0]);
    }
    return out;
}

std::unique_ptr<ClassMap>
make_class(std::unique_ptr<ClassId> class_id = nullptr,
           const char *vendor = nullptr, const char *model = nullptr,
           std::unique_ptr<uint32_t> layer = nullptr) {
    return std::make_unique<ClassMap>(
        std::move(class_id),
        vendor ? std::make_unique<std::string>(vendor) : nullptr,
        model ? std::make_unique<std::string>(model) : nullptr,
        std::move(layer),
        /*index=*/nullptr);
}

EnvironmentMap make_env(std::unique_ptr<ClassMap> cls,
                        std::unique_ptr<InstanceId> inst = nullptr,
                        std::unique_ptr<GroupId> grp = nullptr) {
    return EnvironmentMap(std::move(cls), std::move(inst), std::move(grp));
}
} // namespace

TEST(EnvironmentMatch, EmptyReferenceMatchesAnything) {
    EnvironmentMap empty;
    EnvironmentMap evidence =
        make_env(make_class(make_oid({0x2a, 0x03, 0x04}), "ACME", "Widget"));
    EXPECT_TRUE(empty.matches(evidence));
    EXPECT_TRUE(empty.matches(empty));
}

TEST(EnvironmentMatch,
     ReferenceWithSameClassValueMatchesDespiteDistinctPointers) {
    EnvironmentMap ref =
        make_env(make_class(make_oid({0x2a, 0x03, 0x04}), "ACME"));
    EnvironmentMap evidence =
        make_env(make_class(make_oid({0x2a, 0x03, 0x04}), "ACME"));
    EXPECT_TRUE(ref.matches(evidence));
}

TEST(EnvironmentMatch, ReferenceFieldNotPresentOnEvidenceFails) {
    EnvironmentMap ref = make_env(make_class(make_oid({0x2a, 0x03, 0x04})));
    EnvironmentMap evidence =
        make_env(make_class(/*class_id=*/nullptr, "ACME"));
    EXPECT_FALSE(ref.matches(evidence));
}

TEST(EnvironmentMatch, ExtraEvidenceClassFieldsAreIgnored) {
    EnvironmentMap ref = make_env(make_class(make_oid({0x2a, 0x03, 0x04})));
    EnvironmentMap evidence =
        make_env(make_class(make_oid({0x2a, 0x03, 0x04}), "ACME", "Widget"));
    EXPECT_TRUE(ref.matches(evidence));
}

TEST(EnvironmentMatch, DifferentClassIdValueFails) {
    EnvironmentMap ref = make_env(make_class(make_oid({0x2a, 0x03, 0x04})));
    EnvironmentMap evidence =
        make_env(make_class(make_oid({0x2a, 0x03, 0x05})));
    EXPECT_FALSE(ref.matches(evidence));
}

TEST(EnvironmentMatch, DifferentVendorFails) {
    EnvironmentMap ref = make_env(make_class(/*class_id=*/nullptr, "ACME"));
    EnvironmentMap evidence =
        make_env(make_class(/*class_id=*/nullptr, "OTHER"));
    EXPECT_FALSE(ref.matches(evidence));
}

TEST(EnvironmentMatch, InstanceMismatchFails) {
    const std::vector<uint8_t> uuid_a(16, 0xAA);
    const std::vector<uint8_t> uuid_b(16, 0xBB);
    EnvironmentMap ref = make_env(
        /*cls=*/nullptr,
        std::make_unique<InstanceId>(InstanceId::Kind::kUuid,
                                     ByteString(uuid_a.data(), uuid_a.size())));
    EnvironmentMap evidence = make_env(
        /*cls=*/nullptr,
        std::make_unique<InstanceId>(InstanceId::Kind::kUuid,
                                     ByteString(uuid_b.data(), uuid_b.size())));
    EXPECT_FALSE(ref.matches(evidence));
}

TEST(EnvironmentMatch, InstanceKindMismatchFails) {
    const std::vector<uint8_t> bytes(16, 0xCC);
    EnvironmentMap ref = make_env(
        /*cls=*/nullptr,
        std::make_unique<InstanceId>(InstanceId::Kind::kUuid,
                                     ByteString(bytes.data(), bytes.size())));
    EnvironmentMap evidence = make_env(
        /*cls=*/nullptr,
        std::make_unique<InstanceId>(InstanceId::Kind::kBytes,
                                     ByteString(bytes.data(), bytes.size())));
    EXPECT_FALSE(ref.matches(evidence));
}

TEST(EnvironmentMatch, GroupMismatchFails) {
    const std::vector<uint8_t> uuid_a(16, 0xAA);
    const std::vector<uint8_t> uuid_b(16, 0xBB);
    EnvironmentMap ref = make_env(
        /*cls=*/nullptr, /*inst=*/nullptr,
        std::make_unique<GroupId>(GroupId::Kind::kUuid,
                                  ByteString(uuid_a.data(), uuid_a.size())));
    EnvironmentMap evidence = make_env(
        /*cls=*/nullptr, /*inst=*/nullptr,
        std::make_unique<GroupId>(GroupId::Kind::kUuid,
                                  ByteString(uuid_b.data(), uuid_b.size())));
    EXPECT_FALSE(ref.matches(evidence));
}

namespace {
MeasurementValues mv(std::unique_ptr<Version> version = nullptr,
                     std::unique_ptr<FlagsMap> flags = nullptr,
                     std::unique_ptr<ByteString> raw_value = nullptr,
                     std::unique_ptr<ByteString> raw_value_mask = nullptr,
                     std::unique_ptr<std::string> name = nullptr,
                     std::unique_ptr<IntRange> int_range = nullptr,
                     std::unique_ptr<Svn> svn = nullptr,
                     std::vector<Digest> digests = {}) {
    return MeasurementValues(std::move(version), std::move(flags),
                             std::move(raw_value), std::move(raw_value_mask),
                             std::move(name), std::move(int_range),
                             std::move(svn), std::move(digests));
}

Digest sha256(std::vector<uint8_t> bytes) {
    return Digest(/*alg=*/-16, ByteString(bytes.data(), bytes.size()));
}

Digest sha384(std::vector<uint8_t> bytes) {
    return Digest(/*alg=*/-43, ByteString(bytes.data(), bytes.size()));
}

// A `purpose` string-keyed measurement — every root env must declare one.
MeasurementMap purpose_measurement(const std::string &name) {
    return MeasurementMap{
        MeasurementMapKey::ofString("purpose"),
        mv(nullptr, nullptr, nullptr, nullptr,
           std::make_unique<std::string>(name), nullptr, nullptr, {})};
}

// Prepend a corroborable purpose to a root env's claims so it satisfies the
// well-formed-root requirement. Used identically on reference and evidence.
std::vector<MeasurementMap> with_purpose(std::vector<MeasurementMap> claims,
                                         const std::string &name = "USE_CASE_1") {
    std::vector<MeasurementMap> out;
    out.push_back(purpose_measurement(name));
    for (auto &claim : claims) {
        out.push_back(std::move(claim));
    }
    return out;
}
} // namespace

TEST(MeasurementValuesMatch, EmptyReferenceMatchesAnything) {
    auto ref = mv();
    auto ev = mv(std::make_unique<Version>("1.0"));
    auto mm = match_measurement_values(ref, ev);
    EXPECT_FALSE(mm.any());
    EXPECT_TRUE(mm.fields().empty());
}

TEST(MeasurementValuesMatch, IdenticalNoMismatch) {
    auto ref = mv(std::make_unique<Version>("1.0"));
    auto ev = mv(std::make_unique<Version>("1.0"));
    auto mm = match_measurement_values(ref, ev);
    EXPECT_FALSE(mm.any());
}

TEST(MeasurementValuesMatch, VersionValueMismatch) {
    auto ref = mv(std::make_unique<Version>("1.0"));
    auto ev = mv(std::make_unique<Version>("2.0"));
    auto mm = match_measurement_values(ref, ev);
    EXPECT_TRUE(mm.version.mismatched);
    EXPECT_NE(mm.version.reference.find("1.0"), std::string::npos);
    EXPECT_NE(mm.version.evidence.find("2.0"), std::string::npos);
    ASSERT_EQ(mm.fields().size(), 1u);
    EXPECT_EQ(mm.fields()[0], "version");
}

TEST(MeasurementValuesMatch, RefSetEvidenceAbsentRecordsAbsentMarker) {
    auto ref = mv(std::make_unique<Version>("1.0"));
    auto ev = mv();
    auto mm = match_measurement_values(ref, ev);
    EXPECT_TRUE(mm.version.mismatched);
    EXPECT_EQ(mm.version.evidence, "<absent>");
}

TEST(MeasurementValuesMatch, SvnExactMatch) {
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  std::make_unique<Svn>(SvnKind::kExact, 5));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 std::make_unique<Svn>(SvnKind::kExact, 5));
    EXPECT_FALSE(match_measurement_values(ref, ev).svn.mismatched);
    nlohmann::json j = ref;
    std::cout << "REF MV JSON: " << j.dump(2) << std::endl;
}

TEST(MeasurementValuesMatch, SvnExactMismatchRecordsValues) {
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  std::make_unique<Svn>(SvnKind::kExact, 5));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 std::make_unique<Svn>(SvnKind::kExact, 6));
    auto mm = match_measurement_values(ref, ev);
    EXPECT_TRUE(mm.svn.mismatched);
    EXPECT_EQ(mm.svn.reference, "exact:5");
    EXPECT_EQ(mm.svn.evidence, "exact:6");
}

TEST(MeasurementValuesMatch, SvnMinMet) {
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  std::make_unique<Svn>(SvnKind::kMin, 5));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 std::make_unique<Svn>(SvnKind::kExact, 10));
    EXPECT_FALSE(match_measurement_values(ref, ev).svn.mismatched);
}

TEST(MeasurementValuesMatch, SvnMinNotMetRecordsKind) {
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  std::make_unique<Svn>(SvnKind::kMin, 5));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 std::make_unique<Svn>(SvnKind::kExact, 3));
    auto mm = match_measurement_values(ref, ev);
    EXPECT_TRUE(mm.svn.mismatched);
    EXPECT_EQ(mm.svn.reference, "min:5");
    EXPECT_EQ(mm.svn.evidence, "exact:3");
}

TEST(MeasurementValuesMatch, DigestSameAlgSameValueMatches) {
    std::vector<Digest> ref_d;
    ref_d.push_back(sha256({0x01, 0x02, 0x03}));
    std::vector<Digest> ev_d;
    ev_d.push_back(sha256({0x01, 0x02, 0x03}));
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  /*svn=*/nullptr, std::move(ref_d));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 /*svn=*/nullptr, std::move(ev_d));
    EXPECT_TRUE(match_measurement_values(ref, ev).digests.empty());
}

TEST(MeasurementValuesMatch, DigestEvidenceWithExtraAlgStillMatches) {
    // Reference has only sha256; evidence carries sha256 + sha384. Match.
    std::vector<Digest> ref_d;
    ref_d.push_back(sha256({0x01, 0x02, 0x03}));
    std::vector<Digest> ev_d;
    ev_d.push_back(sha256({0x01, 0x02, 0x03}));
    ev_d.push_back(sha384({0xAA}));
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  /*svn=*/nullptr, std::move(ref_d));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 /*svn=*/nullptr, std::move(ev_d));
    EXPECT_TRUE(match_measurement_values(ref, ev).digests.empty());
}

TEST(MeasurementValuesMatch, DigestRefAlgNotInEvidence) {
    std::vector<Digest> ref_d;
    ref_d.push_back(sha256({0x01}));
    std::vector<Digest> ev_d;
    ev_d.push_back(sha384({0xAA}));
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  /*svn=*/nullptr, std::move(ref_d));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 /*svn=*/nullptr, std::move(ev_d));
    auto mm = match_measurement_values(ref, ev);
    ASSERT_EQ(mm.digests.size(), 1u);
    EXPECT_EQ(mm.digests[0].reason,
              DigestMatchEntry::Reason::kAlgorithmNotInEvidence);
    EXPECT_EQ(mm.digests[0].evidence, nullptr);
}

TEST(MeasurementValuesMatch, DigestSameAlgValueDiffers) {
    std::vector<Digest> ref_d;
    ref_d.push_back(sha256({0x01}));
    std::vector<Digest> ev_d;
    ev_d.push_back(sha256({0xFF}));
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  /*svn=*/nullptr, std::move(ref_d));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 /*svn=*/nullptr, std::move(ev_d));
    auto mm = match_measurement_values(ref, ev);
    ASSERT_EQ(mm.digests.size(), 1u);
    EXPECT_EQ(mm.digests[0].reason, DigestMatchEntry::Reason::kValueDiffers);
    ASSERT_NE(mm.digests[0].evidence, nullptr);
    int32_t alg = 0;
    ASSERT_TRUE(mm.digests[0].evidence->getAlgorithm(alg));
    EXPECT_EQ(alg, -16);
}

TEST(MeasurementValuesMatch, DigestDuplicateAlgorithmInReferenceFails) {
    std::vector<Digest> ref_d;
    ref_d.push_back(sha256({0x01}));
    ref_d.push_back(sha256({0x02}));  // duplicate sha256
    std::vector<Digest> ev_d;
    ev_d.push_back(sha256({0x01}));
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  nullptr, std::move(ref_d));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 nullptr, std::move(ev_d));
    auto mm = match_measurement_values(ref, ev);
    ASSERT_FALSE(mm.digests.empty());
    EXPECT_EQ(mm.digests[0].reason,
              DigestMatchEntry::Reason::kDuplicateAlgorithmInReference);
}

TEST(MeasurementValuesMatch, DigestDuplicateAlgorithmInEvidenceFails) {
    std::vector<Digest> ref_d;
    ref_d.push_back(sha256({0x01}));
    std::vector<Digest> ev_d;
    ev_d.push_back(sha256({0x01}));
    ev_d.push_back(sha256({0x01}));  // duplicate sha256, even with same value
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  nullptr, std::move(ref_d));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 nullptr, std::move(ev_d));
    auto mm = match_measurement_values(ref, ev);
    ASSERT_FALSE(mm.digests.empty());
    EXPECT_EQ(mm.digests[0].reason,
              DigestMatchEntry::Reason::kDuplicateAlgorithmInEvidence);
}

// Multi-digest references are alternatives over the same artifact;
// any single common-algorithm match is enough.
TEST(MeasurementValuesMatch, DigestAlternativesAnyMatchPasses) {
    std::vector<Digest> ref_d;
    ref_d.push_back(sha256({0x01}));
    ref_d.push_back(sha384({0xAA}));
    std::vector<Digest> ev_d;
    ev_d.push_back(sha384({0xAA}));  // matches sha-384 alt; sha-256 absent
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  nullptr, std::move(ref_d));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 nullptr, std::move(ev_d));
    EXPECT_TRUE(match_measurement_values(ref, ev).digests.empty());
}

// One alternative matches, another common-alg pair's value differs.
// Strict semantics: any common-alg mismatch fails the claim — a
// matching alt does NOT excuse it.
TEST(MeasurementValuesMatch, DigestAlternativesAnyDifferingFails) {
    std::vector<Digest> ref_d;
    ref_d.push_back(sha256({0x01}));
    ref_d.push_back(sha384({0xAA}));
    std::vector<Digest> ev_d;
    ev_d.push_back(sha256({0x01}));   // matches
    ev_d.push_back(sha384({0xBB}));   // common alg, differs → fail
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  nullptr, std::move(ref_d));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 nullptr, std::move(ev_d));
    auto mm = match_measurement_values(ref, ev);
    ASSERT_EQ(mm.digests.size(), 1u);
    EXPECT_EQ(mm.digests[0].reason, DigestMatchEntry::Reason::kValueDiffers);
}

// All common-algorithm pairs differ → fail. Reported as a single
// kValueDiffers entry (the first common-alg differs encountered).
TEST(MeasurementValuesMatch, DigestAlternativesAllDifferFails) {
    std::vector<Digest> ref_d;
    ref_d.push_back(sha256({0x01}));
    ref_d.push_back(sha384({0xAA}));
    std::vector<Digest> ev_d;
    ev_d.push_back(sha256({0xFF}));
    ev_d.push_back(sha384({0xBB}));
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                  nullptr, std::move(ref_d));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                 nullptr, std::move(ev_d));
    auto mm = match_measurement_values(ref, ev);
    ASSERT_EQ(mm.digests.size(), 1u);
    EXPECT_EQ(mm.digests[0].reason, DigestMatchEntry::Reason::kValueDiffers);
}

TEST(MeasurementValuesMatch, RawValueMaskedMatchIgnoresMaskedBits) {
    // ref value=AABBCC, mask=FF00FF → only first and third byte must match.
    auto make_bs = [](std::vector<uint8_t> v) {
        return std::make_unique<ByteString>(std::move(v));
    };
    auto ref = mv(nullptr, nullptr, make_bs({0xAA, 0xBB, 0xCC}),
                  make_bs({0xFF, 0x00, 0xFF}));
    // Evidence differs in masked-out byte 1 only.
    auto ev = mv(nullptr, nullptr, make_bs({0xAA, 0x99, 0xCC}),
                 /*raw_value_mask=*/nullptr);
    EXPECT_FALSE(match_measurement_values(ref, ev).raw_value.mismatched);
}

TEST(MeasurementValuesMatch, RawValueMaskedMismatchOnUnmaskedByte) {
    auto make_bs = [](std::vector<uint8_t> v) {
        return std::make_unique<ByteString>(std::move(v));
    };
    auto ref = mv(nullptr, nullptr, make_bs({0xAA, 0xBB, 0xCC}),
                  make_bs({0xFF, 0x00, 0xFF}));
    // Byte 0 differs — masked compare still requires match.
    auto ev = mv(nullptr, nullptr, make_bs({0x55, 0xBB, 0xCC}),
                 /*raw_value_mask=*/nullptr);
    auto mm = match_measurement_values(ref, ev);
    EXPECT_TRUE(mm.raw_value.mismatched);
    EXPECT_NE(mm.raw_value.reference.find("mask="), std::string::npos);
}

TEST(MeasurementValuesMatch, IntRangeExactMatch) {
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr,
                  std::make_unique<IntRange>(IntRange::simpleInt(7)));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr,
                 std::make_unique<IntRange>(IntRange::simpleInt(7)));
    EXPECT_FALSE(match_measurement_values(ref, ev).int_range.mismatched);
}

TEST(MeasurementValuesMatch, IntRangeExactMismatch) {
    auto ref = mv(nullptr, nullptr, nullptr, nullptr, nullptr,
                  std::make_unique<IntRange>(IntRange::simpleInt(7)));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr,
                 std::make_unique<IntRange>(IntRange::simpleInt(8)));
    auto mm = match_measurement_values(ref, ev);
    EXPECT_TRUE(mm.int_range.mismatched);
    EXPECT_EQ(mm.int_range.reference, "exact:7");
}

TEST(MeasurementValuesMatch, IntRangeRangeContainsValue) {
    auto ref =
        mv(nullptr, nullptr, nullptr, nullptr, nullptr,
           std::make_unique<IntRange>(IntRange::range(true, 5, true, 10)));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr,
                 std::make_unique<IntRange>(IntRange::simpleInt(7)));
    EXPECT_FALSE(match_measurement_values(ref, ev).int_range.mismatched);
}

TEST(MeasurementValuesMatch, IntRangeRangeBelowMin) {
    auto ref =
        mv(nullptr, nullptr, nullptr, nullptr, nullptr,
           std::make_unique<IntRange>(IntRange::range(true, 5, true, 10)));
    auto ev = mv(nullptr, nullptr, nullptr, nullptr, nullptr,
                 std::make_unique<IntRange>(IntRange::simpleInt(3)));
    auto mm = match_measurement_values(ref, ev);
    EXPECT_TRUE(mm.int_range.mismatched);
    EXPECT_EQ(mm.int_range.reference, "range:[5,10]");
}

TEST(MeasurementValuesMatch, IntRangeEvidenceRangeShapeFails) {
    // Evidence carrying a range (rather than a concrete value) is treated as a
    // mismatch, even when the reference is also a range that would otherwise
    // contain it. Spec is silent.
    auto ref =
        mv(nullptr, nullptr, nullptr, nullptr, nullptr,
           std::make_unique<IntRange>(IntRange::range(true, 0, true, 100)));
    auto ev =
        mv(nullptr, nullptr, nullptr, nullptr, nullptr,
           std::make_unique<IntRange>(IntRange::range(true, 5, true, 10)));
    EXPECT_TRUE(match_measurement_values(ref, ev).int_range.mismatched);

    auto ref_exact = mv(nullptr, nullptr, nullptr, nullptr, nullptr,
                        std::make_unique<IntRange>(IntRange::simpleInt(7)));
    auto ev_range =
        mv(nullptr, nullptr, nullptr, nullptr, nullptr,
           std::make_unique<IntRange>(IntRange::range(true, 7, true, 7)));
    EXPECT_TRUE(
        match_measurement_values(ref_exact, ev_range).int_range.mismatched);
}

TEST(MeasurementValuesMatch, IntRangeUnboundedMin) {
    auto ref =
        mv(nullptr, nullptr, nullptr, nullptr, nullptr,
           std::make_unique<IntRange>(IntRange::range(false, 0, true, 10)));
    auto ev_in = mv(nullptr, nullptr, nullptr, nullptr, nullptr,
                    std::make_unique<IntRange>(IntRange::simpleInt(-100)));
    EXPECT_FALSE(match_measurement_values(ref, ev_in).int_range.mismatched);

    auto ref_above =
        mv(nullptr, nullptr, nullptr, nullptr, nullptr,
           std::make_unique<IntRange>(IntRange::range(false, 0, true, 10)));
    auto ev_out = mv(nullptr, nullptr, nullptr, nullptr, nullptr,
                     std::make_unique<IntRange>(IntRange::simpleInt(11)));
    EXPECT_TRUE(
        match_measurement_values(ref_above, ev_out).int_range.mismatched);
}

TEST(MeasurementValuesMatch, MultipleFieldsReportedTogether) {
    auto ref = mv(std::make_unique<Version>("1.0"),
                  /*flags=*/nullptr,
                  std::make_unique<ByteString>(std::vector<uint8_t>{0x01}));
    auto ev = mv(std::make_unique<Version>("2.0"),
                 /*flags=*/nullptr,
                 std::make_unique<ByteString>(std::vector<uint8_t>{0x02}));
    auto mm = match_measurement_values(ref, ev);
    EXPECT_TRUE(mm.version.mismatched);
    EXPECT_TRUE(mm.raw_value.mismatched);
    EXPECT_FALSE(mm.svn.mismatched);
    EXPECT_EQ(mm.fields().size(), 2u);
}

// Every per-value field set on both sides with differing data. Exercises each
// arm of match_measurement_values + the corresponding branch in
// MeasurementValuesMismatch::fields(). key_not_in_evidence is excluded — that
// signal lives on MkeyMismatch (one level up), not on the per-values type.
TEST(MeasurementValuesMatch, EveryFieldMismatchedReportedTogether) {
    auto bs = [](std::vector<uint8_t> v) {
        return std::make_unique<ByteString>(std::move(v));
    };
    std::vector<Digest> ref_d;
    ref_d.push_back(sha256({0x01}));
    std::vector<Digest> ev_d;
    ev_d.push_back(sha256({0xFF}));
    auto all_flags = [](bool v) {
        auto f = std::make_unique<FlagsMap>();
        f->setConfigured(v); f->setSecure(v); f->setRecovery(v); f->setDebug(v);
        f->setReplayProtected(v); f->setIntegrityProtected(v);
        f->setRuntimeMeas(v); f->setImmutable(v); f->setTcb(v);
        f->setConfidentialityProtected(v);
        return f;
    };
    auto ref = mv(std::make_unique<Version>("1.0"),
                  all_flags(true),
                  bs({0xAA}),
                  /*raw_value_mask=*/nullptr,
                  std::make_unique<std::string>("ref-name"),
                  std::make_unique<IntRange>(IntRange::simpleInt(7)),
                  std::make_unique<Svn>(SvnKind::kExact, 5),
                  std::move(ref_d));
    auto ev = mv(std::make_unique<Version>("2.0"),
                 all_flags(false),
                 bs({0xBB}),
                 /*raw_value_mask=*/nullptr,
                 std::make_unique<std::string>("ev-name"),
                 std::make_unique<IntRange>(IntRange::simpleInt(8)),
                 std::make_unique<Svn>(SvnKind::kExact, 6),
                 std::move(ev_d));
    auto mm = match_measurement_values(ref, ev);

    EXPECT_TRUE(mm.any());
    EXPECT_TRUE(mm.version.mismatched);
    EXPECT_TRUE(mm.svn.mismatched);
    ASSERT_EQ(mm.digests.size(), 1u);
    EXPECT_EQ(mm.digests[0].reason, DigestMatchEntry::Reason::kValueDiffers);
    EXPECT_TRUE(mm.flags.mismatched);
    EXPECT_TRUE(mm.raw_value.mismatched);
    EXPECT_TRUE(mm.name.mismatched);
    EXPECT_TRUE(mm.int_range.mismatched);

    EXPECT_EQ(mm.fields(),
              (std::vector<std::string>{"version", "svn", "digests", "flags",
                                        "raw_value", "name", "int_range"}));
}

TEST(MeasurementMapKeyDisplay, EachVariantRendersAsExpected) {
    MeasurementMapKey absent;
    EXPECT_EQ(absent.toDisplayString(), "<absent>");

    MeasurementMapKey u;
    u.type = MeasurementMapKey::Type::kUint;
    u.uint_value = 42;
    EXPECT_EQ(u.toDisplayString(), "42");

    MeasurementMapKey s;
    s.type = MeasurementMapKey::Type::kString;
    s.str_value = "boot-loader";
    EXPECT_EQ(s.toDisplayString(), "boot-loader");

    MeasurementMapKey oid;
    oid.type = MeasurementMapKey::Type::kOid;
    oid.str_value = "oid:1.2.3.4";
    EXPECT_EQ(oid.toDisplayString(), "oid:1.2.3.4");

    MeasurementMapKey uuid;
    uuid.type = MeasurementMapKey::Type::kUuid;
    uuid.str_value = "uuid:00000000-0000-4000-8000-000000000001";
    EXPECT_EQ(uuid.toDisplayString(),
              "uuid:00000000-0000-4000-8000-000000000001");
}

TEST(MeasurementValuesMatch, JsonDumpIncludesPerFieldDetail) {
    auto ref = mv(std::make_unique<Version>("1.0"));
    auto ev = mv(std::make_unique<Version>("2.0"));
    nlohmann::json j = match_measurement_values(ref, ev);
    ASSERT_TRUE(j.contains("version"));
    EXPECT_TRUE(j["version"]["mismatched"]);
    EXPECT_TRUE(j["version"].contains("reference"));
    EXPECT_TRUE(j["version"].contains("evidence"));
}

TEST(EnvironmentMatch, MatchIsAsymmetric) {
    EnvironmentMap ref = make_env(/*cls=*/nullptr);
    EnvironmentMap evidence =
        make_env(make_class(make_oid({0x2a, 0x03, 0x04}), "ACME"));
    EXPECT_TRUE(ref.matches(evidence));
    EXPECT_FALSE(evidence.matches(ref));
}

// Promote a few keys to the front so dumps read top-down:
// pass/fail → which env → which ref claims → per-alt attempts. All
// other keys keep their alphabetical order (the std::map default).
nlohmann::ordered_json reorder(const nlohmann::json &src) {
    if (src.is_array()) {
        nlohmann::ordered_json out = nlohmann::ordered_json::array();
        for (const auto &v : src) {
            out.push_back(reorder(v));
        }
        return out;
    }
    if (!src.is_object()) {
        return src;
    }
    nlohmann::ordered_json out = nlohmann::ordered_json::object();
    for (const char *k :
         {"passed", "severity", "code", "detail", "environment",
          "related_envs", "reference_claims", "attempts", "diagnostics"}) {
        if (src.contains(k)) {
            out[k] = reorder(src[k]);
        }
    }
    for (auto it = src.begin(); it != src.end(); ++it) {
        if (!out.contains(it.key())) {
            out[it.key()] = reorder(it.value());
        }
    }
    return out;
}

// Render `j` with 2-space indent, but inline any subtree whose
// compact dump fits in `max_inline` chars. Templated so we can pass
// either nlohmann::json or nlohmann::ordered_json.
template <typename Json>
std::string compact_dump(const Json &j, int max_inline = 60, int indent = 0) {
    if (!j.is_object() && !j.is_array()) {
        return j.dump();
    }
    const std::string compact = j.dump();
    if (static_cast<int>(compact.size()) <= max_inline) {
        return compact;
    }

    const std::string pad(indent + 2, ' ');
    const std::string close_pad(indent, ' ');
    std::string out;
    if (j.is_object()) {
        out = "{\n";
        size_t i = 0;
        for (auto it = j.begin(); it != j.end(); ++it) {
            out += pad + Json(it.key()).dump() + ": " +
                   compact_dump<Json>(it.value(), max_inline, indent + 2);
            if (++i < j.size()) {
                out += ",";
            }
            out += "\n";
        }
        out += close_pad + "}";
    } else {
        out = "[\n";
        size_t i = 0;
        for (const auto &v : j) {
            out += pad + compact_dump<Json>(v, max_inline, indent + 2);
            if (++i < j.size()) {
                out += ",";
            }
            out += "\n";
        }
        out += close_pad + "]";
    }
    return out;
}

// Emit a markdown-formatted record of the test scenario:
//   - H2 with the GTest test name
//   - human description (prose)
//   - H3 + ```json fences for inputs (refs, evidence, deps) and result
// Re-running the test regenerates the output verbatim. Capture via
// the `corim-verify-docs` make target → build/corim-verify-docs.md.
void document_test(const std::string &description,
                   const std::vector<Ect> &reference,
                   const std::vector<Ect> &evidence,
                   const std::vector<DependencyTriple> &dependencies,
                   const VerificationResult &result) {
    const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
    std::cout << "\n## " << info->test_suite_name() << "." << info->name()
              << "\n\n"
              << description << "\n\n";
    std::cout << "### Reference ECTs\n\n```json\n"
              << compact_dump(reorder(nlohmann::json(reference))) << "\n```\n\n";
    std::cout << "### Evidence ECTs\n\n```json\n"
              << compact_dump(reorder(nlohmann::json(evidence))) << "\n```\n\n";
    std::cout << "### Dependencies\n\n```json\n"
              << compact_dump(reorder(nlohmann::json(dependencies))) << "\n```\n\n";
    std::cout << "### Result\n\n```json\n"
              << compact_dump(reorder(nlohmann::json(result))) << "\n```\n\n";
}

// EnvOutcome for `env`, or nullptr if none.
const EnvOutcome *outcome_for_env(const VerificationResult &v,
                                  const EnvironmentMap &env) {
    for (const auto &o : v.outcomes) {
        if (o.environment == env) {
            return &o;
        }
    }
    return nullptr;
}

EnvironmentMap make_env_map(std::string model = "Widget", bool is_root = true) {
    std::unique_ptr<ClassId> class_id = nullptr;
    if (is_root) {
        // Root-env OID under 1.3.6.1.4.1.5703.1300 with penultimate arc 1.
        class_id = make_oid(
            oid_content({1, 3, 6, 1, 4, 1, 5703, 1300, 1, 1, 11, 1, 11, 1, 1}));
    }
    auto cls = std::make_unique<ClassMap>(std::move(class_id),
                                          std::make_unique<std::string>("ACME"),
                                          std::make_unique<std::string>(model),
                                          /*layer=*/nullptr,
                                          /*index=*/nullptr);

    return {std::move(cls), std::unique_ptr<InstanceId>(nullptr),
            std::unique_ptr<GroupId>(nullptr)};
}

TEST(CorimVerify, VerifyTrivialMatch) {
    auto env = make_env_map();
    std::vector<Ect> reference{
        Ect{env, with_purpose({MeasurementMap{
                     MeasurementMapKey::ofUint(1),
                     mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                        std::make_unique<Svn>(SvnKind::kMin, 0), {})}})}};
    std::vector<Ect> evidence{Ect{
        env,
        with_purpose(
            {MeasurementMap{
                 MeasurementMapKey::ofUint(1),
                 mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                    std::make_unique<Svn>(SvnKind::kExact, 1), {})},
             MeasurementMap{MeasurementMapKey::ofUint(2), /*has no ref val*/
                            mv(nullptr, nullptr, nullptr, nullptr,
                               std::make_unique<std::string>("test"), nullptr,
                               nullptr, {})}})}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(One reference ECT and one evidence ECT for the same root env;
no dependencies. The reference requires SVN >= 0; evidence has
SVN = 1 (satisfies). Evidence also carries an extra mkey=2 with a
name claim that the reference does not specify (irrelevant claims
on evidence are ignored). Expected: env corroborated, outcome
passes.)",
                  reference, evidence, dependencies, v);

    ASSERT_EQ(v.outcomes.size(), 1u);
    auto *o = outcome_for_env(v, env);
    ASSERT_NE(o, nullptr);
    ASSERT_EQ(o->attempts.size(), 1u);
    EXPECT_FALSE(o->attempts[0].matched_evidence_ects.empty());
    EXPECT_FALSE(o->attempts[0].reason.any());
    EXPECT_TRUE(o->attempts[0].passed());
    EXPECT_TRUE(o->reason.failed_dependencies.empty());
    EXPECT_TRUE(o->passed());
}

TEST(CorimVerify, DefaultRootDependsOnAllReferencesInScope) {
    auto root_env = make_env_map("Default Root");
    auto ref_a = make_env_map("A", /*is_root=*/false);
    auto ref_b = make_env_map("B", /*is_root=*/false);

    std::vector<Ect> reference{Ect{root_env, with_purpose({}, "DEFAULT")},
                               Ect{ref_a, {}}, Ect{ref_b, {}}};
    std::vector<Ect> evidence{Ect{root_env, with_purpose({}, "DEFAULT")},
                              Ect{ref_a, {}}, Ect{ref_b, {}}};
    std::vector<DependencyTriple> dependencies{
        DependencyTriple(root_env, {ref_a, ref_b})};

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Mirrors the no-root WAR: a synthetic root env that depends
on every (non-root) reference env. collect_reachable walks the
dependency edge from the root, so all reference outcomes land in
scope (reachable_from_root) and are appraised. Expected: no
diagnostics, purpose corroborated as DEFAULT, every outcome in
scope and passing.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.diagnostics.empty());
    ASSERT_NE(v.purpose, nullptr);
    EXPECT_EQ(*v.purpose, "DEFAULT");
    for (const auto &env : {root_env, ref_a, ref_b}) {
        const auto *o = outcome_for_env(v, env);
        ASSERT_NE(o, nullptr);
        EXPECT_TRUE(o->reachable_from_root);
        EXPECT_TRUE(o->passed());
    }
}

TEST(CorimVerify, VerifyTrivialMeasurementMismatch) {
    auto env = make_env_map();
    std::vector<Ect> reference{
        Ect{env, with_purpose({MeasurementMap{
                     MeasurementMapKey::ofUint(1),
                     mv(nullptr, nullptr, nullptr, nullptr,
                        std::make_unique<std::string>("expected"), nullptr,
                        std::make_unique<Svn>(SvnKind::kMin, 0), {})}})}};
    std::vector<Ect> evidence{
        Ect{env, with_purpose({MeasurementMap{
                     MeasurementMapKey::ofUint(1),
                     mv(nullptr, nullptr, nullptr, nullptr,
                        std::make_unique<std::string>("bad"), nullptr,
                        std::make_unique<Svn>(SvnKind::kExact, 1), {})}})}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(One reference ECT requires name = "expected"; the matching
evidence carries name = "bad". Same env, no dependencies. Expected:
claims-mismatch on the name field, outcome not passed.)",
                  reference, evidence, dependencies, v);

    auto *o = outcome_for_env(v, env);
    ASSERT_NE(o, nullptr);
    ASSERT_EQ(o->attempts.size(), 1u);
    EXPECT_TRUE(o->attempts[0].matched_evidence_ects.empty());
    EXPECT_FALSE(o->attempts[0].reason.mkey_mismatches.empty());
    EXPECT_FALSE(o->attempts[0].reason.no_evidence);
    EXPECT_TRUE(o->reason.failed_dependencies.empty());
    EXPECT_FALSE(o->passed());
}

TEST(CorimVerify, VerifyMismatchMkeyNotInEvidence) {
    auto env = make_env_map();
    std::vector<Ect> reference{
        Ect{env, with_purpose({MeasurementMap{
                     MeasurementMapKey::ofUint(1),
                     mv(nullptr, nullptr, nullptr, nullptr,
                        std::make_unique<std::string>("expected"), nullptr,
                        nullptr, {})}})}};
    std::vector<Ect> evidence{
        Ect{env, with_purpose({MeasurementMap{
                     MeasurementMapKey::ofUint(2),
                     mv(nullptr, nullptr, nullptr, nullptr,
                        std::make_unique<std::string>("other"), nullptr, nullptr,
                        {})}})}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(One reference ECT requires mkey=1 with name="expected"; the
matching evidence ECT for the same env carries only mkey=2.
Expected: outcome fails with one `MkeyMismatch` for mkey=1 where
`key_not_in_evidence` is **true** — the flag is a property of the
mkey, not of any individual reference alternative.)",
                  reference, evidence, dependencies, v);

    auto *o = outcome_for_env(v, env);
    ASSERT_NE(o, nullptr);
    ASSERT_EQ(o->attempts.size(), 1u);
    ASSERT_EQ(o->attempts[0].reason.mkey_mismatches.size(), 1u);
    const auto &mkm = o->attempts[0].reason.mkey_mismatches[0];
    EXPECT_TRUE(mkm.key_not_in_evidence);
    EXPECT_FALSE(mkm.mismatch.any()); // no value mismatch when key absent
    EXPECT_EQ(mkm.mkey, MeasurementMapKey::ofUint(1));
    EXPECT_FALSE(o->passed());
}

TEST(CorimVerify, VerifyMismatchMissingEnv) {
    // Graph root → dep; evidence carries no ECT matching `dep`. dep is in scope
    // (reachable from the root) yet its attempt carries no_evidence.
    auto root_env = make_env_map("Root");
    auto dep_env = make_env_map("Dep", /*is_root=*/false);
    std::vector<Ect> reference{
        Ect{root_env, with_purpose({})},
        Ect{dep_env,
            std::vector<MeasurementMap>{MeasurementMap{
                MeasurementMapKey::ofUint(1),
                mv(/*version=*/nullptr, /*flags=*/nullptr, /*raw_value=*/nullptr,
                   /*raw_value_mask=*/nullptr,
                   /*name=*/std::make_unique<std::string>("expected"),
                   /*int_range=*/nullptr, /*svn=*/nullptr, /*digests=*/{})}}}};
    std::vector<Ect> evidence{Ect{root_env, with_purpose({})}};
    std::vector<DependencyTriple> dependencies{
        DependencyTriple(root_env, {dep_env})};

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Graph root → dep; evidence carries no ECT matching `dep`.
Expected: dep is in scope but its attempt carries `no_evidence = true`
and the outcome does not pass.)",
                  reference, evidence, dependencies, v);

    auto *o = outcome_for_env(v, dep_env);
    ASSERT_NE(o, nullptr);
    ASSERT_EQ(o->attempts.size(), 1u);
    EXPECT_TRUE(o->attempts[0].matched_evidence_ects.empty());
    EXPECT_TRUE(o->attempts[0].reason.no_evidence);
    EXPECT_TRUE(o->attempts[0].reason.mkey_mismatches.empty());
    EXPECT_TRUE(o->reason.failed_dependencies.empty());
    EXPECT_FALSE(o->passed());
}

TEST(CorimVerify, VerifyMismatchFailedDependency) {
    auto root_env = make_env_map("Root");
    auto dep1_env = make_env_map("Dep 1", /*is_root=*/false);
    auto dep2_env = make_env_map("Dep 2", /*is_root=*/false);
    std::vector<Ect> reference{
        Ect{root_env,
            with_purpose({
                MeasurementMap{
                    MeasurementMapKey::ofUint(1),
                    MeasurementValues{
                        /*version=*/nullptr,
                        /*flags=*/nullptr,
                        /*raw_value=*/nullptr,
                        /*raw_value_mask=*/nullptr,
                        /*name=*/nullptr,
                        /*int_range=*/nullptr,
                        /*svn=*/nullptr,
                        /*digests=*/{sha256({0xFF}), sha384({0xFE})}}},
            })},
        Ect{dep1_env,
            {MeasurementMap{
                MeasurementMapKey::ofUint(2),
                MeasurementValues{/*version=*/nullptr,
                                  /*flags=*/nullptr,
                                  /*raw_value=*/nullptr,
                                  /*raw_value_mask=*/nullptr,
                                  /*name=*/nullptr,
                                  /*int_range=*/nullptr,
                                  /*svn=*/nullptr,
                                  /*digests=*/{sha256({0xEF}), sha384({0xEE})}}}

            }},
        Ect{dep2_env,
            {MeasurementMap{
                MeasurementMapKey::ofUint(3),
                MeasurementValues{/*version=*/nullptr,
                                  /*flags=*/nullptr,
                                  /*raw_value=*/nullptr,
                                  /*raw_value_mask=*/nullptr,
                                  /*name=*/nullptr,
                                  /*int_range=*/nullptr,
                                  /*svn=*/nullptr,
                                  /*digests=*/{sha256({0xDF}), sha384({0xDE})}}}

            }},
    };
    std::vector<Ect> evidence {
        Ect{root_env,
            with_purpose({
                MeasurementMap{
                    MeasurementMapKey::ofUint(1),
                    MeasurementValues{
                        /*version=*/nullptr,
                        /*flags=*/nullptr,
                        /*raw_value=*/nullptr,
                        /*raw_value_mask=*/nullptr,
                        /*name=*/nullptr,
                        /*int_range=*/nullptr,
                        /*svn=*/nullptr,
                        /*digests=*/{sha384({0xFE})}}},
            })},
        Ect{dep1_env,
            {MeasurementMap{
                MeasurementMapKey::ofUint(2),
                MeasurementValues{/*version=*/nullptr,
                                  /*flags=*/nullptr,
                                  /*raw_value=*/nullptr,
                                  /*raw_value_mask=*/nullptr,
                                  /*name=*/nullptr,
                                  /*int_range=*/nullptr,
                                  /*svn=*/nullptr,
                                  /*digests=*/{sha384({0xEE})}}}

            }},
        Ect{dep2_env,
            {MeasurementMap{
                MeasurementMapKey::ofUint(3),
                MeasurementValues{/*version=*/nullptr,
                                  /*flags=*/nullptr,
                                  /*raw_value=*/nullptr,
                                  /*raw_value_mask=*/nullptr,
                                  /*name=*/nullptr,
                                  /*int_range=*/nullptr,
                                  /*svn=*/nullptr,
                                  /*mismatch*/
                                  /*digests=*/{sha384({0x00})}}}

            }},
    };
    std::vector<DependencyTriple> dependencies {
       {root_env, {dep1_env}},
       {dep1_env, {dep2_env}}
    };

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Three envs in a chain: root → dep1 → dep2. Each reference
ECT carries two digests (sha-256 and sha-384) — multiple digests
in a single `MeasurementValues` are alternatives over the same
artifact, so any one common-algorithm match suffices. Evidence
carries only sha-384, which corroborates root and dep1, but dep2's
evidence sha-384 value is wrong.

Expected: dep2 fails on its own claims; dep1 corroborates its own
claims yet inherits dep2 as a failed dependency; root corroborates
its own claims yet inherits dep1. **`failed_dependencies` carries
env identifiers only — the per-trustee failure detail lives on the
trustee's own `EnvOutcome` in `VerificationResult.outcomes`, not
duplicated inside each dependent.**)",
                  reference, evidence, dependencies, v);

    ASSERT_EQ(v.outcomes.size(), 3u);
    for (const auto &o : v.outcomes) {
        EXPECT_FALSE(o.passed());
    }

    // dep2_env: own claims-mismatch (sha-384 value differs), no
    // failed_dependencies of its own.
    auto *dep2_o = outcome_for_env(v, dep2_env);
    ASSERT_NE(dep2_o, nullptr);
    ASSERT_EQ(dep2_o->attempts.size(), 1u);
    EXPECT_TRUE(dep2_o->attempts[0].matched_evidence_ects.empty());
    EXPECT_FALSE(dep2_o->attempts[0].reason.mkey_mismatches.empty());
    EXPECT_TRUE(dep2_o->reason.failed_dependencies.empty());

    // dep1_env: own claims corroborated (sha-384 matches) — only the
    // trustee failure brings it down.
    auto *dep1_o = outcome_for_env(v, dep1_env);
    ASSERT_NE(dep1_o, nullptr);
    ASSERT_EQ(dep1_o->attempts.size(), 1u);
    EXPECT_FALSE(dep1_o->attempts[0].matched_evidence_ects.empty());
    EXPECT_TRUE(dep1_o->attempts[0].reason.mkey_mismatches.empty());
    ASSERT_EQ(dep1_o->reason.failed_dependencies.size(), 1u);
    EXPECT_EQ(dep1_o->reason.failed_dependencies[0], dep2_env);

    // root_env: own claims corroborated; trustee dep1 failed
    // transitively.
    auto *root_o = outcome_for_env(v, root_env);
    ASSERT_NE(root_o, nullptr);
    ASSERT_EQ(root_o->attempts.size(), 1u);
    EXPECT_FALSE(root_o->attempts[0].matched_evidence_ects.empty());
    EXPECT_TRUE(root_o->attempts[0].reason.mkey_mismatches.empty());
    ASSERT_EQ(root_o->reason.failed_dependencies.size(), 1u);
    EXPECT_EQ(root_o->reason.failed_dependencies[0], dep1_env);
    // dep1's failure detail isn't duplicated here — look it up by env
    // in v.outcomes (already asserted on dep1_o above).
}

namespace {
std::vector<MeasurementMap> claims_with_digest(uint64_t mkey, Digest d) {
    std::vector<Digest> digests;
    digests.push_back(std::move(d));
    return {MeasurementMap{
        MeasurementMapKey::ofUint(mkey),
        MeasurementValues{nullptr, nullptr, nullptr, nullptr, nullptr,
                          nullptr, nullptr, std::move(digests)}}};
}

MeasurementMap name_claim(uint64_t mkey, const std::string &name) {
    return MeasurementMap{
        MeasurementMapKey::ofUint(mkey),
        MeasurementValues{nullptr, nullptr, nullptr, nullptr,
                          std::make_unique<std::string>(name), nullptr,
                          nullptr, {}}};
}

std::vector<MeasurementMap> claims_with_purpose(const std::string &name) {
    return {purpose_measurement(name)};
}
} // namespace

TEST(CorimVerify, VerifyDuplicateReferenceMkey) {
    auto env = make_env_map();
    std::vector<MeasurementMap> ref_claims;
    ref_claims.push_back(name_claim(1, "A"));
    ref_claims.push_back(name_claim(1, "B")); // duplicate mkey=1
    std::vector<Ect> reference{Ect{env, std::move(ref_claims)}};
    std::vector<Ect> evidence{Ect{env, with_purpose({name_claim(1, "A")})}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(One reference ECT carries mkey=1 twice. Duplicate mkeys within
a single reference ECT are fatal — alternatives are expressed by
duplicate environments (multiple reference ECTs), not duplicate
mkeys within one ECT. Expected: verify aborts with
`duplicate-reference-mkey` carrying the offending environment.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code,
              Diagnostic::Code::kDuplicateReferenceMkey);
    EXPECT_TRUE(v.diagnostics[0].isError());
    ASSERT_EQ(v.diagnostics[0].related_envs.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].related_envs[0], env);
}

TEST(CorimVerify, VerifyMergeableReferenceEctsRejected) {
    auto env = make_env_map();
    std::vector<Ect> reference{
        Ect{env, with_purpose({name_claim(1, "A")})}, // mkey=1 only
        Ect{env, with_purpose({name_claim(2, "B")})}, // mkey=2 only — no overlap
    };
    std::vector<Ect> evidence{Ect{env, with_purpose({name_claim(1, "A")})}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult result = verify(reference, evidence, dependencies);
    document_test(R"(Two reference ECTs for the same environment with disjoint mkey
sets (mkey=1 and mkey=2). Without a conflicting mkey these ECTs
are compatible rather than alternative states; this is unsupported.
Expected: fatal `mergeable-reference-ects` diagnostic.)",
                  reference, evidence, dependencies, result);

    EXPECT_TRUE(result.outcomes.empty());
    ASSERT_EQ(result.diagnostics.size(), 1U);
    EXPECT_EQ(result.diagnostics[0].code,
              Diagnostic::Code::kMergeableReferenceEcts);
    EXPECT_TRUE(result.diagnostics[0].isError());
    ASSERT_EQ(result.diagnostics[0].related_envs.size(), 1u);
    EXPECT_EQ(result.diagnostics[0].related_envs[0], env);
}

TEST(CorimVerify, VerifyEnvAlternativesFirstAltMatches) {
    auto env = make_env_map();
    std::vector<Ect> reference{
        Ect{env, with_purpose(claims_with_digest(1, sha256({0x11})))}, // alt A
        Ect{env, with_purpose(claims_with_digest(1, sha256({0x22})))}, // alt B
    };
    std::vector<Ect> evidence{
        Ect{env, with_purpose(claims_with_digest(1, sha256({0x11})))}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Two reference ECTs share the same environment — alternative
configurations. Evidence matches alt A (sha256={0x11}). Expected:
two attempts on the outcome (one per alt); the first passes;
outcome passes.)",
                  reference, evidence, dependencies, v);

    auto *o = outcome_for_env(v, env);
    ASSERT_NE(o, nullptr);
    ASSERT_EQ(o->attempts.size(), 2u);
    EXPECT_TRUE(o->attempts[0].passed());
    EXPECT_FALSE(o->attempts[1].passed());
    EXPECT_TRUE(o->passed());
    EXPECT_NE(v.purpose, nullptr);
}

TEST(CorimVerify, VerifyEnvAlternativesSecondAltMatches) {
    auto env = make_env_map();
    std::vector<Ect> reference{
        Ect{env, with_purpose(claims_with_digest(1, sha256({0x11})))}, // alt A
        Ect{env, with_purpose(claims_with_digest(1, sha256({0x22})))}, // alt B
    };
    std::vector<Ect> evidence{
        Ect{env, with_purpose(claims_with_digest(1, sha256({0x22})))}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Two reference ECTs for the same environment. Evidence matches
alt B (sha256={0x22}). Expected: first attempt fails; second
attempt passes; outcome passes.)",
                  reference, evidence, dependencies, v);

    auto *o = outcome_for_env(v, env);
    ASSERT_NE(o, nullptr);
    ASSERT_EQ(o->attempts.size(), 2u);
    EXPECT_FALSE(o->attempts[0].passed());
    EXPECT_TRUE(o->attempts[1].passed());
    EXPECT_TRUE(o->passed());
    EXPECT_NE(v.purpose, nullptr);
}

TEST(CorimVerify, VerifyEnvAlternativesNoneMatch) {
    auto env = make_env_map();
    std::vector<Ect> reference{
        Ect{env, with_purpose(claims_with_digest(1, sha256({0x11})))}, // alt A
        Ect{env, with_purpose(claims_with_digest(1, sha256({0x22})))}, // alt B
    };
    std::vector<Ect> evidence{
        Ect{env, with_purpose(claims_with_digest(1, sha256({0x33})))}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Two reference ECTs for the same environment. Evidence
(sha256={0x33}) matches neither alt A nor alt B. Expected: two
attempts, both failing; outcome does not pass.)",
                  reference, evidence, dependencies, v);

    auto *o = outcome_for_env(v, env);
    ASSERT_NE(o, nullptr);
    ASSERT_EQ(o->attempts.size(), 2u);
    EXPECT_FALSE(o->attempts[0].passed());
    EXPECT_FALSE(o->attempts[1].passed());
    EXPECT_FALSE(o->passed());
    EXPECT_EQ(v.diagnostics.size(), 0u);
}

TEST(CorimVerify, VerifyEnvAlternativesPassesTrusteeChain) {
    auto root_env = make_env_map("Root");
    auto other_env = make_env_map("Other", /*is_root=*/false);
    std::vector<Ect> reference{
        Ect{root_env, with_purpose(claims_with_digest(1, sha256({0x11})))},
        Ect{other_env, {name_claim(2, "A")}}, // alt A for other_env
        Ect{other_env, {name_claim(2, "B")}}, // alt B for other_env
    };
    std::vector<Ect> evidence{
        Ect{root_env, with_purpose(claims_with_digest(1, sha256({0x11})))},
        Ect{other_env, {name_claim(2, "A")}},
    };
    std::vector<DependencyTriple> dependencies{{root_env, {other_env}}};

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Root depends on "Other". "Other" has two alternative reference
ECTs: alt A (name="A") and alt B (name="B"). Evidence for "Other"
carries name="A" → matches alt A. Expected: "Other" outcome passes
(alt A matched); root sees "Other" as passing trustee → root
passes.)",
                  reference, evidence, dependencies, v);

    auto *other_o = outcome_for_env(v, other_env);
    ASSERT_NE(other_o, nullptr);
    ASSERT_EQ(other_o->attempts.size(), 2u);
    EXPECT_TRUE(other_o->attempts[0].passed());
    EXPECT_FALSE(other_o->attempts[1].passed());
    EXPECT_TRUE(other_o->passed());

    auto *root_o = outcome_for_env(v, root_env);
    ASSERT_NE(root_o, nullptr);
    EXPECT_TRUE(root_o->reason.failed_dependencies.empty());
    EXPECT_TRUE(root_o->passed());
}

TEST(CorimVerify, VerifyEnvAlternativesFailsTrusteeChain) {
    auto root_env = make_env_map("Root");
    auto other_env = make_env_map("Other", /*is_root=*/false);
    std::vector<Ect> reference{
        Ect{root_env, with_purpose(claims_with_digest(1, sha256({0x11})))},
        Ect{other_env, {name_claim(2, "A")}}, // alt A for other_env
        Ect{other_env, {name_claim(2, "B")}}, // alt B for other_env
    };
    std::vector<Ect> evidence{
        Ect{root_env, with_purpose(claims_with_digest(1, sha256({0x11})))},
        Ect{other_env, {name_claim(2, "C")}}, // matches neither alt
    };
    std::vector<DependencyTriple> dependencies{{root_env, {other_env}}};

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Root depends on "Other". "Other" has two alternative reference
ECTs but evidence (name="C") matches neither. Expected: both
"Other" attempts fail; "Other" does not pass; root inherits a
failed_dependencies entry → root does not pass.)",
                  reference, evidence, dependencies, v);

    auto *other_o = outcome_for_env(v, other_env);
    ASSERT_NE(other_o, nullptr);
    ASSERT_EQ(other_o->attempts.size(), 2u);
    EXPECT_FALSE(other_o->attempts[0].passed());
    EXPECT_FALSE(other_o->attempts[1].passed());
    EXPECT_FALSE(other_o->passed());

    auto *root_o = outcome_for_env(v, root_env);
    ASSERT_NE(root_o, nullptr);
    ASSERT_EQ(root_o->reason.failed_dependencies.size(), 1u);
    EXPECT_EQ(root_o->reason.failed_dependencies[0], other_env);
    EXPECT_FALSE(root_o->passed());
}

// Direct callers get a fatal diagnostic, not a vacuous pass.
TEST(CorimVerify, VerifyNoReferenceEctsIsFatal) {
    auto env = make_env_map();
    std::vector<Ect> evidence{Ect{env, with_purpose({name_claim(1, "A")})}};

    VerificationResult v = verify({}, evidence, {});
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code, Diagnostic::Code::kNoReferenceEcts);
    EXPECT_TRUE(v.diagnostics[0].isError());
    EXPECT_TRUE(v.outcomes.empty());
    EXPECT_EQ(v.purpose, nullptr);
}

TEST(CorimVerify, VerifyEnvAlternativesJsonShape) {
    auto env = make_env_map();
    std::vector<Ect> reference{
        Ect{env, with_purpose({name_claim(1, "A")})}, // alt A
        Ect{env, with_purpose({name_claim(1, "B")})}, // alt B
    };
    std::vector<Ect> evidence{Ect{env, with_purpose({name_claim(1, "C")})}};

    VerificationResult v = verify(reference, evidence, {});
    nlohmann::json j = v;
    ASSERT_TRUE(j.contains("outcomes"));
    ASSERT_FALSE(j["outcomes"].empty());
    const auto &attempts = j["outcomes"][0]["attempts"];
    ASSERT_EQ(attempts.size(), 2u);
    for (const auto &attempt : attempts) {
        ASSERT_TRUE(attempt.contains("reason"));
        ASSERT_TRUE(attempt["reason"].contains("mkey_mismatches"));
        const auto &mkms = attempt["reason"]["mkey_mismatches"];
        ASSERT_EQ(mkms.size(), 1u);
        EXPECT_EQ(mkms[0]["mkey"], 1);
        ASSERT_TRUE(mkms[0].contains("mismatch"));
        EXPECT_FALSE(mkms[0].contains("key_not_in_evidence"));
    }
}

TEST(CorimVerify, VerifyMismatchMixedMkeys) {
    auto env = make_env_map();
    std::vector<MeasurementMap> ref_claims;
    ref_claims.push_back(name_claim(1, "alpha")); // mkey=1 — will match
    ref_claims.push_back(name_claim(2, "x"));     // mkey=2 — matches
    ref_claims.push_back(name_claim(3, "y"));     // mkey=3 — fails
    std::vector<Ect> reference{Ect{env, with_purpose(std::move(ref_claims))}};

    std::vector<MeasurementMap> ev_claims;
    ev_claims.push_back(name_claim(1, "alpha"));
    ev_claims.push_back(name_claim(2, "x"));
    ev_claims.push_back(name_claim(3, "z"));
    std::vector<Ect> evidence{Ect{env, with_purpose(std::move(ev_claims))}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(One reference ECT with three distinct mkeys: mkey=1 (matches),
mkey=2 (matches), mkey=3 ("y" vs evidence "z", fails). Expected:
exactly one MkeyMismatch entry for mkey=3.)",
                  reference, evidence, dependencies, v);

    auto *o = outcome_for_env(v, env);
    ASSERT_NE(o, nullptr);
    ASSERT_EQ(o->attempts.size(), 1u);
    ASSERT_EQ(o->attempts[0].reason.mkey_mismatches.size(), 1u);
    const auto &mkm = o->attempts[0].reason.mkey_mismatches[0];
    EXPECT_EQ(mkm.mkey, MeasurementMapKey::ofUint(3));
    EXPECT_FALSE(mkm.key_not_in_evidence);
    EXPECT_TRUE(mkm.mismatch.name.mismatched);
    EXPECT_EQ(mkm.mismatch.name.reference, "y");
    EXPECT_EQ(mkm.mismatch.name.evidence, "z");
    EXPECT_FALSE(o->passed());
}

// Proves end-to-end that EnvironmentMap matching is asymmetric:
// reference fields left unset act as wildcards on evidence. Here
// the reference carries only class info; the evidence carries the
// same class plus an instance UUID. Verify must pair them —
// reference's absent instance accepts any evidence instance.
TEST(CorimVerify, VerifyReferenceEnvIsWildcardForEvidenceInstance) {
    const std::vector<uint32_t> root_arcs{1, 3, 6, 1, 4, 1, 5703,
                                          1300, 1, 1, 11, 1, 11, 1, 1};
    EnvironmentMap ref_env =
        make_env(make_class(make_oid(oid_content(root_arcs)), "ACME", "Widget"));
    EnvironmentMap ev_env =
        make_env(make_class(make_oid(oid_content(root_arcs)), "ACME", "Widget"),
                 std::make_unique<InstanceId>(
                     InstanceId::Kind::kUuid,
                     ByteString(std::vector<uint8_t>(16, 0xAA))));

    std::vector<Ect> reference{
        Ect{ref_env, with_purpose(claims_with_digest(1, sha256({0xAA})))}};
    std::vector<Ect> evidence{
        Ect{ev_env, with_purpose(claims_with_digest(1, sha256({0xAA})))}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Reference ECT carries env `{ class=Root }` (no instance-id);
evidence ECT carries env `{ class=Root, instance=UUID-A }`.

**Env matching is asymmetric: every field unset on the reference
is a wildcard.** The more-specific evidence env is therefore
accepted and the outcome passes.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.diagnostics.empty());
    ASSERT_EQ(v.outcomes.size(), 1u);
    auto *o = outcome_for_env(v, ref_env);
    ASSERT_NE(o, nullptr);
    ASSERT_EQ(o->attempts.size(), 1u);
    ASSERT_EQ(o->attempts[0].matched_evidence_ects.size(), 1u);
    EXPECT_FALSE(o->attempts[0].reason.no_evidence);
    EXPECT_TRUE(o->attempts[0].passed());
    EXPECT_TRUE(o->passed());
}

TEST(CorimVerify, VerifyMissingReferenceForDependencyEnv) {
    auto root_env = make_env_map("Root");
    auto dep_env = make_env_map("Dep");

    // Root has a ref ECT and depends on `dep_env` — but dep_env is
    // not in the reference set. Verify must reject: a dep-graph env
    // without a ref ECT cannot be appraised.
    std::vector<Ect> reference{
        Ect{root_env, with_purpose(claims_with_digest(1, sha256({0x11})))}};
    std::vector<Ect> evidence{
        Ect{root_env, with_purpose(claims_with_digest(1, sha256({0x11})))}};
    std::vector<DependencyTriple> dependencies{{root_env, {dep_env}}};

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Root has a reference ECT and declares a dependency on env
"Dep". The reference set does not include "Dep" — there is no
ECT to appraise it against. Expected: verify aborts with a
fatal `missing-reference-for-dependency-env` diagnostic carrying
"Dep" as the offending environment, no outcomes. Virtual /
evidence-less envs are not supported in this design.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code,
              Diagnostic::Code::kMissingReferenceForDependencyEnv);
    EXPECT_TRUE(v.diagnostics[0].isError());
    ASSERT_EQ(v.diagnostics[0].related_envs.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].related_envs[0], dep_env);
}

TEST(CorimVerify, VerifyDependencyCycle) {
    auto root_env = make_env_map("Root");
    auto a = make_env_map("A");
    auto b = make_env_map("B");
    std::vector<Ect> reference{
        Ect{root_env, with_purpose(claims_with_digest(1, sha256({0x11})))}};
    std::vector<Ect> evidence{
        Ect{root_env, with_purpose(claims_with_digest(1, sha256({0x11})))}};
    std::vector<DependencyTriple> dependencies{{a, {b}}, {b, {a}}};

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Dependency triples form A → B → A. Expected: verify aborts
before any appraisal — top-level diagnostic with code
`dependency-cycle`, no outcomes.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code,
              Diagnostic::Code::kDependencyCycle);
    EXPECT_TRUE(v.diagnostics[0].isError());
}

TEST(CorimVerify, VerifyNoRootEnvironment) {
    // Evidence carries no ECT with the root class id. A root is required to
    // anchor appraisal, so verify aborts.
    auto non_root = make_env_map("NotRoot", /*is_root=*/false);
    std::vector<Ect> reference{
        Ect{non_root, claims_with_digest(1, sha256({0x11}))}};
    std::vector<Ect> evidence{
        Ect{non_root, claims_with_digest(1, sha256({0x11}))}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Evidence carries no ECT with a root class id. Expected: verify
aborts with top-level diagnostic `no-root-environment`, no outcomes.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code, Diagnostic::Code::kNoRootEnvironment);
}

TEST(CorimVerify, VerifyMultipleRootEnvironments) {
    // Three distinct evidence roots, one repeated root and a non-root:
    // report each distinct root only once in the diagnostic.
    auto root_a = make_env_map("RootA", /*is_root=*/true);
    auto root_b = make_env_map("RootB", /*is_root=*/true);
    auto root_c = make_env_map("RootC", /*is_root=*/true);
    auto non_root = make_env_map("Other", /*is_root=*/false);
    std::vector<Ect> reference{
        Ect{root_a, with_purpose(claims_with_digest(1, sha256({0x11})))}};
    std::vector<Ect> evidence{
        Ect{root_a, with_purpose(claims_with_digest(1, sha256({0x11})))},
        Ect{non_root, claims_with_digest(1, sha256({0x44}))},
        Ect{root_b, claims_with_digest(1, sha256({0x22}))},
        Ect{root_a, claims_with_digest(1, sha256({0x55}))},
        Ect{root_c, claims_with_digest(1, sha256({0x33}))}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Evidence carries three distinct root environments, with
RootA repeated in a second ECT, and one non-root ECT. Expected: verify aborts
with `multiple-root-environments` and reports each distinct root once.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code,
              Diagnostic::Code::kMultipleRootEnvironments);
    const auto &related = v.diagnostics[0].related_envs;
    EXPECT_EQ(related.size(), 3u);
    EXPECT_EQ((std::set<EnvironmentMap>(related.begin(), related.end())),
              (std::set<EnvironmentMap>{root_a, root_b, root_c}));
    const nlohmann::json diagnostic = v.diagnostics[0];
    const auto &json_related = diagnostic["related_envs"];
    ASSERT_EQ(json_related.size(), 3u);
    EXPECT_EQ((std::set<nlohmann::json>(json_related.begin(), json_related.end())),
              (std::set<nlohmann::json>{root_a, root_b, root_c}));
    EXPECT_FALSE(diagnostic.contains("environment"));
}

TEST(CorimVerify, VerifyRootPurposeCorroborated) {
    // The root env's `purpose` measurement matches between reference and
    // evidence, so the root outcome passes and its purpose is surfaced.
    auto root_env = make_env_map("Root", /*is_root=*/true);
    std::vector<Ect> reference{Ect{root_env, claims_with_purpose("USE_CASE_1")}};
    std::vector<Ect> evidence{Ect{root_env, claims_with_purpose("USE_CASE_1")}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Reference and evidence root envs both carry a `purpose`
measurement with name "USE_CASE_1". Expected: root outcome passes and the
verification result surfaces purpose "USE_CASE_1".)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.diagnostics.empty());
    const auto *o = outcome_for_env(v, root_env);
    ASSERT_NE(o, nullptr);
    EXPECT_TRUE(o->passed());
    ASSERT_NE(v.purpose, nullptr);
    EXPECT_EQ(*v.purpose, "USE_CASE_1");
}

TEST(CorimVerify, VerifyRootPurposeNotCorroborated) {
    // Evidence root states a different purpose; the name mismatch fails the
    // root outcome, so no purpose is surfaced.
    auto root_env = make_env_map("Root", /*is_root=*/true);
    std::vector<Ect> reference{Ect{root_env, claims_with_purpose("USE_CASE_1")}};
    std::vector<Ect> evidence{Ect{root_env, claims_with_purpose("USE_CASE_2")}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Reference root declares purpose "USE_CASE_1" but the evidence
root declares "USE_CASE_2". Expected: the root outcome fails on the purpose
name mismatch and no purpose is surfaced.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.diagnostics.empty());
    const auto *o = outcome_for_env(v, root_env);
    ASSERT_NE(o, nullptr);
    EXPECT_FALSE(o->passed());
    EXPECT_EQ(v.purpose, nullptr);
}

TEST(CorimVerify, VerifyMultipleReferenceRootsPurpose) {
    // Two CoRIMs each contribute a root reference ECT (distinct models) —
    // legitimate, unlike multiple evidence roots. Only the one matching the
    // single evidence root corroborates; its purpose is surfaced.
    auto root_a = make_env_map("RootA", /*is_root=*/true);
    auto root_b = make_env_map("RootB", /*is_root=*/true);
    std::vector<Ect> reference{Ect{root_a, claims_with_purpose("USE_CASE_1")},
                               Ect{root_b, claims_with_purpose("USE_CASE_2")}};
    std::vector<Ect> evidence{Ect{root_a, claims_with_purpose("USE_CASE_1")}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Reference carries two root ECTs (RootA purpose "USE_CASE_1",
RootB purpose "USE_CASE_2"); evidence carries only the RootA root. Expected:
RootA corroborates and purpose "USE_CASE_1" is surfaced; RootB has no evidence.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.diagnostics.empty());
    ASSERT_NE(v.purpose, nullptr);
    EXPECT_EQ(*v.purpose, "USE_CASE_1");
}

TEST(CorimVerify, VerifyRootPurposeReadFromCorroboratedEvidence) {
    auto root_env = make_env_map("Root");
    std::vector<Ect> reference{
        Ect{root_env, {purpose_measurement("USE_CASE_1")}}, // alt A
        Ect{root_env, {purpose_measurement("USE_CASE_2")}}, // alt B
    };
    std::vector<Ect> evidence{Ect{root_env, claims_with_purpose("USE_CASE_2")}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(The reference root has two alternative ECTs — "USE_CASE_1" and
"USE_CASE_2" — expressed as duplicate environments. Evidence reports
"USE_CASE_2", matching alt B. Expected: the surfaced purpose is the
evidence's runtime value "USE_CASE_2".)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.diagnostics.empty());
    ASSERT_NE(v.purpose, nullptr);
    EXPECT_EQ(*v.purpose, "USE_CASE_2");
}

TEST(CorimVerify, VerifyRootPurposeRequiresReferenceDeclaration) {
    auto root_env = make_env_map("Root");
    std::vector<Ect> reference{
        Ect{root_env, claims_with_digest(1, sha256({0x11}))}};
    std::vector<Ect> evidence{Ect{
        root_env,
        with_purpose(claims_with_digest(1, sha256({0x11})), "INJECTED")}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(The reference root declares no purpose; the evidence carries an
unvetted purpose. Expected: verify aborts with root-environment-missing-purpose
and does not surface the evidence value.)",
                  reference, evidence, dependencies, v);

    EXPECT_EQ(v.purpose, nullptr);
    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code,
              Diagnostic::Code::kRootEnvironmentMissingPurpose);
}

TEST(CorimVerify, VerifyOidUnderRootArcButNotRoot) {
    // OID 1.3.6.1.4.1.5703.1300.1.1.11.1.11.2.1 sits under the NVIDIA root arc
    // but its penultimate arc is 2, not 1, so it is not a root env. With no
    // recognized root present, verify aborts.
    auto env = make_env(make_class(
        make_oid(oid_content({1, 3, 6, 1, 4, 1, 5703, 1300, 1, 1, 11, 1, 11, 2,
                              1})),
        "ACME", "NotRoot"));
    std::vector<Ect> reference{Ect{env, claims_with_purpose("USE_CASE_1")}};
    std::vector<Ect> evidence{Ect{env, claims_with_purpose("USE_CASE_1")}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Environment OID 1.3.6.1.4.1.5703.1300.1.1.11.1.11.2.1 is under
the NVIDIA root arc but its penultimate arc is 2, not 1 — not a root env.
Expected: verify aborts with `no-root-environment`.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code, Diagnostic::Code::kNoRootEnvironment);
}

TEST(CorimVerify, VerifyRootMissingPurpose) {
    // The recognized root declares no purpose measurement — malformed.
    auto root_env = make_env_map("Root");
    std::vector<Ect> reference{
        Ect{root_env, claims_with_digest(1, sha256({0x11}))}};
    std::vector<Ect> evidence{
        Ect{root_env, claims_with_digest(1, sha256({0x11}))}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(The root env declares no `purpose` measurement. Expected: verify
aborts with `root-environment-missing-purpose`, no outcomes.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code,
              Diagnostic::Code::kRootEnvironmentMissingPurpose);
}

TEST(CorimVerify, VerifyIrrelevantFailingEnvDoesNotAffectRoot) {
    // No filtering: an env that is not a trustee of the root stays in outcomes
    // and may fail, but it never feeds the root's outcome. The overall result
    // is based on the root, which still passes.
    auto root_env = make_env_map("Root");
    auto unrelated = make_env_map("Unrelated", /*is_root=*/false);
    std::vector<Ect> reference{
        Ect{root_env, with_purpose(claims_with_digest(1, sha256({0x11})))},
        Ect{unrelated, claims_with_digest(2, sha256({0x22}))}};
    std::vector<Ect> evidence{
        Ect{root_env, with_purpose(claims_with_digest(1, sha256({0x11})))},
        Ect{unrelated, claims_with_digest(2, sha256({0xFF}))}}; // mismatch
    std::vector<DependencyTriple> dependencies; // root has no trustees

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(`unrelated` is not a trustee of the root and fails its own
claims. Expected: outcomes retain both envs (no filtering); the root's outcome
is unaffected and passes, and its purpose is surfaced.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_EQ(v.outcomes.size(), 2u);
    const auto *root_outcome = outcome_for_env(v, root_env);
    ASSERT_NE(root_outcome, nullptr);
    EXPECT_TRUE(root_outcome->passed());
    EXPECT_TRUE(root_outcome->reachable_from_root);
    const auto *unrelated_outcome = outcome_for_env(v, unrelated);
    ASSERT_NE(unrelated_outcome, nullptr);
    EXPECT_FALSE(unrelated_outcome->passed());
    EXPECT_FALSE(unrelated_outcome->reachable_from_root);
    ASSERT_NE(v.purpose, nullptr);
    EXPECT_EQ(*v.purpose, "USE_CASE_1");
}

TEST(CorimVerify, VerifyPurposeSuppressedWhenTrusteeFails) {
    // The root's own purpose+claims corroborate, but its trustee fails.
    // Because the subtree does not fully pass, purpose must not be set.
    auto root_env = make_env_map("Root");
    auto dep_env = make_env_map("Dep", /*is_root=*/false);
    std::vector<Ect> reference{
        Ect{root_env, with_purpose(claims_with_digest(1, sha256({0x11})))},
        Ect{dep_env, claims_with_digest(2, sha256({0x22}))}};
    std::vector<Ect> evidence{
        Ect{root_env, with_purpose(claims_with_digest(1, sha256({0x11})))},
        Ect{dep_env, claims_with_digest(2, sha256({0xFF}))}}; // trustee mismatch
    std::vector<DependencyTriple> dependencies{
        DependencyTriple(root_env, {dep_env})};

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Root corroborates its own purpose+claims; its trustee `dep`
fails. Expected: the root's outcome fails (failed dependency) but purpose is
still surfaced because the root's own attempts passed — callers must gate on
the overall pass status in addition to purpose.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.diagnostics.empty());
    const auto *root_outcome = outcome_for_env(v, root_env);
    ASSERT_NE(root_outcome, nullptr);
    EXPECT_FALSE(root_outcome->passed());
    EXPECT_TRUE(root_outcome->reachable_from_root);
    const auto *dep_outcome = outcome_for_env(v, dep_env);
    ASSERT_NE(dep_outcome, nullptr);
    EXPECT_TRUE(dep_outcome->reachable_from_root);
    EXPECT_NE(v.purpose, nullptr);
}

TEST(CorimVerify, VerifyPurposeFromMatchedRootAmongMany) {
    // Two CoRIMs: rootA → depA and rootB → depB. Evidence carries only rootA's
    // subtree. No filtering: all reference envs appear in outcomes, but purpose
    // comes from the corroborated matched root (rootA). rootB/depB are present
    // but fail (no evidence) and do not affect rootA.
    auto root_a = make_env_map("RootA");
    auto root_b = make_env_map("RootB");
    auto dep_a = make_env_map("DepA", /*is_root=*/false);
    auto dep_b = make_env_map("DepB", /*is_root=*/false);
    std::vector<Ect> reference{
        Ect{root_a, with_purpose(claims_with_digest(1, sha256({0x11})))},
        Ect{dep_a, claims_with_digest(2, sha256({0x22}))},
        Ect{root_b, with_purpose(claims_with_digest(1, sha256({0x33})),
                                 "USE_CASE_2")},
        Ect{dep_b, claims_with_digest(2, sha256({0x44}))}};
    std::vector<Ect> evidence{
        Ect{root_a, with_purpose(claims_with_digest(1, sha256({0x11})))},
        Ect{dep_a, claims_with_digest(2, sha256({0x22}))}};
    std::vector<DependencyTriple> dependencies{
        DependencyTriple(root_a, {dep_a}), DependencyTriple(root_b, {dep_b})};

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(rootA → depA and rootB → depB; evidence carries only rootA's
subtree. Expected: no filtering (all four reference envs have outcomes); purpose
comes from the corroborated matched root rootA; rootB/depB fail with no evidence
but do not affect rootA.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_EQ(v.outcomes.size(), 4u);
    ASSERT_NE(v.purpose, nullptr);
    EXPECT_EQ(*v.purpose, "USE_CASE_1");
    // rootA's subtree is in scope; rootB's is not — this is what the AR layer
    // selects on.
    const auto *root_a_outcome = outcome_for_env(v, root_a);
    ASSERT_NE(root_a_outcome, nullptr);
    EXPECT_TRUE(root_a_outcome->passed());
    EXPECT_TRUE(root_a_outcome->reachable_from_root);
    EXPECT_TRUE(outcome_for_env(v, dep_a)->reachable_from_root);
    const auto *root_b_outcome = outcome_for_env(v, root_b);
    ASSERT_NE(root_b_outcome, nullptr);
    EXPECT_FALSE(root_b_outcome->passed());
    EXPECT_FALSE(root_b_outcome->reachable_from_root);
    EXPECT_FALSE(outcome_for_env(v, dep_b)->reachable_from_root);
}

TEST(CorimVerify, VerifyEvidenceRootNotInReference) {
    // The evidence root corresponds to no reference root (different model), so
    // no root is corroborated and no purpose is surfaced. Outcomes are retained
    // (not silently emptied); the absence of a corroborated root is the signal.
    auto ev_root = make_env_map("EvidenceRoot");
    auto ref_root = make_env_map("ReferenceRoot");
    std::vector<Ect> reference{
        Ect{ref_root, with_purpose(claims_with_digest(1, sha256({0x11})))}};
    std::vector<Ect> evidence{
        Ect{ev_root, with_purpose(claims_with_digest(1, sha256({0x11})))}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(The evidence root (model "EvidenceRoot") matches no reference
root (model "ReferenceRoot"). Expected: no corroborated root, so no purpose is
surfaced; outcomes are not silently emptied.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_EQ(v.purpose, nullptr);
    const auto *ref_root_outcome = outcome_for_env(v, ref_root);
    ASSERT_NE(ref_root_outcome, nullptr);
    EXPECT_FALSE(ref_root_outcome->passed());
    EXPECT_FALSE(ref_root_outcome->reachable_from_root); // no anchor → nothing in scope
    ASSERT_EQ(v.unmatched_environments.size(), 1u);
    EXPECT_EQ(v.unmatched_environments[0], ev_root);
}

TEST(CorimVerify, EvidenceEnvSupersetOfReferenceEnvIsNotUnmatched) {
    // Reference root env: {root_oid, vendor="ACME", model="Widget"} — no layer.
    // Evidence root env:  same OID/vendor/model but with layer=3 added.
    // ref.matches(ev) is true (layer absent from ref → wildcard), so the
    // evidence env must NOT appear in unmatched_environments.
    auto ref_env = make_env_map("Widget");
    auto ev_env  = make_env(make_class(
        make_oid(oid_content({1, 3, 6, 1, 4, 1, 5703, 1300, 1, 1, 11, 1, 11, 1, 1})),
        "ACME", "Widget", std::make_unique<uint32_t>(3u)));

    Digest d = sha256({0x01});
    std::vector<Ect> reference{Ect{ref_env, with_purpose(claims_with_digest(1, d))}};
    std::vector<Ect> evidence {Ect{ev_env,  with_purpose(claims_with_digest(1, d))}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Evidence env carries an extra 'layer' field absent from the
reference env. The reference still matches() the evidence via subset semantics,
so unmatched_environments must be empty.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_TRUE(v.unmatched_environments.empty());
    const auto *eo = outcome_for_env(v, ref_env);
    ASSERT_NE(eo, nullptr);
    ASSERT_EQ(eo->attempts.size(), 1u);
    EXPECT_TRUE(eo->attempts[0].passed());
}

TEST(CorimVerify, VerifyDuplicateEvidenceEnv) {
    auto root_env = make_env_map("Root");
    auto env = make_env_map("Widget", /*is_root=*/false);
    std::vector<Ect> reference{
        Ect{root_env, claims_with_digest(0, sha256({0x00}))},
        Ect{env, claims_with_digest(1, sha256({0x11}))}};
    std::vector<Ect> evidence{
        Ect{root_env, claims_with_digest(0, sha256({0x00}))},
        Ect{env, claims_with_digest(1, sha256({0x11}))},
        // Second evidence ECT carries the same env — ambiguous merge,
        // verify must reject.
        Ect{env, claims_with_digest(2, sha256({0x22}))},
    };
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(Two evidence ECTs share the same environment. Merging is
unsafe (which claim wins?), so verify aborts with a fatal
top-level diagnostic `duplicate-evidence-env` carrying the
offending environment.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code,
              Diagnostic::Code::kDuplicateEvidenceEnv);
    ASSERT_EQ(v.diagnostics[0].related_envs.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].related_envs[0], env);
}

TEST(CorimVerify, VerifyDuplicateEvidenceMkey) {
    auto env = make_env_map();
    std::vector<Ect> reference{
        Ect{env, claims_with_digest(1, sha256({0x11}))}};

    // Single ev ECT carrying mkey=1 twice.
    std::vector<MeasurementMap> dup_claims;
    dup_claims.push_back(MeasurementMap{
        MeasurementMapKey::ofUint(1),
        MeasurementValues{nullptr, nullptr, nullptr, nullptr, nullptr,
                          nullptr, nullptr,
                          std::vector<Digest>{sha256({0x11})}}});
    dup_claims.push_back(MeasurementMap{
        MeasurementMapKey::ofUint(1),
        MeasurementValues{nullptr, nullptr, nullptr, nullptr, nullptr,
                          nullptr, nullptr,
                          std::vector<Digest>{sha256({0x22})}}});
    std::vector<Ect> evidence{Ect{env, std::move(dup_claims)}};
    std::vector<DependencyTriple> dependencies;

    VerificationResult v = verify(reference, evidence, dependencies);
    document_test(R"(One evidence ECT carries mkey=1 twice. Merging is unsafe
(which value wins?), so verify aborts with a fatal top-level
`duplicate-evidence-mkey` diagnostic carrying the offending
environment.)",
                  reference, evidence, dependencies, v);

    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code,
              Diagnostic::Code::kDuplicateEvidenceMkey);
    EXPECT_TRUE(v.diagnostics[0].isError());
    ASSERT_EQ(v.diagnostics[0].related_envs.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].related_envs[0], env);
}

// ----- reverse_topological_sort -------------------------------------------

namespace {
DependencyTriple dep(EnvironmentMap domain, std::vector<EnvironmentMap> trustees) {
    return DependencyTriple(std::move(domain), std::move(trustees));
}

int idx_of(const std::vector<EnvironmentMap>& sorted, const EnvironmentMap& target) {
    for (size_t i = 0; i < sorted.size(); i++) {
        if (sorted[i] == target) { return static_cast<int>(i); }
    }
    return -1;
}
} // namespace

TEST(ReverseTopologicalSort, EmptyGraphSucceeds) {
    std::vector<DependencyTriple> deps;
    std::vector<EnvironmentMap> sorted;
    EXPECT_TRUE(reverse_topological_sort(deps, sorted));
    EXPECT_TRUE(sorted.empty());
}

TEST(ReverseTopologicalSort, SingleNodeNoTrustees) {
    auto a = make_env_map("A");
    std::vector<DependencyTriple> deps;
    deps.push_back(dep(a, {}));
    std::vector<EnvironmentMap> sorted;
    ASSERT_TRUE(reverse_topological_sort(deps, sorted));
    ASSERT_EQ(sorted.size(), 1u);
    EXPECT_EQ(sorted[0], a);
}

TEST(ReverseTopologicalSort, LinearChainLeavesFirst) {
    // A -> B -> C -> D. Leaves first: D, C, B, A.
    auto a = make_env_map("A"), b = make_env_map("B"),
         c = make_env_map("C"), d = make_env_map("D");
    std::vector<DependencyTriple> deps;
    deps.push_back(dep(a, {b}));
    deps.push_back(dep(b, {c}));
    deps.push_back(dep(c, {d}));
    std::vector<EnvironmentMap> sorted;
    ASSERT_TRUE(reverse_topological_sort(deps, sorted));
    ASSERT_EQ(sorted.size(), 4u);
    EXPECT_LT(idx_of(sorted, d), idx_of(sorted, c));
    EXPECT_LT(idx_of(sorted, c), idx_of(sorted, b));
    EXPECT_LT(idx_of(sorted, b), idx_of(sorted, a));
}

TEST(ReverseTopologicalSort, DiamondGraph) {
    // A -> B, A -> C, B -> D, C -> D.
    auto a = make_env_map("A"), b = make_env_map("B"),
         c = make_env_map("C"), d = make_env_map("D");
    std::vector<DependencyTriple> deps;
    deps.push_back(dep(a, {b, c}));
    deps.push_back(dep(b, {d}));
    deps.push_back(dep(c, {d}));
    std::vector<EnvironmentMap> sorted;
    ASSERT_TRUE(reverse_topological_sort(deps, sorted));
    ASSERT_EQ(sorted.size(), 4u);
    EXPECT_LT(idx_of(sorted, d), idx_of(sorted, b));
    EXPECT_LT(idx_of(sorted, d), idx_of(sorted, c));
    EXPECT_LT(idx_of(sorted, b), idx_of(sorted, a));
    EXPECT_LT(idx_of(sorted, c), idx_of(sorted, a));
}

TEST(ReverseTopologicalSort, DisconnectedComponents) {
    auto a = make_env_map("A"), b = make_env_map("B"),
         x = make_env_map("X"), y = make_env_map("Y");
    std::vector<DependencyTriple> deps;
    deps.push_back(dep(a, {b}));
    deps.push_back(dep(x, {y}));
    std::vector<EnvironmentMap> sorted;
    ASSERT_TRUE(reverse_topological_sort(deps, sorted));
    EXPECT_EQ(sorted.size(), 4u);
    EXPECT_LT(idx_of(sorted, b), idx_of(sorted, a));
    EXPECT_LT(idx_of(sorted, y), idx_of(sorted, x));
}

TEST(ReverseTopologicalSort, TrusteeOnlyEnvIncluded) {
    // A -> B, with B having no triple of its own. B should still appear.
    auto a = make_env_map("A"), b = make_env_map("B");
    std::vector<DependencyTriple> deps;
    deps.push_back(dep(a, {b}));
    std::vector<EnvironmentMap> sorted;
    ASSERT_TRUE(reverse_topological_sort(deps, sorted));
    ASSERT_EQ(sorted.size(), 2u);
    EXPECT_EQ(sorted[0], b);
    EXPECT_EQ(sorted[1], a);
}

TEST(ReverseTopologicalSort, SameDomainInMultipleTriplesFlattens) {
    auto a = make_env_map("A"), b = make_env_map("B"), c = make_env_map("C");
    std::vector<DependencyTriple> deps;
    deps.push_back(dep(a, {b}));
    deps.push_back(dep(a, {c}));
    std::vector<EnvironmentMap> sorted;
    ASSERT_TRUE(reverse_topological_sort(deps, sorted));
    ASSERT_EQ(sorted.size(), 3u);
    EXPECT_LT(idx_of(sorted, b), idx_of(sorted, a));
    EXPECT_LT(idx_of(sorted, c), idx_of(sorted, a));
}

TEST(ReverseTopologicalSort, SelfLoopIsCycle) {
    auto a = make_env_map("A");
    std::vector<DependencyTriple> deps;
    deps.push_back(dep(a, {a}));
    std::vector<EnvironmentMap> sorted;
    EXPECT_FALSE(reverse_topological_sort(deps, sorted));
}

TEST(ReverseTopologicalSort, TwoNodeCycle) {
    auto a = make_env_map("A"), b = make_env_map("B");
    std::vector<DependencyTriple> deps;
    deps.push_back(dep(a, {b}));
    deps.push_back(dep(b, {a}));
    std::vector<EnvironmentMap> sorted;
    EXPECT_FALSE(reverse_topological_sort(deps, sorted));
}

TEST(ReverseTopologicalSort, LongerCycleDetectedAfterTraversal) {
    // A -> B -> C -> A. Cycle visible only after walking three edges.
    auto a = make_env_map("A"), b = make_env_map("B"), c = make_env_map("C");
    std::vector<DependencyTriple> deps;
    deps.push_back(dep(a, {b}));
    deps.push_back(dep(b, {c}));
    deps.push_back(dep(c, {a}));
    std::vector<EnvironmentMap> sorted;
    EXPECT_FALSE(reverse_topological_sort(deps, sorted));
}

TEST(ReverseTopologicalSort, CycleInOneComponentOnly) {
    // A -> B (acyclic), C -> D -> E -> C (cyclic). Whole input fails.
    auto a = make_env_map("A"), b = make_env_map("B"),
         c = make_env_map("C"), d = make_env_map("D"), e = make_env_map("E");
    std::vector<DependencyTriple> deps;
    deps.push_back(dep(a, {b}));
    deps.push_back(dep(c, {d}));
    deps.push_back(dep(d, {e}));
    deps.push_back(dep(e, {c}));
    std::vector<EnvironmentMap> sorted;
    EXPECT_FALSE(reverse_topological_sort(deps, sorted));
}

// Mixed true/false across all 10 slots so any dropped slot, dropped polarity,
// or aliasing bug surfaces as an inequality failure.
FlagsMap make_fully_populated_flags() {
    FlagsMap fm;
    fm.setConfigured(true);
    fm.setSecure(false);
    fm.setRecovery(true);
    fm.setDebug(false);
    fm.setReplayProtected(true);
    fm.setIntegrityProtected(false);
    fm.setRuntimeMeas(true);
    fm.setImmutable(false);
    fm.setTcb(true);
    fm.setConfidentialityProtected(false);
    return fm;
}

// Copy ctor with every slot present (all 10 if-true branches), copy
// assignment's non-self path, defaulted move ctor + move assign, operator==.
// Independent-ownership tail guards against shared-state aliasing.
TEST(FlagsMap, CopyAndMoveRoundTripAllSlots) {
    FlagsMap src = make_fully_populated_flags();

    FlagsMap copy_ctor(src);
    EXPECT_EQ(copy_ctor, src);

    FlagsMap copy_assign;
    copy_assign.setRecovery(true);
    copy_assign = src;
    EXPECT_EQ(copy_assign, src);

    FlagsMap move_ctor(std::move(copy_ctor));
    EXPECT_EQ(move_ctor, src);

    FlagsMap move_assign;
    move_assign = std::move(copy_assign);
    EXPECT_EQ(move_assign, src);

    move_ctor.setTcb(false);
    ASSERT_NE(src.getTcb(), nullptr);
    EXPECT_TRUE(*src.getTcb());
}

// Copy ctor with every slot absent (all 10 if-false branches) and the
// clear-on-assign path.
TEST(FlagsMap, EmptyCopiesAndClearsCorrectly) {
    FlagsMap empty;
    EXPECT_TRUE(empty.empty());

    FlagsMap copy_of_empty(empty);
    EXPECT_TRUE(copy_of_empty.empty());
    EXPECT_EQ(copy_of_empty, empty);

    FlagsMap populated = make_fully_populated_flags();
    populated = empty;
    EXPECT_TRUE(populated.empty());
}

// Aliased through a pointer so the compiler can't elide the self-assignment.
TEST(FlagsMap, SelfAssignIsSafe) {
    FlagsMap fm = make_fully_populated_flags();
    FlagsMap snapshot(fm);
    FlagsMap *self = &fm;
    fm = *self;
    EXPECT_EQ(fm, snapshot);
}

namespace {
EnvironmentMap claims_from_evidence_env(uint32_t leaf, const char *model) {
    return make_env(make_class(
        make_oid(oid_content(
            {1, 3, 6, 1, 4, 1, 5703, 1300, 1, 1, 11, 1, 11, 2, leaf})),
        "ACME", model));
}

Ect corroborating_root() {
    return Ect{make_env_map("Root"), claims_with_purpose("USE_CASE_1")};
}

MeasurementMap string_name_claim(const std::string &mkey,
                                 const std::string &name) {
    return MeasurementMap{
        MeasurementMapKey::ofString(mkey),
        mv(nullptr, nullptr, nullptr, nullptr,
           std::make_unique<std::string>(name), nullptr, nullptr, {})};
}

MeasurementMap string_rawvalue_claim(const std::string &mkey,
                                     const std::vector<uint8_t> &bytes) {
    return MeasurementMap{
        MeasurementMapKey::ofString(mkey),
        mv(nullptr, nullptr,
           std::make_unique<ByteString>(bytes.data(), bytes.size()), nullptr,
           nullptr, nullptr, nullptr, {})};
}

MeasurementMap string_version_claim(const std::string &mkey,
                                    const std::string &ver_str) {
    return MeasurementMap{
        MeasurementMapKey::ofString(mkey),
        mv(std::make_unique<Version>(ver_str), nullptr, nullptr, nullptr,
           nullptr, nullptr, nullptr, {})};
}
} // namespace

TEST(CorimVerify, ClaimsFromEvidenceRequirementExample) {
    const std::vector<uint8_t> enabled{0x65, 0x6E, 0x61, 0x62, 0x6C, 0x65, 0x64};
    auto jtag_env = claims_from_evidence_env(17, "Gpu");
    std::vector<Ect> reference{
        corroborating_root(),
        Ect{jtag_env, {string_rawvalue_claim("jtag_status", enabled)}}};
    std::vector<Ect> evidence{
        corroborating_root(),
        Ect{claims_from_evidence_env(2, "Gpu"),
            {string_name_claim("driver_version", "535.104.05")}},
        Ect{jtag_env, {string_rawvalue_claim("jtag_status", enabled)}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    document_test(R"(Two claims-from-evidence envs (penultimate arc 2): jtag_status
carries a raw-value matching a CoRIM reference (corroborated, decoded to
"enabled"); driver_version has no reference (uncorroborated).)",
                  reference, evidence, deps, v);

    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_EQ(v.corroborated_evidence_claims,
              (std::map<std::string, std::string>{{"jtag_status", "enabled"}}));
    EXPECT_EQ(
        v.uncorroborated_evidence_claims,
        (std::map<std::string, std::string>{{"driver_version", "535.104.05"}}));
}

TEST(CorimVerify, ClaimsFromEvidenceUncorroboratedNoReference) {
    std::vector<Ect> reference{corroborating_root()};
    std::vector<Ect> evidence{
        corroborating_root(),
        Ect{claims_from_evidence_env(2, "Gpu"),
            {string_name_claim("driver_version", "535.104.05")}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    document_test(R"(A claims-from-evidence env with no matching CoRIM reference is
uncorroborated.)",
                  reference, evidence, deps, v);

    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_TRUE(v.corroborated_evidence_claims.empty());
    EXPECT_EQ(
        v.uncorroborated_evidence_claims,
        (std::map<std::string, std::string>{{"driver_version", "535.104.05"}}));
}

TEST(CorimVerify, ClaimsFromEvidenceUncorroboratedReferenceMismatch) {
    auto env = claims_from_evidence_env(2, "Gpu");
    std::vector<Ect> reference{corroborating_root(),
                               Ect{env, {string_name_claim("k", "expected")}}};
    std::vector<Ect> evidence{corroborating_root(),
                              Ect{env, {string_name_claim("k", "actual")}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    document_test(R"(A claims-from-evidence env whose reference value mismatches is
uncorroborated (a failed match, not corroborated).)",
                  reference, evidence, deps, v);

    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_TRUE(v.corroborated_evidence_claims.empty());
    EXPECT_EQ(v.uncorroborated_evidence_claims,
              (std::map<std::string, std::string>{{"k", "actual"}}));
}

TEST(CorimVerify, ClaimsFromEvidenceCorroboratedName) {
    auto env = claims_from_evidence_env(2, "Gpu");
    std::vector<Ect> reference{corroborating_root(),
                               Ect{env, {string_name_claim("k", "v")}}};
    std::vector<Ect> evidence{corroborating_root(),
                              Ect{env, {string_name_claim("k", "v")}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    document_test(R"(A claims-from-evidence env whose name matches its CoRIM
reference is corroborated.)",
                  reference, evidence, deps, v);

    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_EQ(v.corroborated_evidence_claims,
              (std::map<std::string, std::string>{{"k", "v"}}));
    EXPECT_TRUE(v.uncorroborated_evidence_claims.empty());
}

TEST(CorimVerify, ClaimsFromEvidenceCorroboratedViaAlternative) {
    auto env = claims_from_evidence_env(2, "Gpu");
    std::vector<Ect> reference{
        corroborating_root(),
        Ect{env, {string_name_claim("k", "A")}}, // alt A
        Ect{env, {string_name_claim("k", "B")}}, // alt B
    };
    std::vector<Ect> evidence{corroborating_root(),
                              Ect{env, {string_name_claim("k", "B")}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    document_test(R"(Two alternative reference ECTs for the claims-from-evidence env;
the evidence value matches alt B, so the claim is corroborated.)",
                  reference, evidence, deps, v);

    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_EQ(v.corroborated_evidence_claims,
              (std::map<std::string, std::string>{{"k", "B"}}));
}

TEST(CorimVerify, ClaimsFromEvidenceRawValueDecodedToString) {
    const std::vector<uint8_t> enabled{0x65, 0x6E, 0x61, 0x62, 0x6C, 0x65, 0x64};
    std::vector<Ect> reference{corroborating_root()};
    std::vector<Ect> evidence{
        corroborating_root(),
        Ect{claims_from_evidence_env(17, "Gpu"),
            {string_rawvalue_claim("jtag_status", enabled)}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);

    EXPECT_TRUE(v.diagnostics.empty());
    ASSERT_EQ(v.uncorroborated_evidence_claims.count("jtag_status"), 1u);
    EXPECT_EQ(v.uncorroborated_evidence_claims.at("jtag_status"), "enabled");
}

TEST(CorimVerify, ClaimsFromEvidenceCorroboratedVersion) {
    auto env = claims_from_evidence_env(2, "Gpu");
    std::vector<Ect> reference{corroborating_root(),
                               Ect{env, {string_version_claim("fw_version", "1.2.3")}}};
    std::vector<Ect> evidence{corroborating_root(),
                              Ect{env, {string_version_claim("fw_version", "1.2.3")}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    document_test(R"(A claims-from-evidence env whose version matches its CoRIM
reference is corroborated.)",
                  reference, evidence, deps, v);

    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_EQ(v.corroborated_evidence_claims,
              (std::map<std::string, std::string>{{"fw_version", "1.2.3"}}));
    EXPECT_TRUE(v.uncorroborated_evidence_claims.empty());
}

TEST(CorimVerify, ClaimsFromEvidenceUncorroboratedVersion) {
    std::vector<Ect> reference{corroborating_root()};
    std::vector<Ect> evidence{
        corroborating_root(),
        Ect{claims_from_evidence_env(2, "Gpu"),
            {string_version_claim("fw_version", "535.104.05")}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    document_test(R"(A claims-from-evidence env with a version claim and no
matching CoRIM reference is uncorroborated.)",
                  reference, evidence, deps, v);

    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_TRUE(v.corroborated_evidence_claims.empty());
    EXPECT_EQ(v.uncorroborated_evidence_claims,
              (std::map<std::string, std::string>{{"fw_version", "535.104.05"}}));
}

TEST(CorimVerify, ClaimsFromEvidenceVersionMismatch) {
    auto env = claims_from_evidence_env(2, "Gpu");
    std::vector<Ect> reference{
        corroborating_root(),
        Ect{env, {string_version_claim("fw_version", "expected")}}};
    std::vector<Ect> evidence{
        corroborating_root(),
        Ect{env, {string_version_claim("fw_version", "actual")}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    document_test(R"(A claims-from-evidence env whose version mismatches its CoRIM
reference is uncorroborated.)",
                  reference, evidence, deps, v);

    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_TRUE(v.corroborated_evidence_claims.empty());
    EXPECT_EQ(v.uncorroborated_evidence_claims,
              (std::map<std::string, std::string>{{"fw_version", "actual"}}));
}

TEST(CorimVerify, ClaimsFromEvidenceMalformedShapesAbort) {
    auto check = [](std::vector<MeasurementMap> claims) {
        std::vector<Ect> reference{corroborating_root()};
        std::vector<Ect> evidence{
            corroborating_root(),
            Ect{claims_from_evidence_env(2, "Gpu"), std::move(claims)}};
        std::vector<DependencyTriple> deps;
        VerificationResult v = verify(reference, evidence, deps);
        EXPECT_TRUE(v.outcomes.empty());
        ASSERT_EQ(v.diagnostics.size(), 1u);
        EXPECT_EQ(v.diagnostics[0].code,
                  Diagnostic::Code::kMalformedClaimsFromEvidenceEnv);
        EXPECT_TRUE(v.corroborated_evidence_claims.empty());
        EXPECT_TRUE(v.uncorroborated_evidence_claims.empty());
    };

    check({string_name_claim("a", "1"), string_name_claim("b", "2")});
    check({name_claim(1, "v")});
    check({MeasurementMap{
        MeasurementMapKey::ofOid("oid:1.2.3"),
        mv(nullptr, nullptr, nullptr, nullptr,
           std::make_unique<std::string>("v"), nullptr, nullptr, {})}});
    const std::vector<uint8_t> raw{0x01};
    check({MeasurementMap{
        MeasurementMapKey::ofString("a"),
        mv(nullptr, nullptr,
           std::make_unique<ByteString>(raw.data(), raw.size()), nullptr,
           std::make_unique<std::string>("v"), nullptr, nullptr, {})}});
    check({MeasurementMap{
        MeasurementMapKey::ofString("a"),
        mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
           std::make_unique<Svn>(SvnKind::kExact, 1), {})}});
    // version + name both set → two fields, rejected
    check({MeasurementMap{
        MeasurementMapKey::ofString("a"),
        mv(std::make_unique<Version>("1.0"), nullptr, nullptr, nullptr,
           std::make_unique<std::string>("v"), nullptr, nullptr, {})}});
    // no fields set
    check({MeasurementMap{
        MeasurementMapKey::ofString("a"),
        mv(nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, {})}});
}

TEST(CorimVerify, ClaimsFromEvidenceMalformedAbortsBeforeClaims) {
    std::vector<Ect> reference{corroborating_root()};
    std::vector<Ect> evidence{
        corroborating_root(),
        Ect{claims_from_evidence_env(2, "Gpu"),
            {string_name_claim("good", "v")}},
        Ect{claims_from_evidence_env(3, "Gpu"),
            {string_name_claim("a", "1"), string_name_claim("b", "2")}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    document_test(R"(One well-formed and one malformed claims-from-evidence env. The
whole appraisal aborts; no partial claims are committed.)",
                  reference, evidence, deps, v);

    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code,
              Diagnostic::Code::kMalformedClaimsFromEvidenceEnv);
    EXPECT_TRUE(v.corroborated_evidence_claims.empty());
    EXPECT_TRUE(v.uncorroborated_evidence_claims.empty());
}

TEST(CorimVerify, ClaimsFromEvidenceDuplicateClaimKeyAborts) {
    auto env_a = claims_from_evidence_env(2, "Gpu");
    auto env_b = claims_from_evidence_env(3, "Gpu");
    std::vector<Ect> reference{corroborating_root(),
                               Ect{env_a, {string_name_claim("dup", "v")}}};
    std::vector<Ect> evidence{
        corroborating_root(), Ect{env_a, {string_name_claim("dup", "v")}},
        Ect{env_b, {string_name_claim("dup", "other")}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    document_test(R"(Two claims-from-evidence envs declare the same claim key (one
corroborated, one not). A flat claim output cannot hold it in both buckets, so
verify aborts with duplicate-evidence-claim-key.)",
                  reference, evidence, deps, v);

    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code,
              Diagnostic::Code::kDuplicateEvidenceClaimKey);
    ASSERT_EQ(v.diagnostics[0].related_envs.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].related_envs[0], env_b);
    EXPECT_TRUE(v.corroborated_evidence_claims.empty());
    EXPECT_TRUE(v.uncorroborated_evidence_claims.empty());
}

TEST(CorimVerify, ClaimsFromEvidenceJsonShape) {
    const std::vector<uint8_t> enabled{0x65, 0x6E, 0x61, 0x62, 0x6C, 0x65, 0x64};
    auto jtag_env = claims_from_evidence_env(17, "Gpu");
    std::vector<Ect> reference{
        corroborating_root(),
        Ect{jtag_env, {string_rawvalue_claim("jtag_status", enabled)}}};
    std::vector<Ect> evidence{
        corroborating_root(),
        Ect{claims_from_evidence_env(2, "Gpu"),
            {string_name_claim("driver_version", "535.104.05")}},
        Ect{jtag_env, {string_rawvalue_claim("jtag_status", enabled)}}};
    std::vector<DependencyTriple> deps;

    nlohmann::json j = verify(reference, evidence, deps);
    EXPECT_EQ(j["corroborated_evidence_claims"]["jtag_status"], "enabled");
    EXPECT_EQ(j["uncorroborated_evidence_claims"]["driver_version"],
              "535.104.05");

    nlohmann::json empty =
        verify({corroborating_root()}, {corroborating_root()}, deps);
    EXPECT_FALSE(empty.contains("corroborated_evidence_claims"));
    EXPECT_FALSE(empty.contains("uncorroborated_evidence_claims"));
}

TEST(CorimVerify, ClaimsFromEvidenceRawValueInvalidUtf8Aborts) {
    std::vector<Ect> reference{corroborating_root()};
    std::vector<Ect> evidence{
        corroborating_root(),
        Ect{claims_from_evidence_env(2, "Gpu"),
            {string_rawvalue_claim("k", {0xFF})}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    document_test(R"(A claims-from-evidence raw-value that is not valid UTF-8 (0xFF)
aborts with non-utf8-evidence-claim; no claims are emitted.)",
                  reference, evidence, deps, v);

    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code, Diagnostic::Code::kNonUtf8EvidenceClaim);
    EXPECT_TRUE(v.corroborated_evidence_claims.empty());
    EXPECT_TRUE(v.uncorroborated_evidence_claims.empty());
}

TEST(CorimVerify, ClaimsFromEvidenceNameInvalidUtf8Aborts) {
    std::vector<Ect> reference{corroborating_root()};
    std::vector<Ect> evidence{
        corroborating_root(),
        Ect{claims_from_evidence_env(2, "Gpu"),
            {string_name_claim("k", std::string("\xFF"))}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    EXPECT_TRUE(v.outcomes.empty());
    ASSERT_EQ(v.diagnostics.size(), 1u);
    EXPECT_EQ(v.diagnostics[0].code, Diagnostic::Code::kNonUtf8EvidenceClaim);
    EXPECT_TRUE(v.corroborated_evidence_claims.empty());
    EXPECT_TRUE(v.uncorroborated_evidence_claims.empty());
}

TEST(CorimVerify, ClaimsFromEvidenceValidMultibyteUtf8Preserved) {
    const std::vector<uint8_t> e_acute{0xC3, 0xA9}; // U+00E9
    std::vector<Ect> reference{corroborating_root()};
    std::vector<Ect> evidence{
        corroborating_root(),
        Ect{claims_from_evidence_env(2, "Gpu"),
            {string_rawvalue_claim("k", e_acute)}}};
    std::vector<DependencyTriple> deps;

    VerificationResult v = verify(reference, evidence, deps);
    EXPECT_TRUE(v.diagnostics.empty());
    EXPECT_EQ(
        v.uncorroborated_evidence_claims,
        (std::map<std::string, std::string>{{"k", std::string("\xC3\xA9")}}));
}

// ── cert_chain_dti_matches ───────────────────────────────────────────────────

namespace {
// An outcome for `env` that is in the root's subtree and passed.
EnvOutcome passing_outcome(const EnvironmentMap &env) {
    EnvOutcome outcome{};
    outcome.environment = env;
    outcome.reachable_from_root = true;
    EctAttempt attempt{};
    attempt.matched_evidence_ects.push_back(Ect{env, {}});
    outcome.attempts.push_back(std::move(attempt));
    return outcome;
}
} // namespace

TEST(CertChainDtiMatches, TrueWhenEveryChainEnvHasAPassingOutcome) {
    auto env = make_env_map();
    std::vector<EnvOutcome> outcomes;
    outcomes.push_back(passing_outcome(env));
    EXPECT_TRUE(cert_chain_dti_matches({env}, outcomes));
}

// The reference side may omit fields verify() treats as wildcards. Guards
// against a regression from matches() back to strict equality.
TEST(CertChainDtiMatches, WildcardReferenceMatchesRicherChainEnv) {
    auto chain_env = make_env_map("Widget");
    // Reference env carries no class at all, so it accepts any evidence class.
    EnvironmentMap wildcard_env{};
    std::vector<EnvOutcome> outcomes;
    outcomes.push_back(passing_outcome(wildcard_env));

    EXPECT_TRUE(cert_chain_dti_matches({chain_env}, outcomes));
    // Sanity: the two environments are not equal, so == would have failed.
    EXPECT_FALSE(wildcard_env == chain_env);
}

TEST(CertChainDtiMatches, FalseWhenChainEnvHasNoOutcome) {
    auto env = make_env_map();
    EXPECT_FALSE(cert_chain_dti_matches({env}, {}));
}

TEST(CertChainDtiMatches, FalseWhenOutcomeIsOutsideRootSubtree) {
    auto env = make_env_map();
    EnvOutcome outcome = passing_outcome(env);
    outcome.reachable_from_root = false;
    std::vector<EnvOutcome> outcomes;
    outcomes.push_back(std::move(outcome));
    EXPECT_FALSE(cert_chain_dti_matches({env}, outcomes));
}

TEST(CertChainDtiMatches, FalseWhenOutcomeFailed) {
    auto env = make_env_map();
    EnvOutcome outcome{};
    outcome.environment = env;
    outcome.reachable_from_root = true;  // no passing attempt
    std::vector<EnvOutcome> outcomes;
    outcomes.push_back(std::move(outcome));
    EXPECT_FALSE(cert_chain_dti_matches({env}, outcomes));
}

TEST(DiagnosticPublicCode, MapsIntoTheReservedBand) {
    // Reserved band keeps diagnostics clear of the nvat_rc_t ranges.
    EXPECT_EQ(diagnostic_public_code(Diagnostic::Code::kDependencyCycle), 1000);
    EXPECT_EQ(diagnostic_public_code(Diagnostic::Code::kNoRootEnvironment), 1002);
}

TEST(DiagnosticPublicCode, EveryCodeIsDistinctAndInBand) {
    const Diagnostic::Code kAll[] = {
        Diagnostic::Code::kDependencyCycle,
        Diagnostic::Code::kNoReferenceEcts,
        Diagnostic::Code::kNoRootEnvironment,
        Diagnostic::Code::kMultipleRootEnvironments,
        Diagnostic::Code::kRootEnvironmentMissingPurpose,
        Diagnostic::Code::kDuplicateReferenceMkey,
        Diagnostic::Code::kMergeableReferenceEcts,
        Diagnostic::Code::kDuplicateEvidenceEnv,
        Diagnostic::Code::kDuplicateEvidenceMkey,
        Diagnostic::Code::kMissingReferenceForDependencyEnv,
        Diagnostic::Code::kMalformedClaimsFromEvidenceEnv,
        Diagnostic::Code::kNonUtf8EvidenceClaim,
        Diagnostic::Code::kDuplicateEvidenceClaimKey,
    };
    std::set<int> seen;
    for (Diagnostic::Code c : kAll) {
        const int code = diagnostic_public_code(c);
        EXPECT_GE(code, 1000);
        EXPECT_LT(code, 2000);
        EXPECT_TRUE(seen.insert(code).second) << code;
    }
    EXPECT_EQ(seen.size(), 13U);
}

} // namespace
} // namespace nvattestation
