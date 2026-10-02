/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "nv_attestation/corim_evidence/eat.h"
#include "nv_attestation/corim_evidence/eat_cwt.h"
#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/nv_x509.h"
#include "test_utils.h"

namespace nvattestation {
namespace {

// Loads a compiled .cbor fixture from the eat fixture dir.
std::vector<uint8_t> load_eat_fixture(const std::string& name) {
    const std::string path = "testdata/sample_rims/eat/" + name + ".cbor";
    std::ifstream s(path, std::ios::binary);
    if (!s) {
        ADD_FAILURE() << "missing fixture: " << path;
        return {};
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(s)),
                                std::istreambuf_iterator<char>());
}

std::string read_text_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        ADD_FAILURE() << "missing file: " << path;
        return {};
    }
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// OCSP is disabled in these tests (verify_ocsp=false), so the client is never
// called; this stub satisfies the IOcspHttpClient reference parameter.
class NoopOcspHttpClient : public IOcspHttpClient {
public:
    Error get_ocsp_response(const nv_unique_ptr<X509>& /*subject_cert*/,
                            const nv_unique_ptr<X509>& /*issuer_cert*/,
                            const nv_unique_ptr<stack_st_X509>& /*intermediates*/,
                            const nv_unique_ptr<X509_STORE>& /*trust_store*/,
                            NvOcspResponse& /*out_ocsp_response*/) override {
        return Error::InternalError;
    }
};

TEST(Eat, EmptyBufferIsEvidenceMalformed) {
    Eat out;
    EXPECT_EQ(parse_eat_claims({}, out), Error::EvidenceMalformed);
}

TEST(Eat, DefaultConstructsEmpty) {
    Eat eat;
    EXPECT_TRUE(eat.getNonce().empty());
    EXPECT_TRUE(eat.getMeasurements().empty());
    EXPECT_EQ(eat.getProfile(), nullptr);
}

TEST(Eat, FullFixtureParses) {
    auto bytes = load_eat_fixture("full");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    ASSERT_EQ(parse_eat_claims(bytes, eat), Error::Ok);
    EXPECT_EQ(eat.getNonce().size(), 8u);
    ASSERT_NE(eat.getDebugStatus(), nullptr);
    EXPECT_EQ(*eat.getDebugStatus(), DebugStatus::DisabledPermanently);
    ASSERT_NE(eat.getProfile(), nullptr);
    EXPECT_EQ(eat.getProfile()->kind, ProfileKind::Oid);
    EXPECT_EQ(eat.getProfile()->value, "1.3.6.1.4.1.42623.1.3");
    ASSERT_EQ(eat.getMeasurements().size(), 1u);
    EXPECT_EQ(eat.getMeasurements()[0].content_format_id,
              kConciseEvidenceContentFormatId);
    // measurements body parsed into ConciseEvidence:
    EXPECT_FALSE(eat.getMeasurements()[0].evidence.getEvTriples()
                     .getEvidenceTriples().empty());
}

TEST(Eat, MissingNonceIsEvidenceMalformed) {
    auto bytes = load_eat_fixture("missing_nonce");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    EXPECT_EQ(parse_eat_claims(bytes, eat), Error::EvidenceMalformed);
}

TEST(Eat, MissingMeasurementsIsEvidenceMalformed) {
    auto bytes = load_eat_fixture("missing_measurements");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    EXPECT_EQ(parse_eat_claims(bytes, eat), Error::EvidenceMalformed);
}

// eat_profile may be a URI instead of an OID (RFC 9711). The parser accepts
// it and exposes the kind; it does not reject on profile value.
TEST(Eat, ProfileUriParses) {
    auto bytes = load_eat_fixture("profile_uri");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    ASSERT_EQ(parse_eat_claims(bytes, eat), Error::Ok);
    ASSERT_NE(eat.getProfile(), nullptr);
    EXPECT_EQ(eat.getProfile()->kind, ProfileKind::Uri);
    EXPECT_EQ(eat.getProfile()->value, "https://nvidia.example/eat-profile");
}

// to_json renders a URI-kind eat_profile with kind "uri" (exercises the
// profile-kind rendering for the non-OID branch).
TEST(Eat, ProfileUriJsonHasUriKind) {
    auto bytes = load_eat_fixture("profile_uri");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    ASSERT_EQ(parse_eat_claims(bytes, eat), Error::Ok);
    nlohmann::json j;
    to_json(j, eat);
    ASSERT_TRUE(j.contains("eat_profile"));
    EXPECT_EQ(j["eat_profile"]["kind"], "uri");
    EXPECT_EQ(j["eat_profile"]["value"], "https://nvidia.example/eat-profile");
}

TEST(Eat, UnknownClaimIsTolerated) {
    auto bytes = load_eat_fixture("unknown_claim");
    Eat eat;
    EXPECT_EQ(parse_eat_claims(bytes, eat), Error::Ok);
}

TEST(Eat, PrivateClaimTolerated) {
    auto bytes = load_eat_fixture("private_claim");
    Eat eat;
    EXPECT_EQ(parse_eat_claims(bytes, eat), Error::Ok);
}

TEST(Eat, FullFixtureJsonMatchesGolden) {
    auto bytes = load_eat_fixture("full");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    ASSERT_EQ(parse_eat_claims(bytes, eat), Error::Ok);
    nlohmann::json j;
    to_json(j, eat);
    compare_to_golden(j, "testdata/sample_rims/eat/golden/full.json");
}

TEST(Eat, UnknownContentFormatRemainsNumericInJson) {
    MeasurementsFormat measurement;
    measurement.content_format_id = 4242;
    Eat eat;
    eat.setMeasurements({measurement});

    nlohmann::json j;
    to_json(j, eat);

    ASSERT_EQ(j["measurements"].size(), 1u);
    EXPECT_EQ(j["measurements"][0]["content-type"], 4242);
}

TEST(Eat, SignedTokenVerifiesAndParses) {
    auto bytes = load_eat_fixture("full_signed");
    ASSERT_FALSE(bytes.empty());
    CoseSign1VerifyOptions opts;
    opts.verify_ocsp = false;
    opts.root_cert_pem =
        read_text_file("testdata/x509_cert_chain/cose_signing_root.crt");
    ASSERT_FALSE(opts.root_cert_pem.empty());
    NoopOcspHttpClient ocsp;
    Eat eat;
    ASSERT_EQ(verify_and_parse_eat_cwt(bytes, opts, ocsp, eat), Error::Ok);
    ASSERT_NE(eat.getProfile(), nullptr);
    EXPECT_EQ(eat.getProfile()->value, "1.3.6.1.4.1.42623.1.3");
}

// The self-described CBOR and CWT tags are optional.
TEST(Eat, BareCoseWithoutOuterTagsVerifiesAndParses) {
    auto bytes = load_eat_fixture("bare_cose");
    ASSERT_FALSE(bytes.empty());
    CoseSign1VerifyOptions opts;
    opts.verify_ocsp = false;
    opts.root_cert_pem =
        read_text_file("testdata/x509_cert_chain/cose_signing_root.crt");
    ASSERT_FALSE(opts.root_cert_pem.empty());
    NoopOcspHttpClient ocsp;
    Eat eat;
    ASSERT_EQ(verify_and_parse_eat_cwt(bytes, opts, ocsp, eat), Error::Ok);
    ASSERT_NE(eat.getProfile(), nullptr);
    EXPECT_EQ(eat.getProfile()->value, "1.3.6.1.4.1.42623.1.3");
}

TEST(Eat, EmptySignedBufferIsEvidenceMalformed) {
    CoseSign1VerifyOptions opts;
    NoopOcspHttpClient ocsp;
    Eat eat;
    EXPECT_EQ(verify_and_parse_eat_cwt({}, opts, ocsp, eat), Error::EvidenceMalformed);
}

TEST(Eat, AbsentDebugStatusIsNullAndOmittedFromJson) {
    auto bytes = load_eat_fixture("measurements_body_untagged");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    ASSERT_EQ(parse_eat_claims(bytes, eat), Error::Ok);

    EXPECT_EQ(eat.getDebugStatus(), nullptr);

    nlohmann::json j;
    to_json(j, eat);
    EXPECT_FALSE(j.contains("dbgstat"));
}

TEST(Eat, AllOptionalClaimsParse) {
    auto bytes = load_eat_fixture("full_all_optionals");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    ASSERT_EQ(parse_eat_claims(bytes, eat), Error::Ok);

    ASSERT_NE(eat.getDebugStatus(), nullptr);
    EXPECT_EQ(*eat.getDebugStatus(), DebugStatus::Disabled);
    ASSERT_NE(eat.getIssuer(), nullptr);
    EXPECT_EQ(*eat.getIssuer(), "https://ocp.example/attestation");
    ASSERT_NE(eat.getCti(), nullptr);
    EXPECT_EQ(eat.getCti()->size(), 8u);
    ASSERT_NE(eat.getUeid(), nullptr);
    ASSERT_NE(eat.getSueid(), nullptr);
    ASSERT_NE(eat.getHwModel(), nullptr);
    ASSERT_NE(eat.getUptime(), nullptr);
    EXPECT_EQ(*eat.getUptime(), 123456u);
    ASSERT_NE(eat.getBootCount(), nullptr);
    EXPECT_EQ(*eat.getBootCount(), 7u);
    ASSERT_NE(eat.getBootSeed(), nullptr);
    EXPECT_EQ(eat.getBootSeed()->size(), 32u);

    // rim-locators: first is a single URI, second is a two-URI list.
    ASSERT_EQ(eat.getRimLocators().size(), 2u);
    EXPECT_EQ(eat.getRimLocators()[0].getUris().size(), 1u);
    EXPECT_EQ(eat.getRimLocators()[1].getUris().size(), 2u);

    Eat copy(eat);
    ASSERT_NE(copy.getIssuer(), nullptr);
    EXPECT_EQ(*copy.getIssuer(), *eat.getIssuer());
    ASSERT_NE(copy.getBootSeed(), nullptr);
    EXPECT_EQ(*copy.getBootSeed(), *eat.getBootSeed());
    EXPECT_EQ(copy.getRimLocators().size(), 2u);
}

void expect_claims_decoded_regardless_of_order(const std::string& fixture) {
    SCOPED_TRACE(fixture);
    auto bytes = load_eat_fixture(fixture);
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    ASSERT_EQ(parse_eat_claims(bytes, eat), Error::Ok);

    EXPECT_EQ(eat.getNonce(), (std::vector<uint8_t>{0x00, 0x11, 0x22, 0x33,
                                                    0x44, 0x55, 0x66, 0x77}));
    ASSERT_NE(eat.getDebugStatus(), nullptr);
    EXPECT_EQ(*eat.getDebugStatus(), DebugStatus::Disabled);
    ASSERT_NE(eat.getProfile(), nullptr);
    EXPECT_EQ(eat.getProfile()->kind, ProfileKind::Oid);
    EXPECT_EQ(eat.getProfile()->value, "1.3.6.1.4.1.42623.1.3");
    ASSERT_NE(eat.getIssuer(), nullptr);
    EXPECT_EQ(*eat.getIssuer(), "https://ocp.example/attestation");
    ASSERT_NE(eat.getUeid(), nullptr);
    EXPECT_EQ(eat.getUeid()->size(), 10u);
    ASSERT_EQ(eat.getRimLocators().size(), 1u);
    ASSERT_EQ(eat.getRimLocators()[0].getUris().size(), 1u);
    EXPECT_EQ(eat.getRimLocators()[0].getUris()[0],
              "https://rim.example/single.corim");
    ASSERT_EQ(eat.getMeasurements().size(), 1u);
    EXPECT_EQ(eat.getMeasurements()[0].content_format_id,
              kConciseEvidenceContentFormatId);
    EXPECT_FALSE(eat.getMeasurements()[0].evidence.getEvTriples()
                     .getEvidenceTriples().empty());
}

TEST(Eat, ClaimsDecodeInReverseOrder) {
    expect_claims_decoded_regardless_of_order("claim_order_reversed");
}

TEST(Eat, ClaimsDecodeWithPrivateClaimsInterleaved) {
    expect_claims_decoded_regardless_of_order("claim_order_interleaved");
}

TEST(Eat, ClaimsDecodeWithMandatoryClaimsLast) {
    expect_claims_decoded_regardless_of_order("claim_order_mandatory_last");
}

TEST(Eat, UntaggedMeasurementsBodyParses) {
    auto bytes = load_eat_fixture("measurements_body_untagged");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    ASSERT_EQ(parse_eat_claims(bytes, eat), Error::Ok);

    ASSERT_EQ(eat.getMeasurements().size(), 1u);
    EXPECT_FALSE(eat.getMeasurements()[0].evidence.getEvTriples()
                     .getEvidenceTriples().empty());
}

TEST(Eat, NestedMeasurementValuesMapDecodesOutOfOrder) {
    auto bytes = load_eat_fixture("nested_map_order_scrambled");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    ASSERT_EQ(parse_eat_claims(bytes, eat), Error::Ok);

    ASSERT_EQ(eat.getMeasurements().size(), 1u);
    const auto& triples =
        eat.getMeasurements()[0].evidence.getEvTriples().getEvidenceTriples();
    ASSERT_EQ(triples.size(), 1u);
    ASSERT_EQ(triples[0].getMeasurements().size(), 1u);

    const auto& values = triples[0].getMeasurements()[0].getValues();
    ASSERT_NE(values.getName(), nullptr);
    EXPECT_EQ(*values.getName(), "scrambled-mval");
    EXPECT_EQ(values.getDigests().size(), 1u);
}

TEST(Eat, MalformedMeasurementsBodyIsEvidenceMalformed) {
    auto bytes = load_eat_fixture("bad_measurements_body");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    EXPECT_EQ(parse_eat_claims(bytes, eat), Error::EvidenceMalformed);
}

TEST(Eat, AllOptionalsJsonMatchesGolden) {
    auto bytes = load_eat_fixture("full_all_optionals");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    ASSERT_EQ(parse_eat_claims(bytes, eat), Error::Ok);
    nlohmann::json j;
    to_json(j, eat);
    compare_to_golden(j, "testdata/sample_rims/eat/golden/full_all_optionals.json");
}

// 55799(0): self-described-CBOR tag wrapping a bare integer, not a
// #6.18(COSE_Sign1).
TEST(Eat, NonCoseSign1PayloadIsCoseParseError) {
    const std::vector<uint8_t> bytes = {0xD9, 0xD9, 0xF7, 0x00};
    CoseSign1VerifyOptions opts;
    opts.verify_ocsp = false;
    opts.root_cert_pem =
        read_text_file("testdata/x509_cert_chain/cose_signing_root.crt");
    ASSERT_FALSE(opts.root_cert_pem.empty());
    NoopOcspHttpClient ocsp;
    Eat eat;
    EXPECT_EQ(verify_and_parse_eat_cwt(bytes, opts, ocsp, eat), Error::CoseParseError);
}

// A well-formed tag stack whose COSE_Sign1 cannot be verified (no trust anchor)
// must propagate the verification failure rather than parse the payload.
TEST(Eat, SignatureVerificationFailurePropagates) {
    auto bytes = load_eat_fixture("full_signed");
    ASSERT_FALSE(bytes.empty());
    CoseSign1VerifyOptions opts;
    opts.verify_ocsp = false;
    opts.root_cert_pem = "";  // no trust anchor -> COSE_Sign1 verification fails
    NoopOcspHttpClient ocsp;
    Eat eat;
    EXPECT_NE(verify_and_parse_eat_cwt(bytes, opts, ocsp, eat), Error::Ok);
}

TEST(Eat, MalformedUeidIsNamedNotTolerated) {
    // A declared claim whose value fails validation lands in the `* int => any`
    // catch-all. It is malformed, not an unknown claim key.
    auto bytes = load_eat_fixture("malformed_ueid");
    ASSERT_FALSE(bytes.empty());
    Eat eat;

    testing::internal::CaptureStderr();
    Error err = parse_eat_claims(bytes, eat);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::EvidenceMalformed);
    EXPECT_NE(logs.find("key 256 (ueid) is malformed"), std::string::npos)
        << "expected the shadowed-member diagnostic, got:\n" << logs;
    EXPECT_EQ(logs.find("unknown claim key tolerated"), std::string::npos)
        << "a malformed claim must not be reported as unknown:\n" << logs;
}

// Vendor claims interleaved between the declared ones, mirroring a real
// bmsai_platform token. rim-locators sits past several of them, so it is the
// first thing lost if the claims map is walked in wire order.
TEST(Eat, ScrambledInterleavedOrderParses) {
    auto bytes = load_eat_fixture("scrambled_interleaved");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    ASSERT_EQ(parse_eat_claims(bytes, eat), Error::Ok);

    EXPECT_EQ(eat.getNonce().size(), 8u);
    ASSERT_NE(eat.getProfile(), nullptr);
    EXPECT_EQ(eat.getProfile()->kind, ProfileKind::Oid);
    EXPECT_EQ(eat.getMeasurements().size(), 1u);
    ASSERT_NE(eat.getUeid(), nullptr);
    ASSERT_NE(eat.getHwModel(), nullptr);
    ASSERT_EQ(eat.getRimLocators().size(), 1u);
    EXPECT_EQ(eat.getRimLocators()[0].getUris().size(), 1u);
}

TEST(Eat, ScrambledMissingMandatoryIsEvidenceMalformed) {
    auto bytes = load_eat_fixture("scrambled_missing_mandatory");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    EXPECT_EQ(parse_eat_claims(bytes, eat), Error::EvidenceMalformed);
}

}  // namespace
}  // namespace nvattestation
