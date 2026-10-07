/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <nlohmann/json.hpp>
#include <openssl/ocsp.h>
#include "nv_attestation/corim.h"
#include "nv_attestation/cose.h"
#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/nv_x509.h"
#include "test_utils.h"

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + path);
    }
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

static std::string get_corim_testdata(const std::string& filename) {
    return "testdata/sample_rims/corim/" + filename;
}

static std::string get_comid_testdata(const std::string& filename) {
    return "testdata/sample_rims/comid/" + filename;
}

static std::string get_golden_path(const std::string& kind, const std::string& name) {
    return "testdata/sample_rims/" + kind + "/golden/" + name + ".json";
}

// Set REGEN_GOLDENS=1 to overwrite the golden under the runtime testdata dir;
// copy the result back to source-tree testdata to commit.
static void compare_to_rim_golden(const nlohmann::json& actual, const std::string& name,
                                  const std::string& kind = "corim") {
    compare_to_golden(actual, get_golden_path(kind, name));
}

static nvattestation::CorimMap parse_corim(const std::vector<uint8_t>& bytes) {
    nvattestation::CorimMap corim;
    nvattestation::Error err = nvattestation::parse_unsigned_corim(bytes, corim);
    EXPECT_EQ(err, nvattestation::Error::Ok) << "parse_unsigned_corim failed";
    return corim;
}

static std::string get_signed_corim_testdata(const std::string& filename) {
    return "testdata/sample_rims/corim_signed/" + filename;
}

static std::string read_text_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error(
            "Failed to open: " + path +
            " (run `make prepare-test-data` to generate signing chain and signed fixtures)");
    }
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static const std::string& signed_corim_trust_anchor() {
    static const std::string pem =
        read_text_file("testdata/x509_cert_chain/cose_signing_root.crt");
    return pem;
}

namespace {
class NoopOcspHttpClient : public nvattestation::IOcspHttpClient {
public:
    nvattestation::Error get_ocsp_response(
        const nvattestation::nv_unique_ptr<X509>& /*subject_cert*/,
        const nvattestation::nv_unique_ptr<X509>& /*issuer_cert*/,
        const nvattestation::nv_unique_ptr<stack_st_X509>& /*intermediates*/,
        const nvattestation::nv_unique_ptr<X509_STORE>& /*trust_store*/,
        nvattestation::NvOcspResponse& /*out_ocsp_response*/) override {
        return nvattestation::Error::InternalError;
    }
};

// Reports every queried cert with a fixed OCSP status, to drive the
// signing-chain revocation-gating tests.
class FixedStatusOcspHttpClient : public nvattestation::IOcspHttpClient {
public:
    explicit FixedStatusOcspHttpClient(int status) : m_status(status) {}

    nvattestation::Error get_ocsp_response(
        const nvattestation::nv_unique_ptr<X509>& /*subject_cert*/,
        const nvattestation::nv_unique_ptr<X509>& /*issuer_cert*/,
        const nvattestation::nv_unique_ptr<stack_st_X509>& /*intermediates*/,
        const nvattestation::nv_unique_ptr<X509_STORE>& /*trust_store*/,
        nvattestation::NvOcspResponse& out_ocsp_response) override {
        out_ocsp_response = nvattestation::NvOcspResponse{};
        out_ocsp_response.response_valid = true;
        out_ocsp_response.status = m_status;
        out_ocsp_response.thisupd = 1700000000;
        out_ocsp_response.nextupd = 1700003600;
        out_ocsp_response.producedat = 1700000000;
        return nvattestation::Error::Ok;
    }

private:
    int m_status;
};
}  // namespace

static nvattestation::Error parse_signed_corim_with_ocsp_helper(
    const std::vector<uint8_t>& bytes,
    nvattestation::IOcspHttpClient& ocsp_client,
    nvattestation::CorimMap& out,
    std::vector<nvattestation::PerCertStatus>* out_claims = nullptr
) {
    nvattestation::CoseSign1VerifyOptions options;
    options.root_cert_pem = signed_corim_trust_anchor();
    std::vector<nvattestation::PerCertStatus> claims;
    nvattestation::Error err =
        nvattestation::parse_signed_corim(bytes, options, ocsp_client, out, claims, {});
    if (out_claims != nullptr) {
        *out_claims = std::move(claims);
    }
    return err;
}

static nvattestation::Error parse_signed_corim_helper(
    const std::vector<uint8_t>& bytes,
    nvattestation::CorimMap& out,
    const nvattestation::CorimParseOptions& parse_options = {},
    const std::string* root_pem_override = nullptr
) {
    NoopOcspHttpClient ocsp_client;
    nvattestation::CoseSign1VerifyOptions options;
    options.verify_ocsp = false;
    options.root_cert_pem = root_pem_override ? *root_pem_override : signed_corim_trust_anchor();
    std::vector<nvattestation::PerCertStatus> claims;
    return nvattestation::parse_signed_corim(bytes, options, ocsp_client, out, claims, parse_options);
}

TEST(CorimParse, ParseFullCorim) {
    auto bytes = read_file(get_corim_testdata("full.cbor"));
    auto corim = parse_corim(bytes);
    EXPECT_FALSE(corim.getId().empty());

    nlohmann::json j = corim;
    compare_to_rim_golden(j, "full");

    // Lock the wrapper accessors that golden-JSON projection flattens.
    const auto& tags = corim.getCoMidTags();
    ASSERT_GE(tags.size(), 1u);

    const auto& triples = tags[0].getReferenceTriples();
    ASSERT_GE(triples.size(), 1u);
    const auto* cls = triples[0].getEnvironment().getClass();
    ASSERT_NE(cls, nullptr);
    EXPECT_NE(cls->getClassId(), nullptr);
    EXPECT_NE(cls->getVendor(), nullptr);
    EXPECT_NE(cls->getModel(), nullptr);
    EXPECT_NE(cls->getLayer(), nullptr);
    EXPECT_NE(cls->getIndex(), nullptr);

    const auto& comid_entities = tags[0].getEntities();
    ASSERT_GE(comid_entities.size(), 1u);
    bool seen_tag_creator = false, seen_creator = false, seen_maintainer = false;
    for (const auto& ent : comid_entities) {
        for (auto role : ent.getRoles()) {
            if (role == nvattestation::EntityRole::TagCreator) seen_tag_creator = true;
            if (role == nvattestation::EntityRole::Creator) seen_creator = true;
            if (role == nvattestation::EntityRole::Maintainer) seen_maintainer = true;
        }
    }
    EXPECT_TRUE(seen_tag_creator && seen_creator && seen_maintainer);

    bool found_multi_digest = false;
    for (const auto& trip : triples) {
        for (const auto& meas : trip.getMeasurements()) {
            if (meas.getValues().getDigests().size() >= 2u) {
                found_multi_digest = true;
                break;
            }
        }
    }
    EXPECT_TRUE(found_multi_digest)
        << "full.cbor expected to carry at least one measurement with 2+ digests";
}

TEST(CorimParse, AcceptsMixedTagTypes) {
    // Parser surfaces the CoMID and quietly ignores the dummy CoSWID/CoTL tags.
    auto bytes = read_file(get_corim_testdata("mixed_tags.cbor"));
    nvattestation::CorimMap corim;
    ASSERT_EQ(nvattestation::parse_unsigned_corim(bytes, corim), nvattestation::Error::Ok);
    EXPECT_EQ(corim.getCoMidTags().size(), 1u);
}

TEST(CorimParse, RejectEmptyTagsArray) {
    // corim-map.tags is bounded 1*25: an empty array must fail to decode.
    auto bytes = read_file(get_corim_testdata("empty_tags.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(nvattestation::parse_unsigned_corim(bytes, corim),
              nvattestation::Error::RimInvalidSchema);
}

TEST(CorimParse, RejectTooManyTags) {
    auto bytes = read_file(get_corim_testdata("reject_too_many_tags.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(nvattestation::parse_unsigned_corim(bytes, corim),
              nvattestation::Error::RimInvalidSchema);
}

TEST(CorimParse, ParseMultiEntity) {
    auto bytes = read_file(get_corim_testdata("multi_entity.cbor"));
    nvattestation::CorimMap corim;
    ASSERT_EQ(nvattestation::parse_unsigned_corim(bytes, corim), nvattestation::Error::Ok);

    const auto& entities = corim.getEntities();
    ASSERT_EQ(entities.size(), 2u);
    EXPECT_EQ(entities[0].getName(), "First Entity");
    EXPECT_NE(entities[0].getRegId(), nullptr);
    ASSERT_EQ(entities[0].getRoles().size(), 1u);
    EXPECT_EQ(entities[0].getRoles()[0], nvattestation::CorimRole::ManifestCreator);

    EXPECT_EQ(entities[1].getName(), "Second Entity");
    EXPECT_EQ(entities[1].getRegId(), nullptr);
    ASSERT_EQ(entities[1].getRoles().size(), 2u);
}

TEST(CorimParse, ParseComidEntityRoles) {
    auto bytes = read_file(get_comid_testdata("entity_roles.cbor"));
    nvattestation::ConciseMidTag tag;
    ASSERT_EQ(nvattestation::parse_comid(bytes, tag), nvattestation::Error::Ok);

    const auto& entities = tag.getEntities();
    ASSERT_EQ(entities.size(), 2u);

    EXPECT_EQ(entities[0].getName(), "Vendor A");
    ASSERT_NE(entities[0].getRegId(), nullptr);
    EXPECT_EQ(*entities[0].getRegId(), "https://vendora.example/registry");
    ASSERT_EQ(entities[0].getRoles().size(), 1u);
    EXPECT_EQ(entities[0].getRoles()[0], nvattestation::EntityRole::TagCreator);

    EXPECT_EQ(entities[1].getName(), "Vendor B");
    EXPECT_EQ(entities[1].getRegId(), nullptr);
    ASSERT_EQ(entities[1].getRoles().size(), 2u);
    EXPECT_EQ(entities[1].getRoles()[0], nvattestation::EntityRole::Creator);
    EXPECT_EQ(entities[1].getRoles()[1], nvattestation::EntityRole::Maintainer);
}

TEST(CorimParse, MalformedOidProfileRejected) {
    // Profile carries a tag-111 bstr whose payload is not a valid OID body.
    // The wrapper turns it into an empty dotted string; no matcher will match.
    auto bytes = read_file(get_corim_testdata("with_malformed_oid_profile.cbor"));
    nvattestation::CorimParseOptions opts;
    opts.accepted_profiles.push_back(
        std::make_shared<const nvattestation::ExactOidMatcher>("1.2.3.4"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(nvattestation::parse_unsigned_corim(bytes, corim, opts),
              nvattestation::Error::RimInvalidSchema);
}

TEST(CorimParse, ParseOidProfile) {
    auto bytes = read_file(get_corim_testdata("with_oid_profile.cbor"));
    nvattestation::CorimParseOptions opts;
    opts.accepted_profiles.push_back(
        std::make_shared<const nvattestation::ExactOidMatcher>("1.2.3.4"));

    nvattestation::CorimMap corim;
    ASSERT_EQ(nvattestation::parse_unsigned_corim(bytes, corim, opts),
              nvattestation::Error::Ok);

    const auto* profile = corim.getProfile();
    ASSERT_NE(profile, nullptr);
    EXPECT_EQ(profile->kind, nvattestation::ProfileKind::Oid);
    EXPECT_EQ(profile->value, "1.2.3.4");
}

TEST(CorimParse, ParseAlternateCorim) {
    auto bytes = read_file(get_corim_testdata("alternate.cbor"));
    auto corim = parse_corim(bytes);
    EXPECT_FALSE(corim.getId().empty());

    nlohmann::json j = corim;
    compare_to_rim_golden(j, "alternate");
}

TEST(CorimParse, EnvironmentEquality) {
    auto bytes = read_file(get_corim_testdata("alternate.cbor"));
    auto corim = parse_corim(bytes);

    const auto& tags = corim.getCoMidTags();
    ASSERT_EQ(tags.size(), 1u);

    const auto& triples = tags[0].getReferenceTriples();
    ASSERT_EQ(triples.size(), 3u);

    auto& env1 = triples[0].getEnvironment();
    auto& env2 = triples[1].getEnvironment();
    auto& env3 = triples[2].getEnvironment();

    // Triple 1 and Triple 3 have the same environment (OID class-id + "TestVendor")
    EXPECT_EQ(env1, env3);
    EXPECT_FALSE(env1 != env3);

    // Triple 1 and Triple 2 have different environments
    EXPECT_NE(env1, env2);
    EXPECT_FALSE(env1 == env2);

    // ClassMap equality
    auto* cls1 = env1.getClass();
    auto* cls2 = env2.getClass();
    auto* cls3 = env3.getClass();
    ASSERT_NE(cls1, nullptr);
    ASSERT_NE(cls2, nullptr);
    ASSERT_NE(cls3, nullptr);
    EXPECT_EQ(*cls1, *cls3);
    EXPECT_NE(*cls1, *cls2);

    // Cross-input: vendor-only ClassMap from full.cbor != full ClassMap from full.cbor
    auto full_bytes = read_file(get_corim_testdata("full.cbor"));
    auto full_corim = parse_corim(full_bytes);
    const auto& full_tags = full_corim.getCoMidTags();
    ASSERT_EQ(full_tags.size(), 1u);
    const auto& full_triples = full_tags[0].getReferenceTriples();
    ASSERT_GE(full_triples.size(), 2u);

    auto* full_cls1 = full_triples[0].getEnvironment().getClass();
    auto* full_cls2 = full_triples[1].getEnvironment().getClass();
    ASSERT_NE(full_cls1, nullptr);
    ASSERT_NE(full_cls2, nullptr);
    EXPECT_NE(*full_cls1, *full_cls2);
}

TEST(CorimParse, ParseExtendedCorim) {
    auto bytes = read_file(get_corim_testdata("extended.cbor"));
    auto corim = parse_corim(bytes);

    nlohmann::json j = corim;
    compare_to_rim_golden(j, "extended");

    // The JSON projection erases the IntRange/MeasurementMapKey variant
    // distinctions, so cover the C++ accessors here.
    const auto& tags = corim.getCoMidTags();
    ASSERT_EQ(tags.size(), 1u);
    const auto& ref_triples = tags[0].getReferenceTriples();
    ASSERT_EQ(ref_triples.size(), 3u);

    {
        auto key = ref_triples[0].getMeasurements()[0].getKey();
        EXPECT_EQ(key.type, nvattestation::MeasurementMapKey::Type::kString);
        std::string str_val;
        EXPECT_TRUE(key.asString(str_val));
        EXPECT_EQ(str_val, "firmware-version");

        const auto* ir = ref_triples[0].getMeasurements()[0].getValues().getIntRange();
        ASSERT_NE(ir, nullptr);
        int32_t simple_val = 0;
        EXPECT_TRUE(ir->isSimpleInt(simple_val));
        EXPECT_EQ(simple_val, 42);
    }

    {
        auto key = ref_triples[1].getMeasurements()[0].getKey();
        EXPECT_TRUE(key.isAbsent());

        const auto* ir = ref_triples[1].getMeasurements()[0].getValues().getIntRange();
        ASSERT_NE(ir, nullptr);
        bool has_min = false, has_max = false;
        int32_t min_val = 0, max_val = 0;
        EXPECT_TRUE(ir->isRange(has_min, min_val, has_max, max_val));
        EXPECT_TRUE(has_min);
        EXPECT_EQ(min_val, 5);
        EXPECT_TRUE(has_max);
        EXPECT_EQ(max_val, 10);
    }

    {
        const auto* ir = ref_triples[2].getMeasurements()[0].getValues().getIntRange();
        ASSERT_NE(ir, nullptr);
        bool has_min = false, has_max = false;
        int32_t min_val = 0, max_val = 0;
        EXPECT_TRUE(ir->isRange(has_min, min_val, has_max, max_val));
        EXPECT_FALSE(has_min);
        EXPECT_TRUE(has_max);
        EXPECT_EQ(max_val, 100);
    }
}

TEST(CorimParse, ParseUserSuppliedCorim) {
    const char* path = std::getenv("CORIM_FILE");
    if (!path || std::strlen(path) == 0) {
        GTEST_SKIP() << "Set CORIM_FILE=/path/to/file.cbor to run this test";
    }

    std::vector<uint8_t> bytes;
    try {
        bytes = read_file(path);
    } catch (const std::runtime_error& e) {
        FAIL() << e.what();
    }
    ASSERT_FALSE(bytes.empty()) << "File is empty: " << path;

    nlohmann::json j;

    // Try CoRIM first (tag 501), fall back to standalone CoMID (tag 506)
    nvattestation::CorimMap corim;
    nvattestation::Error err = nvattestation::parse_unsigned_corim(bytes, corim);
    if (err == nvattestation::Error::Ok) {
        j = corim;
    } else {
        nvattestation::ConciseMidTag comid;
        nvattestation::Error comid_err = nvattestation::parse_comid(bytes, comid);
        ASSERT_EQ(comid_err, nvattestation::Error::Ok)
            << "Both parse_unsigned_corim and parse_comid failed for: " << path;
        j = {{"comid", comid}};
    }

    std::cout << j.dump(2) << std::endl;
}

TEST(CorimParse, ParseMaskedRawValueComid) {
    auto bytes = read_file(get_comid_testdata("masked_raw_value.cbor"));
    nvattestation::ConciseMidTag tag;
    nvattestation::Error err = nvattestation::parse_comid(bytes, tag);
    ASSERT_EQ(err, nvattestation::Error::Ok);

    nlohmann::json j = tag;
    compare_to_rim_golden(j, "masked_raw_value", "comid");
}

TEST(CorimParse, ParseEnvIdVariants) {
    auto bytes = read_file(get_comid_testdata("env_id_variants.cbor"));
    nvattestation::ConciseMidTag tag;
    nvattestation::Error err = nvattestation::parse_comid(bytes, tag);
    ASSERT_EQ(err, nvattestation::Error::Ok);

    nlohmann::json j = tag;
    compare_to_rim_golden(j, "env_id_variants", "comid");

    const auto& triples = tag.getReferenceTriples();
    ASSERT_EQ(triples.size(), 3u);

    // Triple 1: instance/group both UUID.
    {
        const auto* inst = triples[0].getEnvironment().getInstance();
        const auto* grp  = triples[0].getEnvironment().getGroup();
        ASSERT_NE(inst, nullptr);
        ASSERT_NE(grp, nullptr);
        EXPECT_EQ(inst->getKind(), nvattestation::InstanceId::Kind::kUuid);
        EXPECT_EQ(grp->getKind(), nvattestation::GroupId::Kind::kUuid);

        const auto* ver = triples[0].getMeasurements()[0].getValues().getVersion();
        ASSERT_NE(ver, nullptr);
        EXPECT_EQ(ver->getSchemeKind(), nvattestation::Version::SchemeKind::kText);
        ASSERT_NE(ver->getSchemeText(), nullptr);
        EXPECT_EQ(*ver->getSchemeText(), "rolling");
    }

    // Triple 2: instance = ueid, group = bytes.
    {
        const auto* inst = triples[1].getEnvironment().getInstance();
        const auto* grp  = triples[1].getEnvironment().getGroup();
        ASSERT_NE(inst, nullptr);
        ASSERT_NE(grp, nullptr);
        EXPECT_EQ(inst->getKind(), nvattestation::InstanceId::Kind::kUeid);
        EXPECT_EQ(grp->getKind(), nvattestation::GroupId::Kind::kBytes);
    }

    // Triple 3: instance = bytes, no group.
    {
        const auto* inst = triples[2].getEnvironment().getInstance();
        ASSERT_NE(inst, nullptr);
        EXPECT_EQ(inst->getKind(), nvattestation::InstanceId::Kind::kBytes);
        EXPECT_EQ(triples[2].getEnvironment().getGroup(), nullptr);
    }
}

TEST(CorimParse, ParseIgnoredTriples) {
    auto bytes = read_file(get_corim_testdata("ignored_triples.cbor"));
    nvattestation::CorimMap corim;
    nvattestation::Error err = nvattestation::parse_unsigned_corim(bytes, corim);
    ASSERT_EQ(err, nvattestation::Error::Ok);

    // The reference-triple is surfaced; endorsed-triples and conditional-
    // endorsement-triples are silently dropped.
    const auto& tags = corim.getCoMidTags();
    ASSERT_EQ(tags.size(), 1u);
    EXPECT_EQ(tags[0].getReferenceTriples().size(), 1u);
}

TEST(CorimParse, RejectUnknownProfile) {
    auto bytes = read_file(get_corim_testdata("with_profile.cbor"));
    nvattestation::CorimMap corim;
    nvattestation::Error err = nvattestation::parse_unsigned_corim(bytes, corim);
    EXPECT_EQ(err, nvattestation::Error::RimInvalidSchema)
        << "Any profile value must be rejected (no profiles supported)";
}

TEST(CorimParse, AcceptKnownProfileExact) {
    auto bytes = read_file(get_corim_testdata("with_profile.cbor"));
    nvattestation::CorimParseOptions opts;
    opts.accepted_profiles.push_back(
        std::make_shared<const nvattestation::ExactUriMatcher>(
            "http://example.test/unknown-profile"));

    nvattestation::CorimMap corim;
    nvattestation::Error err = nvattestation::parse_unsigned_corim(bytes, corim, opts);
    ASSERT_EQ(err, nvattestation::Error::Ok);

    const nvattestation::ProfileValue* profile = corim.getProfile();
    ASSERT_NE(profile, nullptr);
    EXPECT_EQ(profile->kind, nvattestation::ProfileKind::Uri);
    EXPECT_EQ(profile->value, "http://example.test/unknown-profile");
}

TEST(CorimParse, RejectProfileNotInAllowlist) {
    auto bytes = read_file(get_corim_testdata("with_profile.cbor"));
    nvattestation::CorimParseOptions opts;
    opts.accepted_profiles.push_back(
        std::make_shared<const nvattestation::ExactUriMatcher>(
            "http://other.test/profile"));

    nvattestation::CorimMap corim;
    nvattestation::Error err = nvattestation::parse_unsigned_corim(bytes, corim, opts);
    EXPECT_EQ(err, nvattestation::Error::RimInvalidSchema);
}

// A shadowed member reaches the same generic "extension fields not supported"
// rejection as a genuinely unknown key, so the diagnostic is what tells the two
// apart. Logs go to stderr (log.cpp uses spdlog::stderr_color_mt).
TEST(CorimParse, BareTextProfileIsNamedInTheDiagnostic) {
    auto bytes = read_file(get_corim_testdata("with_text_profile.cbor"));
    nvattestation::CorimParseOptions opts;
    nvattestation::CorimMap corim;

    testing::internal::CaptureStderr();
    nvattestation::Error err = nvattestation::parse_unsigned_corim(bytes, corim, opts);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, nvattestation::Error::RimInvalidSchema);
    EXPECT_NE(logs.find("key 3 (profile) is malformed, not absent"), std::string::npos)
        << "expected the shadowed-member diagnostic, got:\n" << logs;
    EXPECT_EQ(logs.find("extension fields not supported"), std::string::npos)
        << "the generic message must not be used for a shadowed member:\n" << logs;
}

// Only the first extension entry can be blamed. An unknown key ahead of a
// well-formed member halts zcbor's positional walk, so that member is swept
// into the extension array too — valid, but displaced. Blaming it would send
// the reader after a member that is perfectly fine.
TEST(CorimParse, UnknownExtensionBeforeValidMemberIsNotBlamed) {
    auto bytes = read_file(get_corim_testdata("unknown_ext_before_profile.cbor"));
    nvattestation::CorimParseOptions opts;
    nvattestation::CorimMap corim;

    testing::internal::CaptureStderr();
    nvattestation::Error err = nvattestation::parse_unsigned_corim(bytes, corim, opts);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, nvattestation::Error::RimInvalidSchema);
    EXPECT_EQ(logs.find("(profile) is malformed"), std::string::npos)
        << "the profile is well-formed here, only displaced:\n" << logs;
    EXPECT_NE(logs.find("extension fields not supported"), std::string::npos)
        << "expected the generic message when entry 0 is an unknown key:\n" << logs;
}

TEST(CorimParse, RejectBareTextProfile) {
    // profile-type-choice is uri / tagged-oid-type. A bare tstr profile is not
    // a valid encoding and is rejected while decoding, before any matcher runs
    // — so this fails even though the literal value matches the allow-list.
    auto bytes = read_file(get_corim_testdata("with_text_profile.cbor"));
    nvattestation::CorimParseOptions opts;
    opts.accepted_profiles.push_back(
        std::make_shared<const nvattestation::ExactUriMatcher>(
            "http://example.test/unknown-profile"));

    nvattestation::CorimMap corim;
    nvattestation::Error err = nvattestation::parse_unsigned_corim(bytes, corim, opts);
    EXPECT_EQ(err, nvattestation::Error::RimInvalidSchema);
}

TEST(ProfileMatcher, ExactOidMatcherEnforcesOidShape) {
    EXPECT_THROW(nvattestation::ExactOidMatcher("not-an-oid"), std::invalid_argument);
    EXPECT_THROW(nvattestation::ExactOidMatcher(""), std::invalid_argument);
    EXPECT_THROW(nvattestation::ExactOidMatcher("1..2"), std::invalid_argument);
    EXPECT_THROW(nvattestation::ExactOidMatcher("1.2."), std::invalid_argument);
    EXPECT_THROW(nvattestation::ExactOidMatcher(".1.2"), std::invalid_argument);

    using PV = nvattestation::ProfileValue;
    using PK = nvattestation::ProfileKind;
    nvattestation::ExactOidMatcher m("1.2.999");
    EXPECT_TRUE (m.matches(PV{PK::Oid,  "1.2.999"}));
    EXPECT_FALSE(m.matches(PV{PK::Oid,  "1.2.999.1"}));   // not exact
    EXPECT_FALSE(m.matches(PV{PK::Oid,  "1.2.9991"}));    // arc-boundary
    EXPECT_FALSE(m.matches(PV{PK::Text, "1.2.999"}));     // text spelling an OID
    EXPECT_FALSE(m.matches(PV{PK::Uri,  "1.2.999"}));     // URI spelling an OID
}

TEST(ProfileMatcher, OidSubtreeMatcherArcBoundary) {
    using PV = nvattestation::ProfileValue;
    using PK = nvattestation::ProfileKind;
    nvattestation::OidSubtreeMatcher m("1.2.999");
    EXPECT_TRUE (m.matches(PV{PK::Oid,  "1.2.999"}));
    EXPECT_TRUE (m.matches(PV{PK::Oid,  "1.2.999.1"}));
    EXPECT_TRUE (m.matches(PV{PK::Oid,  "1.2.999.4.5"}));
    EXPECT_FALSE(m.matches(PV{PK::Oid,  "1.2.9991"}));     // arc-boundary
    EXPECT_FALSE(m.matches(PV{PK::Oid,  "1.2.99"}));       // not in subtree
    EXPECT_FALSE(m.matches(PV{PK::Oid,  "1.2.999."}));     // ill-formed
    EXPECT_FALSE(m.matches(PV{PK::Text, "1.2.999"}));      // wrong kind
    EXPECT_FALSE(m.matches(PV{PK::Uri,  "1.2.999.1"}));    // wrong kind
}

TEST(ProfileMatcher, ExactUriAndTextRejectCrossKind) {
    using PV = nvattestation::ProfileValue;
    using PK = nvattestation::ProfileKind;
    nvattestation::ExactUriMatcher  uri("http://x");
    nvattestation::ExactTextMatcher text("foo");
    EXPECT_TRUE (uri .matches(PV{PK::Uri,  "http://x"}));
    EXPECT_FALSE(uri .matches(PV{PK::Text, "http://x"}));
    EXPECT_FALSE(uri .matches(PV{PK::Oid,  "http://x"}));
    EXPECT_TRUE (text.matches(PV{PK::Text, "foo"}));
    EXPECT_FALSE(text.matches(PV{PK::Uri,  "foo"}));
    EXPECT_FALSE(text.matches(PV{PK::Oid,  "foo"}));
}

TEST(ProfileMatcher, VersionedUriMatcherTerminalPathSegment) {
    using PV = nvattestation::ProfileValue;
    using PK = nvattestation::ProfileKind;
    nvattestation::VersionedUriMatcher m(
        "tag:nvidia.com,2026:ear/profiles/composite/generic/1.*.*");
    EXPECT_TRUE (m.matches(PV{PK::Uri,  "tag:nvidia.com,2026:ear/profiles/composite/generic/1.0.0"}));
    EXPECT_TRUE (m.matches(PV{PK::Uri,  "tag:nvidia.com,2026:ear/profiles/composite/generic/1.9.3"}));
    EXPECT_FALSE(m.matches(PV{PK::Uri,  "tag:nvidia.com,2026:ear/profiles/composite/generic/2.0.0"}));
    EXPECT_FALSE(m.matches(PV{PK::Uri,  "tag:nvidia.com,2026:ear/profiles/composite/generic/1.0"}));
    EXPECT_FALSE(m.matches(PV{PK::Uri,  "tag:nvidia.com,2026:ear/profiles/composite/different/1.0.0"}));
    EXPECT_FALSE(m.matches(PV{PK::Oid,  "tag:nvidia.com,2026:ear/profiles/composite/generic/1.0.0"}));
    // Text kind also accepted (not just Uri)
    EXPECT_TRUE (m.matches(PV{PK::Text, "tag:nvidia.com,2026:ear/profiles/composite/generic/1.0.0"}));
}

TEST(ProfileMatcher, VersionedUriMatcherFragment) {
    using PV = nvattestation::ProfileValue;
    using PK = nvattestation::ProfileKind;
    nvattestation::VersionedUriMatcher m("tag:arm.com,2025:psa#1.*.*");
    EXPECT_TRUE (m.matches(PV{PK::Uri,  "tag:arm.com,2025:psa#1.0.0"}));
    EXPECT_TRUE (m.matches(PV{PK::Uri,  "tag:arm.com,2025:psa#1.2.99"}));
    EXPECT_FALSE(m.matches(PV{PK::Uri,  "tag:arm.com,2025:psa#2.0.0"}));
    EXPECT_FALSE(m.matches(PV{PK::Uri,  "tag:arm.com,2025:other#1.0.0"}));
}

TEST(ProfileMatcher, VersionedUriMatcherNoWildcardExactOnly) {
    using PV = nvattestation::ProfileValue;
    using PK = nvattestation::ProfileKind;
    nvattestation::VersionedUriMatcher m(
        "tag:nvidia.com,2026:ear/profiles/composite/generic/1.0.0");
    EXPECT_TRUE (m.matches(PV{PK::Uri,  "tag:nvidia.com,2026:ear/profiles/composite/generic/1.0.0"}));
    EXPECT_FALSE(m.matches(PV{PK::Uri,  "tag:nvidia.com,2026:ear/profiles/composite/generic/1.0.1"}));
}

TEST(ProfileMatcher, VersionedUriMatcherMinorWildcard) {
    using PV = nvattestation::ProfileValue;
    using PK = nvattestation::ProfileKind;
    nvattestation::VersionedUriMatcher m(
        "tag:nvidia.com,2026:ear/profiles/composite/generic/1.2.*");
    EXPECT_TRUE (m.matches(PV{PK::Uri,  "tag:nvidia.com,2026:ear/profiles/composite/generic/1.2.0"}));
    EXPECT_TRUE (m.matches(PV{PK::Uri,  "tag:nvidia.com,2026:ear/profiles/composite/generic/1.2.99"}));
    EXPECT_FALSE(m.matches(PV{PK::Uri,  "tag:nvidia.com,2026:ear/profiles/composite/generic/1.3.0"}));
}

TEST(CorimParse, ProfileAbsentIsAlwaysAccepted) {
    // alternate.cbor has no profile field; default-constructed options
    // (empty allow-list) must still parse successfully because profile is
    // optional in the CDDL.
    auto bytes = read_file(get_corim_testdata("alternate.cbor"));
    nvattestation::CorimMap corim;
    nvattestation::Error err = nvattestation::parse_unsigned_corim(bytes, corim);
    ASSERT_EQ(err, nvattestation::Error::Ok);
    EXPECT_EQ(corim.getProfile(), nullptr);
}

TEST(CorimParse, ParseCoverageCorim) {
    // Catch-all fixture for happy-path parser branches none of the other
    // fixtures hit: every version-scheme variant, mval.name, all flags
    // (incl. is-tcb / is-confidentiality-protected), plain svn-val (untagged
    // uint), tstr digest algorithm, manifest-signer entity role, and a
    // validity-map with only not_after.
    auto bytes = read_file(get_corim_testdata("coverage.cbor"));
    nvattestation::CorimMap corim;
    nvattestation::Error err = nvattestation::parse_unsigned_corim(bytes, corim);
    ASSERT_EQ(err, nvattestation::Error::Ok);

    nlohmann::json j = corim;
    compare_to_rim_golden(j, "coverage");

    // Validity: not_after only, not_before absent.
    const auto* validity = corim.getRimValidity();
    ASSERT_NE(validity, nullptr);
    std::chrono::system_clock::time_point tp;
    EXPECT_FALSE(validity->getNotBefore(tp));
    EXPECT_TRUE(validity->getNotAfter(tp));

    // CorimRole::ManifestSigner survives JSON projection but pin it here too.
    ASSERT_EQ(corim.getEntities().size(), 1u);
    const auto& roles = corim.getEntities()[0].getRoles();
    ASSERT_EQ(roles.size(), 1u);
    EXPECT_EQ(roles[0], nvattestation::CorimRole::ManifestSigner);

    const auto& tags = corim.getCoMidTags();
    ASSERT_EQ(tags.size(), 1u);
    const auto& triples = tags[0].getReferenceTriples();
    ASSERT_EQ(triples.size(), 3u);

    // Triple 1 tail: plain svn-val (kExact), mval.name, tstr-keyed mkey.
    {
        const auto& meas = triples[0].getMeasurements();
        ASSERT_GE(meas.size(), 7u);
        const auto* svn = meas[6].getValues().getSvn();
        ASSERT_NE(svn, nullptr);
        EXPECT_EQ(svn->value, 42u);
        EXPECT_EQ(svn->kind, nvattestation::SvnKind::kExact);
        ASSERT_GE(meas.size(), 8u);
        const auto* name = meas[7].getValues().getName();
        ASSERT_NE(name, nullptr);
        EXPECT_EQ(*name, "named-measurement");
        ASSERT_EQ(meas.size(), 10u);
        auto tstr_key = meas[8].getKey();
        EXPECT_EQ(tstr_key.type, nvattestation::MeasurementMapKey::Type::kString);
        std::string tstr_key_val;
        ASSERT_TRUE(tstr_key.asString(tstr_key_val));
        EXPECT_EQ(tstr_key_val, "tstr-keyed-measurement");

        // meas[9]: binary version-scheme (scheme 5) surfaced as base64url-decoded bytes.
        const auto* bin_ver = meas[9].getValues().getVersion();
        ASSERT_NE(bin_ver, nullptr);
        EXPECT_EQ(bin_ver->getSchemeKind(), nvattestation::Version::SchemeKind::kBinary);
        EXPECT_EQ(bin_ver->getValue(), std::string("\x01\x02\x03\xff", 4));
    }

    // Triple 2: every flag bit set, including is-tcb and is-confidentiality-protected.
    {
        const auto* flags = triples[1].getMeasurements()[0].getValues().getFlags();
        ASSERT_NE(flags, nullptr);
        ASSERT_NE(flags->getTcb(), nullptr);
        EXPECT_TRUE(*flags->getTcb());
        ASSERT_NE(flags->getConfidentialityProtected(), nullptr);
        EXPECT_TRUE(*flags->getConfidentialityProtected());
    }

    // Triple 3: digest carries a tstr algorithm name (Digest::AlgKind::kString).
    {
        const auto& digests = triples[2].getMeasurements()[0].getValues().getDigests();
        ASSERT_EQ(digests.size(), 1u);
        std::string alg_str;
        int32_t alg_int = 0;
        EXPECT_TRUE(digests[0].getAlgorithm(alg_str));
        EXPECT_FALSE(digests[0].getAlgorithm(alg_int));
        EXPECT_EQ(alg_str, "sha-256");
    }
}

// Each rejection fixture decodes successfully via zcbor but must be rejected
// by the wrapper layer. The fixture name encodes the field under test.

class CorimRejectFixture : public ::testing::TestWithParam<const char*> {};

TEST_P(CorimRejectFixture, ParserRejectsField) {
    std::string fixture = GetParam();
    auto bytes = read_file(get_corim_testdata(fixture + ".cbor"));
    nvattestation::CorimMap corim;
    nvattestation::Error err = nvattestation::parse_unsigned_corim(bytes, corim);
    EXPECT_EQ(err, nvattestation::Error::RimInvalidSchema)
        << "Expected " << fixture << ".cbor to be rejected by the wrapper";
}

INSTANTIATE_TEST_SUITE_P(
    UnsupportedFields, CorimRejectFixture,
    ::testing::Values(
        "reject_dependent_rims",
        "reject_validity_float"
    ),
    [](const ::testing::TestParamInfo<const char*>& info) {
        return std::string(info.param);
    }
);

class ComidRejectFixture : public ::testing::TestWithParam<const char*> {};

TEST_P(ComidRejectFixture, ParserRejectsField) {
    std::string fixture = GetParam();
    auto bytes = read_file(get_comid_testdata(fixture + ".cbor"));
    nvattestation::ConciseMidTag tag;
    nvattestation::Error err = nvattestation::parse_comid(bytes, tag);
    EXPECT_EQ(err, nvattestation::Error::RimInvalidSchema)
        << "Expected " << fixture << ".cbor to be rejected by parse_comid";
}

INSTANTIATE_TEST_SUITE_P(
    UnsupportedFields, ComidRejectFixture,
    ::testing::Values(
        "reject_authorized_by",
        "reject_mval_ueid",
        "reject_mval_uuid",
        "reject_mval_raw_value_mask_deprecated",
        "reject_masked_raw_value_length_mismatch",
        "reject_mval_mac_addr",
        "reject_mval_ip_addr",
        "reject_mval_serial_number",
        "reject_mval_cryptokeys",
        "reject_mval_integrity_registers",
        "reject_mval_spdm_indirect",
        "reject_linked_tags",
        "reject_identity_triples",
        "reject_attest_key_triples",
        "reject_membership_triples",
        "reject_coswid_triples"
    ),
    [](const ::testing::TestParamInfo<const char*>& info) {
        return std::string(info.param);
    }
);

TEST(CorimParse, RejectVersionBinarySchemeInvalidBase64) {
    auto bytes = read_file(get_comid_testdata("reject_mval_version_binary_invalid_base64.cbor"));
    nvattestation::ConciseMidTag tag;
    nvattestation::Error err = nvattestation::parse_comid(bytes, tag);
    EXPECT_EQ(err, nvattestation::Error::RimInvalidSchema);
}

TEST(CorimParse, ErrorCases) {
    nvattestation::CorimMap corim;

    // Empty input
    {
        std::vector<uint8_t> empty;
        nvattestation::Error err = nvattestation::parse_unsigned_corim(empty, corim);
        EXPECT_EQ(err, nvattestation::Error::RimInvalidSchema);
    }

    // Invalid CBOR (random bytes)
    {
        std::vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF};
        nvattestation::Error err = nvattestation::parse_unsigned_corim(garbage, corim);
        EXPECT_EQ(err, nvattestation::Error::RimInvalidSchema);
    }

    // Truncated: valid CBOR tag 501 but truncated content
    {
        // Tag 501 = 0xD9 0x01 0xF5, followed by truncated map
        std::vector<uint8_t> truncated = {0xD9, 0x01, 0xF5, 0xA1};
        nvattestation::Error err = nvattestation::parse_unsigned_corim(truncated, corim);
        EXPECT_EQ(err, nvattestation::Error::RimInvalidSchema);
    }

    // Valid CoRIM with trailing extra bytes
    {
        auto valid = read_file(get_corim_testdata("full.cbor"));
        valid.push_back(0x00);
        nvattestation::Error err = nvattestation::parse_unsigned_corim(valid, corim);
        EXPECT_EQ(err, nvattestation::Error::RimInvalidSchema);
    }
}

TEST(CorimParse, ParseSignedFull) {
    auto bytes = read_file(get_signed_corim_testdata("signed_full.cbor"));
    nvattestation::CorimMap corim;
    ASSERT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::Ok);
    nlohmann::json j = corim;
    compare_to_rim_golden(j, "full");
}

TEST(CorimParse, ParseSignedRevokedSigningCertRejected) {
    // Needs a chain with >=2 certs: the OCSP check pairs each subject with
    // its issuer, so a lone leaf (signed_full.cbor) has nothing to check.
    auto bytes = read_file(get_signed_corim_testdata("signed_full_chained.cbor"));
    FixedStatusOcspHttpClient ocsp_client(V_OCSP_CERTSTATUS_REVOKED);
    nvattestation::CorimMap corim;
    std::vector<nvattestation::PerCertStatus> claims;
    EXPECT_EQ(parse_signed_corim_with_ocsp_helper(bytes, ocsp_client, corim, &claims),
              nvattestation::Error::CertChainVerificationFailure);
    // Cert-chain diagnostics must survive the rejection, not just the error code.
    EXPECT_FALSE(claims.empty());
}

TEST(CorimParse, ParseSignedUnknownSigningCertRejected) {
    auto bytes = read_file(get_signed_corim_testdata("signed_full_chained.cbor"));
    FixedStatusOcspHttpClient ocsp_client(V_OCSP_CERTSTATUS_UNKNOWN);
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_with_ocsp_helper(bytes, ocsp_client, corim),
              nvattestation::Error::CertChainVerificationFailure);
}

TEST(CorimParse, ParseSignedFullChained) {
    // x5chain emitted as a 2-element CBOR array (leaf + root) instead of the
    // single-cert bare-bstr form. Exercises COSE_X509_chain in cose.cddl.
    auto bytes = read_file(get_signed_corim_testdata("signed_full_chained.cbor"));
    nvattestation::CorimMap corim;
    ASSERT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::Ok);
    nlohmann::json j = corim;
    compare_to_rim_golden(j, "full");
}

TEST(CorimParse, ParseSignedX5ChainUnprotected) {
    // x5chain in unprotected map; protected carries x5t binding (RFC 9360).
    auto bytes = read_file(get_signed_corim_testdata("signed_x5chain_unprotected.cbor"));
    nvattestation::CorimMap corim;
    ASSERT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::Ok);
}

TEST(CorimParse, ParseSignedX5ChainUnprotectedSha256) {
    auto bytes = read_file(get_signed_corim_testdata("signed_x5chain_unprotected_sha256.cbor"));
    nvattestation::CorimMap corim;
    ASSERT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::Ok);
}

TEST(CorimParse, ParseSignedX5ChainUnprotectedSha512) {
    auto bytes = read_file(get_signed_corim_testdata("signed_x5chain_unprotected_sha512.cbor"));
    nvattestation::CorimMap corim;
    ASSERT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::Ok);
}

TEST(CorimParse, RejectSignedGarbageBytes) {
    // Hits parse_cose_sign1's outer cbor_decode_COSE_Sign1_Tagged failure path.
    std::vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03};
    nvattestation::CorimMap corim;
    EXPECT_NE(parse_signed_corim_helper(garbage, corim), nvattestation::Error::Ok);
}

TEST(CorimParse, RejectSignedEmptyInput) {
    std::vector<uint8_t> empty;
    nvattestation::CorimMap corim;
    EXPECT_NE(parse_signed_corim_helper(empty, corim), nvattestation::Error::Ok);
}

TEST(CorimParse, RejectSignedX5ChainInBoth) {
    auto bytes = read_file(get_signed_corim_testdata("signed_reject_x5chain_in_both.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::CoseParseError);
}

TEST(CorimParse, RejectSignedX5tMismatch) {
    auto bytes = read_file(get_signed_corim_testdata("signed_reject_x5t_mismatch.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim),
              nvattestation::Error::CoseThumbprintMismatch);
}

TEST(CorimParse, ParseSignedX5ChainUnprotectedWithoutX5t) {
    auto bytes = read_file(
        get_signed_corim_testdata("signed_x5chain_unprotected_no_x5t.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::Ok);
}

TEST(CorimParse, RejectSignedUnknownX5tAlg) {
    auto bytes = read_file(get_signed_corim_testdata("signed_reject_unknown_x5t_alg.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::CoseParseError);
}

TEST(CorimParse, RejectSignedDetachedPayload) {
    auto bytes = read_file(get_signed_corim_testdata("signed_reject_detached_payload.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::CoseParseError);
}

TEST(CorimParse, RejectSignedEmptyProtected) {
    auto bytes = read_file(get_signed_corim_testdata("signed_reject_empty_protected.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::CoseParseError);
}

TEST(CorimParse, RejectSignedInvalidCertInX5Chain) {
    auto bytes = read_file(get_signed_corim_testdata("signed_reject_invalid_cert_in_x5chain.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_NE(parse_signed_corim_helper(bytes, corim), nvattestation::Error::Ok);
}

TEST(CorimParse, ParseSignedExtended) {
    auto bytes = read_file(get_signed_corim_testdata("signed_extended.cbor"));
    nvattestation::CorimMap corim;
    ASSERT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::Ok);
    nlohmann::json j = corim;
    compare_to_rim_golden(j, "extended");
}

TEST(CorimParse, SignedWithProfileRespectsAllowlist) {
    auto bytes = read_file(get_signed_corim_testdata("signed_with_profile.cbor"));

    {
        nvattestation::CorimMap corim;
        EXPECT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::RimInvalidSchema)
            << "Default options must reject unknown profiles, signed wrapper or not";
    }

    {
        nvattestation::CorimParseOptions opts;
        opts.accepted_profiles.push_back(
            std::make_shared<const nvattestation::ExactUriMatcher>(
                "http://example.test/unknown-profile"));
        nvattestation::CorimMap corim;
        ASSERT_EQ(parse_signed_corim_helper(bytes, corim, opts), nvattestation::Error::Ok);
        const auto* profile = corim.getProfile();
        ASSERT_NE(profile, nullptr);
        EXPECT_EQ(profile->kind, nvattestation::ProfileKind::Uri);
        EXPECT_EQ(profile->value, "http://example.test/unknown-profile");
    }
}

TEST(CorimParse, RejectSignedBadSignature) {
    auto bytes = read_file(get_signed_corim_testdata("signed_reject_bad_sig.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::CoseInvalidSignature);
}

TEST(CorimParse, RejectSignedTruncatedSignature) {
    // ES384 signatures are r||s = 96 bytes. A truncated 64-byte sig must be
    // rejected by the EVP_DigestVerifyFinal path (no bespoke size gate in
    // the SDK — the verifier itself catches this).
    auto bytes = read_file(get_signed_corim_testdata("signed_reject_truncated_sig.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::CoseInvalidSignature);
}

TEST(CorimParse, RejectSignedWrongAlg) {
    auto bytes = read_file(get_signed_corim_testdata("signed_reject_wrong_alg.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::CoseParseError);
}

TEST(CorimParse, RejectSignedMissingX5Chain) {
    auto bytes = read_file(get_signed_corim_testdata("signed_reject_missing_x5chain.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::CoseParseError);
}

TEST(CorimParse, RejectSignedTamperedPayload) {
    auto bytes = read_file(get_signed_corim_testdata("signed_reject_tampered_payload.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::CoseInvalidSignature);
}

TEST(CorimParse, RejectSignedWrongTrustAnchor) {
    auto bytes = read_file(get_signed_corim_testdata("signed_full.cbor"));
    std::string wrong_anchor = read_text_file("testdata/trusted_certs/rim_root.crt");
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim, {}, &wrong_anchor),
              nvattestation::Error::CertChainVerificationFailure);
}

TEST(CorimParse, ParseSignedWithExtraProtectedHeaders) {
    // Exercises CDDL tolerance for keys 3 (content_type) and 8 (custom) that
    // appear between alg (key 1) and x5chain (key 33) in the protected header.
    auto bytes = read_file(get_signed_corim_testdata("signed_with_extra_protected_headers.cbor"));
    nvattestation::CorimMap corim;
    EXPECT_EQ(parse_signed_corim_helper(bytes, corim), nvattestation::Error::Ok);
}

// --- extract_cose_sign1_payload tests ---

TEST(ExtractCoseSign1Payload, EmptyInput) {
    std::vector<uint8_t> out;
    EXPECT_EQ(nvattestation::extract_cose_sign1_payload({}, out),
              nvattestation::Error::CoseParseError);
}

TEST(ExtractCoseSign1Payload, UnsignedInput) {
    auto bytes = read_file(get_corim_testdata("full.cbor"));
    std::vector<uint8_t> out;
    EXPECT_EQ(nvattestation::extract_cose_sign1_payload(bytes, out),
              nvattestation::Error::CoseParseError);
}

TEST(ExtractCoseSign1Payload, GarbageWithCoseTag) {
    // 0xd2 is the COSE_Sign1 tag byte; the remaining bytes are not valid CBOR.
    std::vector<uint8_t> garbage = {0xd2, 0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint8_t> out;
    EXPECT_NE(nvattestation::extract_cose_sign1_payload(garbage, out),
              nvattestation::Error::Ok);
}

TEST(ExtractCoseSign1Payload, ValidSignedCorimYieldsUnsignedPayload) {
    auto signed_bytes = read_file(get_signed_corim_testdata("signed_full.cbor"));
    auto unsigned_bytes = read_file(get_corim_testdata("full.cbor"));

    std::vector<uint8_t> out;
    ASSERT_EQ(nvattestation::extract_cose_sign1_payload(signed_bytes, out),
              nvattestation::Error::Ok);
    EXPECT_EQ(out, unsigned_bytes);
}
