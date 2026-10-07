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

#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>
#include "jwt-cpp/traits/nlohmann-json/traits.h"

#include "nv_attestation/claims.h"
#include "nv_attestation/corim_verify.h"
#include "nv_attestation/ear_mapper.h"
#include "nv_attestation/utils.h"

namespace nvattestation {
namespace {

// A passing item needs a corroborated outcome in the root's subtree; an
// appraisal with no outcomes has affirmed nothing.
CorimAttestationResult make_passing_result(const std::string& label) {
    CorimAttestationResult result{};
    EvidenceItemAppraisal item{};
    item.label = label;
    item.evidence.signature_verified = true;
    item.evidence.parsed = true;

    EnvOutcome outcome{};
    outcome.reachable_from_root = true;
    EctAttempt attempt{};
    attempt.matched_evidence_ects.push_back(Ect{EnvironmentMap{}, {}});
    outcome.attempts.push_back(std::move(attempt));
    item.match.outcomes.push_back(std::move(outcome));

    result.items.push_back(std::move(item));
    return result;
}

// Starts from the passing baseline so only stage_error drives the outcome.
CorimAttestationResult make_failing_result(const std::string& label,
                                           const std::string& stage_error) {
    CorimAttestationResult result = make_passing_result(label);
    result.items[0].stage_error = {Error::InternalError, stage_error, ""};
    return result;
}

// ── Top-level structure ──────────────────────────────────────────────────────

TEST(EarMapperTest, TopLevelMandatoryFieldsPresent) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_TRUE(ear.contains("eat_profile"));
    EXPECT_EQ(ear["eat_profile"].get<std::string>(),
              "tag:nvidia.com,2026:ear/profiles/composite/generic/pre-1.0.0");
    EXPECT_TRUE(ear.contains("iat"));
    EXPECT_TRUE(ear.contains("nbf"));
    EXPECT_TRUE(ear.contains("exp"));
    EXPECT_TRUE(ear.contains("ear_verifier_id"));
    EXPECT_TRUE(ear.contains("ear_status"));
    EXPECT_TRUE(ear.contains("submods"));
}

TEST(EarMapperTest, VerifierIdHardcoded) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_EQ(ear["ear_verifier_id"]["developer"].get<std::string>(),
              "https://developer.nvidia.com/attestation");
    // build starts with "corim-verifier/" followed by the version
    const std::string build = ear["ear_verifier_id"]["build"].get<std::string>();
    EXPECT_EQ(build.rfind("corim-verifier/", 0), 0u);
}

TEST(EarMapperTest, IssAbsentByDefault) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_FALSE(ear.contains("iss"));
}

TEST(EarMapperTest, ExpIsAfterIat) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_GT(ear["exp"].get<int64_t>(), ear["iat"].get<int64_t>());
}

// ── ear_nvidia_inputs.digests ────────────────────────────────────────────────

// Helper: build a result with one pre-computed InputDigest.
CorimAttestationResult make_result_with_digest(
        const std::string& label, HashAlgorithm alg,
        std::vector<uint8_t> val) {
    auto result = make_passing_result(label);
    InputDigest d;
    d.alg = alg;
    d.val = std::move(val);
    result.input_digests.push_back(std::move(d));
    return result;
}

TEST(EarMapperTest, InputDigestEmittedFromResultField) {
    // Digest comes from result.input_digests, not computed from cmw bytes.
    auto result = make_result_with_digest(
        "gpu_0", HashAlgorithm::Sha256, {0xde, 0xad, 0xbe, 0xef});
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    ASSERT_TRUE(ear.contains("ear_nvidia_inputs"));
    ASSERT_TRUE(ear["ear_nvidia_inputs"].contains("digests"));
    const auto& digests = ear["ear_nvidia_inputs"]["digests"];
    ASSERT_EQ(digests.size(), 1U);
    EXPECT_EQ(digests[0]["alg"].get<std::string>(), "sha-256");
    // {0xde,0xad,0xbe,0xef} base64url-encodes to "3q2-7w"
    EXPECT_EQ(digests[0]["val"].get<std::string>(), "3q2-7w");
}

TEST(EarMapperTest, InputDigestAbsentWhenResultHasNone) {
    // No input_digests on result → ear_nvidia_inputs absent.
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);
    EXPECT_FALSE(ear.contains("ear_nvidia_inputs"));
}

TEST(EarMapperTest, MultipleAlgorithmsAllEmitted) {
    auto result = make_passing_result("gpu_0");
    InputDigest d256; d256.alg = HashAlgorithm::Sha256; d256.val = {0x01};
    InputDigest d384; d384.alg = HashAlgorithm::Sha384; d384.val = {0x02};
    result.input_digests.push_back(std::move(d256));
    result.input_digests.push_back(std::move(d384));

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    const auto& digests = ear["ear_nvidia_inputs"]["digests"];
    ASSERT_EQ(digests.size(), 2U);
    EXPECT_EQ(digests[0]["alg"].get<std::string>(), "sha-256");
    EXPECT_EQ(digests[1]["alg"].get<std::string>(), "sha-384");
}

// ── jti ──────────────────────────────────────────────────────────────────────

TEST(EarMapperTest, JtiPresentAndNonEmpty) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    ASSERT_TRUE(ear.contains("jti"));
    EXPECT_FALSE(ear["jti"].get<std::string>().empty());
}

TEST(EarMapperTest, JtiIsUniqueAcrossCalls) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear1{};
    ASSERT_EQ(map_to_ear_json(result, ear1), Error::Ok);
    nlohmann::json ear2{};
    ASSERT_EQ(map_to_ear_json(result, ear2), Error::Ok);

    EXPECT_NE(ear1["jti"].get<std::string>(), ear2["jti"].get<std::string>());
}

// ── eat_nonce ────────────────────────────────────────────────────────────────

TEST(EarMapperTest, TopLevelNoncePresentWhenResultHasNonce) {
    auto result = make_passing_result("gpu_0");
    result.input_nonce = {0xde, 0xad, 0xbe, 0xef};

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    ASSERT_TRUE(ear.contains("eat_nonce"));
    EXPECT_EQ(ear["eat_nonce"].get<std::string>(), "3q2-7w");
}

// The CMW parser hands back decoded bytes, so the emitted claim is the
// canonical base64url of the nonce the relying party sent.
TEST(EarMapperTest, TopLevelNonceRoundTripsCanonicalBase64Url) {
    const std::string sent = "kx2N0K3SA6w9i0-9514RZ0ExiuTRVfEBEP9GRcYUExw";
    std::vector<uint8_t> decoded;
    ASSERT_EQ(decode_base64url(sent, decoded), Error::Ok);

    auto result = make_passing_result("gpu_0");
    result.input_nonce = decoded;

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);
    EXPECT_EQ(ear["eat_nonce"].get<std::string>(), sent);
}

TEST(EarMapperTest, TopLevelNonceAbsentWhenResultLacksNonce) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_FALSE(ear.contains("eat_nonce"));
}

// ── submods ──────────────────────────────────────────────────────────────────

TEST(EarMapperTest, SubmodLabelMatchesItemLabel) {
    auto result = make_passing_result("gpu_42");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    ASSERT_TRUE(ear["submods"].contains("gpu_42"));
}

TEST(EarMapperTest, SubmodEatProfilePresent) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_TRUE(ear["submods"]["gpu_0"].contains("eat_profile"));
}

TEST(EarMapperTest, SubmodEvidenceProfileComesFromEvidence) {
    auto result = make_passing_result("gpu_0");
    result.items[0].evidence_profile = std::make_unique<ProfileValue>(
        ProfileValue{ProfileKind::Uri,
                     "tag:nvidia.com,2026-07:evidence/profiles/spdm/gpu/gr100/gsp/base/1.0.0"});

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_EQ(ear["submods"]["gpu_0"]["evidence_profile"],
              "tag:nvidia.com,2026-07:evidence/profiles/spdm/gpu/gr100/gsp/base/1.0.0");
}

// ── ear_status ───────────────────────────────────────────────────────────────

TEST(EarMapperTest, PassingItemProducesAffirming) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_EQ(ear["ear_status"].get<std::string>(), "affirming");
    EXPECT_EQ(ear["submods"]["gpu_0"]["ear_status"].get<std::string>(), "affirming");
}

TEST(EarMapperTest, StageErrorProducesContraindicated) {
    auto result = make_failing_result("gpu_0", "failed to anchor cert chain");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_EQ(ear["ear_status"].get<std::string>(), "contraindicated");
    EXPECT_EQ(ear["submods"]["gpu_0"]["ear_status"].get<std::string>(), "contraindicated");
}

// Nothing reachable from the attested root means nothing was corroborated, so
// the item must not affirm even though no outcome failed.
// An empty result corroborated nothing and must not affirm.
TEST(EarMapperTest, EmptyResultProducesContraindicated) {
    CorimAttestationResult result{};
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);
    EXPECT_EQ(ear["ear_status"].get<std::string>(), "contraindicated");
    EXPECT_TRUE(ear["submods"].empty());
}

TEST(EarMapperTest, NoReachableOutcomeProducesContraindicated) {
    CorimAttestationResult result{};
    EvidenceItemAppraisal item{};
    item.label = "gpu_0";
    item.evidence.signature_verified = true;
    item.evidence.parsed = true;
    result.items.push_back(std::move(item));

    EnvOutcome outcome{};
    outcome.reachable_from_root = false;
    EctAttempt attempt{};
    attempt.matched_evidence_ects.push_back(Ect{EnvironmentMap{}, {}});
    outcome.attempts.push_back(std::move(attempt));
    result.items[0].match.outcomes.push_back(std::move(outcome));

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);
    EXPECT_EQ(ear["submods"]["gpu_0"]["ear_status"].get<std::string>(),
              "contraindicated");
}

// verify() aborts with diagnostics and no outcomes, so the status has to come
// from the diagnostics alone.
TEST(EarMapperTest, DiagnosticProducesContraindicated) {
    CorimAttestationResult result = make_passing_result("gpu_0");
    result.items[0].match.diagnostics.push_back(Diagnostic::noRootEnvironment());

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);
    EXPECT_EQ(ear["submods"]["gpu_0"]["ear_status"].get<std::string>(),
              "contraindicated");
}

// A reachable outcome that did not pass is a failed corroboration; it also has
// to land in mismatched_env rather than matched_env.
TEST(EarMapperTest, MismatchedOutcomeProducesContraindicated) {
    CorimAttestationResult result = make_passing_result("gpu_0");
    EnvOutcome outcome{};
    outcome.reachable_from_root = true;
    outcome.reason = MismatchReason::noEvidence();
    result.items[0].match.outcomes.push_back(std::move(outcome));

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    const nlohmann::json& submod = ear["submods"]["gpu_0"];
    EXPECT_EQ(submod["ear_status"].get<std::string>(), "contraindicated");
    const nlohmann::json& cmp =
        submod["ear_verifier_claims"]["ear_nvidia_evidence_rim_cmp"];
    EXPECT_EQ(cmp["mismatched_env"].size(), 1u);
    EXPECT_EQ(cmp["matched_env"].size(), 1u);
}

TEST(EarMapperTest, PurposeEmittedWhenAppraisalCarriesOne) {
    CorimAttestationResult result = make_passing_result("gpu_0");
    result.items[0].match.purpose.reset(new std::string("attestation"));

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);
    EXPECT_EQ(ear["submods"]["gpu_0"]["ear_nvidia_purpose"].get<std::string>(),
              "attestation");
}

TEST(EarMapperTest, PurposeAbsentWhenAppraisalHasNone) {
    CorimAttestationResult result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);
    EXPECT_FALSE(ear["submods"]["gpu_0"].contains("ear_nvidia_purpose"));
}

// Both maps feed ear_attester_claims; uncorroborated claims are reported the
// same way, they just were not backed by a reference value.
TEST(EarMapperTest, UncorroboratedClaimsReachAttesterClaims) {
    CorimAttestationResult result = make_passing_result("gpu_0");
    result.items[0].match.corroborated_evidence_claims["dbgstat"] = "disabled";
    result.items[0].match.uncorroborated_evidence_claims["vbios"] = "96.00.9f";

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    const nlohmann::json& attester =
        ear["submods"]["gpu_0"]["ear_attester_claims"];
    EXPECT_EQ(attester["dbgstat"].get<std::string>(), "disabled");
    EXPECT_EQ(attester["vbios"].get<std::string>(), "96.00.9f");
}

TEST(EarMapperTest, FailedSignatureProducesContraindicated) {
    CorimAttestationResult result{};
    EvidenceItemAppraisal item{};
    item.label = "gpu_0";
    // parsed=true so only the signature check can drive the status.
    item.evidence.parsed = true;
    item.evidence.signature_verified = false;
    result.items.push_back(std::move(item));

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_EQ(ear["submods"]["gpu_0"]["ear_status"].get<std::string>(), "contraindicated");
}

TEST(EarMapperTest, TopLevelStatusIsWorstAcrossSubmods) {
    // Two items: one affirming, one contraindicated
    CorimAttestationResult result = make_passing_result("gpu_0");

    EvidenceItemAppraisal bad{};
    bad.label = "gpu_1";
    bad.stage_error = {Error::InternalError, "anchoring failed", ""};
    result.items.push_back(std::move(bad));

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_EQ(ear["ear_status"].get<std::string>(), "contraindicated");
    EXPECT_EQ(ear["submods"]["gpu_0"]["ear_status"].get<std::string>(), "affirming");
    EXPECT_EQ(ear["submods"]["gpu_1"]["ear_status"].get<std::string>(), "contraindicated");
}

// ── eat_nonce in submod ──────────────────────────────────────────────────────

TEST(EarMapperTest, SubmodNoncePresentWhenItemHasNonce) {
    CorimAttestationResult result{};
    EvidenceItemAppraisal item{};
    item.label = "gpu_0";
    item.evidence.signature_verified = true;
    item.eat_nonce = {0xde, 0xad, 0xbe, 0xef};
    result.items.push_back(std::move(item));

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_TRUE(ear["submods"]["gpu_0"].contains("eat_nonce"));
    EXPECT_EQ(ear["submods"]["gpu_0"]["eat_nonce"].get<std::string>(), "3q2-7w");
}

TEST(EarMapperTest, SubmodNonceAbsentWhenItemNonceEmpty) {
    auto result = make_passing_result("gpu_0");
    // eat_nonce left empty (default)
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_FALSE(ear["submods"]["gpu_0"].contains("eat_nonce"));
}

// ── ear_nvidia_rims ──────────────────────────────────────────────────────────

TEST(EarMapperTest, RimsEmittedWhenPresent) {
    CorimAttestationResult result{};
    EvidenceItemAppraisal item{};
    item.label = "gpu_0";
    item.evidence.signature_verified = true;
    CorimResult corim{};
    corim.locator = "https://rim.example.com/v1/rim/DRIVER_RIM";
    corim.fetched = true;
    corim.signature_verified = true;
    corim.id = "ID-Driver";
    item.corims.push_back(std::move(corim));
    result.items.push_back(std::move(item));

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    const auto& rims =
        ear["submods"]["gpu_0"]["ear_verifier_claims"]["ear_nvidia_rims"];
    ASSERT_EQ(rims.size(), 1u);
    EXPECT_EQ(rims[0]["locator"].get<std::string>(),
              "https://rim.example.com/v1/rim/DRIVER_RIM");
    EXPECT_TRUE(rims[0]["fetched"].get<bool>());
    EXPECT_EQ(rims[0]["id"].get<std::string>(), "ID-Driver");
}

TEST(EarMapperTest, RimsAbsentWhenEmpty) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    EXPECT_FALSE(
        ear["submods"]["gpu_0"]["ear_verifier_claims"].contains("ear_nvidia_rims"));
}

// ── ear_attester_claims ──────────────────────────────────────────────────────

TEST(EarMapperTest, AttesterClaimsEmittedFromCorroboratedMap) {
    CorimAttestationResult result{};
    EvidenceItemAppraisal item{};
    item.label = "gpu_0";
    item.evidence.signature_verified = true;
    item.match.corroborated_evidence_claims["oemid"] = "5703";
    result.items.push_back(std::move(item));

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    ASSERT_TRUE(ear["submods"]["gpu_0"].contains("ear_attester_claims"));
    EXPECT_EQ(
        ear["submods"]["gpu_0"]["ear_attester_claims"]["oemid"].get<std::string>(),
        "5703");
}

// hwmodel falls back to the certificate's DMTF product when the evidence
// carries no hwmodel claim of its own.
TEST(EarMapperTest, HwmodelFallsBackToCertificateProduct) {
    auto result = make_passing_result("gpu_0");
    result.items[0].hwmodel = "GB100";

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);
    EXPECT_EQ(
        ear["submods"]["gpu_0"]["ear_attester_claims"]["hwmodel"].get<std::string>(),
        "GB100");
}

// An attester-asserted hwmodel wins over the certificate-derived one.
TEST(EarMapperTest, EvidenceHwmodelWinsOverCertificate) {
    auto result = make_passing_result("gpu_0");
    result.items[0].hwmodel = "GB100";
    result.items[0].match.corroborated_evidence_claims["hwmodel"] = "from-evidence";

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);
    EXPECT_EQ(
        ear["submods"]["gpu_0"]["ear_attester_claims"]["hwmodel"].get<std::string>(),
        "from-evidence");
}

// ── cert_chain_dti_match ─────────────────────────────────────────────────────
// The mapper only serialises the verifier's answer; the matching rule itself
// is covered in test_corim_verify.cpp.

TEST(EarMapperTest, DtiMatchAbsentWhenVerifierLeftItUnset) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    const auto& verifier = ear["submods"]["gpu_0"]["ear_verifier_claims"];
    if (verifier.contains("ear_nvidia_evidence_rim_cmp")) {
        EXPECT_FALSE(
            verifier["ear_nvidia_evidence_rim_cmp"].contains("cert_chain_dti_match"));
    }
}

TEST(EarMapperTest, DtiMatchSerialisedWhenSet) {
    for (bool value : {true, false}) {
        auto result = make_passing_result("gpu_0");
        result.items[0].cert_chain_dti_match.reset(new bool(value));
        // rim_cmp is only emitted when there is something to compare.
        result.items[0].match.unmatched_environments.push_back(EnvironmentMap{});

        nlohmann::json ear{};
        ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

        const auto& cmp =
            ear["submods"]["gpu_0"]["ear_verifier_claims"]["ear_nvidia_evidence_rim_cmp"];
        ASSERT_TRUE(cmp.contains("cert_chain_dti_match"));
        EXPECT_EQ(cmp["cert_chain_dti_match"].get<bool>(), value);
    }
}

// Stable per-device identifiers are collected on the appraisal but must not
// reach the EAR until the authorization model for releasing them is settled.
TEST(EarMapperTest, PerDeviceIdentifiersNeverReachTheEar) {
    auto result = make_passing_result("gpu_0");
    result.items[0].evidence.device_cert_serial = "1215674193163864588919";
    result.items[0].evidence.spdm_end_entity_othername_serial = "48B02DD4C0CB1539";
    result.items[0].evidence.akpub = "-----BEGIN PUBLIC KEY-----\nAAAA\n";
    result.items[0].match.corroborated_evidence_claims["oemid"] = "5703";

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    const std::string serialized = ear.dump();
    EXPECT_EQ(serialized.find("device_cert_serial"), std::string::npos);
    EXPECT_EQ(serialized.find("othername_serial"), std::string::npos);
    EXPECT_EQ(serialized.find("1215674193163864588919"), std::string::npos);
    EXPECT_EQ(serialized.find("48B02DD4C0CB1539"), std::string::npos);

    // Claims that are supposed to be emitted still are.
    EXPECT_NE(serialized.find("akpub"), std::string::npos);
    EXPECT_EQ(
        ear["submods"]["gpu_0"]["ear_attester_claims"]["oemid"].get<std::string>(),
        "5703");
}

// ── Signing ──────────────────────────────────────────────────────────────

TEST(EarMapperTest, SignEarUnsignedWhenNoPrivateKey) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    DetachedEATOptions options;  // m_private_key_pem left empty
    std::string jwt_str;
    ASSERT_EQ(sign_ear(ear, options, jwt_str), Error::Ok);

    auto decoded = jwt::decode<jwt::traits::nlohmann_json>(jwt_str);
    EXPECT_EQ(decoded.get_algorithm(), "none");
}

TEST(EarMapperTest, SignEarEs384WithPrivateKey) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    std::string private_key_pem;
    std::string public_key_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/ec_p384_private.pem", private_key_pem), Error::Ok)
        << "Run unit-tests/testdata/x509_cert_chain/generate_test_certs.sh";
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/ec_p384_public.pem", public_key_pem), Error::Ok);

    DetachedEATOptions options;
    options.m_private_key_pem = private_key_pem;
    options.m_kid = "test-kid";
    std::string jwt_str;
    ASSERT_EQ(sign_ear(ear, options, jwt_str), Error::Ok);

    auto decoded = jwt::decode<jwt::traits::nlohmann_json>(jwt_str);
    EXPECT_EQ(decoded.get_algorithm(), "ES384");
    ASSERT_TRUE(decoded.has_header_claim("kid"));
    EXPECT_EQ(decoded.get_header_claim("kid").as_string(), "test-kid");

    auto verifier = jwt::verify<jwt::traits::nlohmann_json>()
        .allow_algorithm(jwt::algorithm::es384(public_key_pem));
    ASSERT_NO_THROW(verifier.verify(decoded));

    nlohmann::json payload = nlohmann::json::parse(decoded.get_payload());
    EXPECT_EQ(payload["eat_profile"], ear["eat_profile"]);
    EXPECT_EQ(payload["ear_status"], ear["ear_status"]);
}

TEST(EarMapperTest, SignEarReturnsEarSigningFailedForMalformedKey) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    DetachedEATOptions options;
    options.m_private_key_pem = "not a real PEM key";
    std::string jwt_str;
    EXPECT_EQ(sign_ear(ear, options, jwt_str), Error::EarSigningFailed);
}

TEST(EarMapperTest, SignEarOmitsKidHeaderWhenEmpty) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    DetachedEATOptions options;  // m_kid left empty
    std::string private_key_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/ec_p384_private.pem", private_key_pem),
              Error::Ok);
    options.m_private_key_pem = private_key_pem;
    std::string jwt_str;
    ASSERT_EQ(sign_ear(ear, options, jwt_str), Error::Ok);

    auto decoded = jwt::decode<jwt::traits::nlohmann_json>(jwt_str);
    EXPECT_EQ(decoded.get_algorithm(), "ES384");
    EXPECT_FALSE(decoded.has_header_claim("kid"));
}

// ── ear_nvidia_error_details ─────────────────────────────────────────────────

TEST(EarMapperTest, StageErrorReachesErrorDetails) {
    auto result = make_failing_result("gpu_0", "cert chain does not anchor to a known root");
    result.items[0].stage_error.code = Error::CertChainVerificationFailure;

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    const auto& errors = ear["submods"]["gpu_0"]["ear_nvidia_error_details"];
    ASSERT_EQ(errors.size(), 1U);
    EXPECT_EQ(errors[0]["code"].get<int>(),
              static_cast<int>(Error::CertChainVerificationFailure));
    EXPECT_EQ(errors[0]["message"].get<std::string>(),
              "cert chain does not anchor to a known root");
    EXPECT_FALSE(errors[0].contains("details"));
}

TEST(EarMapperTest, MultipleRootDiagnosticListsEveryRelatedEnv) {
    auto result = make_passing_result("gpu_0");
    const EnvironmentMap first{};
    const EnvironmentMap second(
        std::make_unique<ClassMap>(
            nullptr, nullptr, std::make_unique<std::string>("RootB"),
            nullptr, nullptr),
        nullptr, nullptr);
    result.items[0].match.diagnostics.push_back(
        Diagnostic::multipleRootEnvironments({first, second}));

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    const auto& errors = ear["submods"]["gpu_0"]["ear_nvidia_error_details"];
    ASSERT_EQ(errors.size(), 1U);
    EXPECT_EQ(errors[0]["code"].get<int>(),
              diagnostic_public_code(Diagnostic::Code::kMultipleRootEnvironments));
    EXPECT_EQ(errors[0]["related_envs"],
              nlohmann::json::array({first, second}));
}

TEST(EarMapperTest, EachFailingRimReportsItsOwnReason) {
    auto result = make_failing_result("gpu_0", "one or more RIMs failed to fetch or parse");
    result.items[0].stage_error.code = Error::RimConnectionError;

    CorimResult fetch_failed;
    fetch_failed.locator = "https://rim.example/one";
    fetch_failed.error = {Error::RimConnectionError, "RIM fetch failed", ""};

    CorimResult parse_failed;
    parse_failed.locator = "https://rim.example/two";
    parse_failed.fetched = true;
    parse_failed.error = {Error::RimInvalidSchema, "CoRIM parse failed", ""};

    CorimResult ok;
    ok.locator = "https://rim.example/three";
    ok.fetched = true;
    ok.parsed = true;

    result.items[0].corims.push_back(std::move(fetch_failed));
    result.items[0].corims.push_back(std::move(parse_failed));
    result.items[0].corims.push_back(std::move(ok));

    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);

    // Only the two failing locators; the stage error is dropped as redundant.
    const auto& errors = ear["submods"]["gpu_0"]["ear_nvidia_error_details"];
    ASSERT_EQ(errors.size(), 2U);
    EXPECT_EQ(errors[0]["code"].get<int>(), static_cast<int>(Error::RimConnectionError));
    EXPECT_EQ(errors[0]["message"].get<std::string>(),
              "RIM fetch failed: https://rim.example/one");
    EXPECT_EQ(errors[1]["code"].get<int>(), static_cast<int>(Error::RimInvalidSchema));
    EXPECT_EQ(errors[1]["message"].get<std::string>(),
              "CoRIM parse failed: https://rim.example/two");
}

TEST(EarMapperTest, ErrorDetailsAbsentWhenNothingFailed) {
    auto result = make_passing_result("gpu_0");
    nlohmann::json ear{};
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);
    EXPECT_FALSE(ear["submods"]["gpu_0"].contains("ear_nvidia_error_details"));
}

} // namespace

} // namespace nvattestation
