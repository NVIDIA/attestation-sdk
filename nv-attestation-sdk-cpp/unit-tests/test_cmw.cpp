/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
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
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "gtest/gtest.h"

#include "nv_attestation/cmw.h"
#include "nv_attestation/error.h"
#include "nv_attestation/utils.h"

namespace nvattestation {
namespace {

std::vector<uint8_t> bytes(std::initializer_list<uint8_t> vals) {
    return std::vector<uint8_t>(vals);
}

std::vector<uint8_t> filler(std::size_t count, uint8_t seed = 0) {
    std::vector<uint8_t> out(count);
    for (std::size_t i = 0; i < count; ++i) {
        out[i] = static_cast<uint8_t>(i + seed);
    }
    return out;
}

nlohmann::json record(const std::string &media,
                      const std::vector<uint8_t> &value) {
    std::string encoded;
    encode_base64url(value, encoded);
    return nlohmann::json::array({media, encoded});
}

// A structurally valid collection: profile, 32-byte nonce, one SPDM evidence
// item with a PEM cert companion. Individual tests mutate one field to drive
// a specific rejection.
nlohmann::json valid_root() {
    nlohmann::json evidence_item = nlohmann::json::object();
    evidence_item["__cmwc_t"] = kCmwEvidenceItemProfile;
    evidence_item["evidence"] =
        record(kCmwMediaSpdmTranscript, filler(64));
    evidence_item["nonce"] = record(kCmwMediaOctetStream, filler(32, 5));
    evidence_item["certificate"] =
        record(kCmwMediaPemCertChain, filler(48, 7));

    nlohmann::json root = nlohmann::json::object();
    root["__cmwc_t"] = kCmwInputProfile;
    root["nonce"] = record(kCmwMediaOctetStream, filler(32));
    root["gpu_0"] = evidence_item;
    return root;
}

Error parse_root(const nlohmann::json &root, CmwCollection &out) {
    std::string serialized = root.dump();
    return CmwCollection::parse(
        reinterpret_cast<const uint8_t *>(serialized.data()),
        serialized.size(), CmwFormat::kJson, out);
}

TEST(CmwParseTest, ParsesMinimalValid) {
    CmwCollection cmw;
    ASSERT_EQ(parse_root(valid_root(), cmw), Error::Ok);
    EXPECT_EQ(cmw.nonce().size(), 32u);
    ASSERT_EQ(cmw.evidence_items().size(), 1u);
    EXPECT_EQ(cmw.evidence_items()[0].first, "gpu_0");
    EXPECT_EQ(cmw.evidence_items()[0].second.evidence.media_type,
              kCmwMediaSpdmTranscript);
    EXPECT_EQ(cmw.evidence_items()[0].second.nonce.size(), 32u);
    ASSERT_NE(cmw.evidence_items()[0].second.certificate, nullptr);
}

TEST(CmwParseTest, CertificateSlotOptional) {
    nlohmann::json root = valid_root();
    root["gpu_0"].erase("certificate");
    CmwCollection cmw;
    ASSERT_EQ(parse_root(root, cmw), Error::Ok);
    EXPECT_EQ(cmw.evidence_items()[0].second.certificate, nullptr);
}

TEST(CmwParseTest, ParsesHintsRecordWhenPresent) {
    nlohmann::json root = valid_root();
    root["gpu_0"]["hints"] = record(kCmwMediaJson, filler(24, 9));
    CmwCollection cmw;
    ASSERT_EQ(parse_root(root, cmw), Error::Ok);
    ASSERT_EQ(cmw.evidence_items().size(), 1U);
    const CmwEvidenceItem &item = cmw.evidence_items()[0].second;
    ASSERT_NE(item.hints, nullptr);
    EXPECT_EQ(item.hints->media_type, kCmwMediaJson);
    EXPECT_EQ(item.hints->value, filler(24, 9));
}

TEST(CmwParseTest, RejectsMalformedHintsRecord) {
    nlohmann::json root = valid_root();
    root["gpu_0"]["hints"] = nlohmann::json::array({123, 456});
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, RejectsHintsWithWrongMediaType) {
    nlohmann::json root = valid_root();
    root["gpu_0"]["hints"] = record(kCmwMediaOctetStream, filler(24, 9));
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, HintsSlotOptional) {
    CmwCollection cmw;
    ASSERT_EQ(parse_root(valid_root(), cmw), Error::Ok);
    EXPECT_EQ(cmw.evidence_items()[0].second.hints, nullptr);
}

TEST(CmwParseTest, HintsRoundTripsThroughSerialize) {
    nlohmann::json root = valid_root();
    root["gpu_0"]["hints"] = record(kCmwMediaJson, filler(24, 9));
    CmwCollection original;
    ASSERT_EQ(parse_root(root, original), Error::Ok);

    std::vector<uint8_t> serialized;
    ASSERT_EQ(original.serialize(CmwFormat::kJson, serialized), Error::Ok);

    CmwCollection reparsed;
    ASSERT_EQ(CmwCollection::parse(serialized.data(), serialized.size(),
                                   CmwFormat::kJson, reparsed),
              Error::Ok);
    ASSERT_EQ(reparsed.evidence_items().size(), 1U);
    const CmwEvidenceItem &item = reparsed.evidence_items()[0].second;
    ASSERT_NE(item.hints, nullptr);
    EXPECT_EQ(item.hints->media_type, kCmwMediaJson);
    EXPECT_EQ(item.hints->value, filler(24, 9));
}

TEST(CmwParseTest, StoresAppraisalSettings) {
    nlohmann::json root = valid_root();
    root["appraisal-settings"] = record(kCmwMediaJson, bytes({0x7B, 0x7D}));
    CmwCollection cmw;
    ASSERT_EQ(parse_root(root, cmw), Error::Ok);
    EXPECT_EQ(cmw.evidence_items().size(), 1u);
    // Not an evidence item, and the decoded JSON is kept for the verifier.
    EXPECT_EQ(cmw.appraisal_settings(), std::vector<uint8_t>({0x7B, 0x7D}));
}

TEST(CmwParseTest, AppraisalSettingsAbsentLeavesItEmpty) {
    CmwCollection cmw;
    ASSERT_EQ(parse_root(valid_root(), cmw), Error::Ok);
    EXPECT_TRUE(cmw.appraisal_settings().empty());
}

TEST(CmwParseTest, RejectsAppraisalSettingsWithWrongMediaType) {
    nlohmann::json root = valid_root();
    root["appraisal-settings"] =
        record(kCmwMediaOctetStream, bytes({0x7B, 0x7D}));
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, MultipleEvidenceItems) {
    nlohmann::json root = valid_root();
    root["gpu_1"] = root["gpu_0"];
    CmwCollection cmw;
    ASSERT_EQ(parse_root(root, cmw), Error::Ok);
    EXPECT_EQ(cmw.evidence_items().size(), 2u);
}

TEST(CmwParseTest, RejectsNullData) {
    CmwCollection cmw;
    EXPECT_EQ(CmwCollection::parse(nullptr, 10, CmwFormat::kJson, cmw),
              Error::BadArgument);
}

TEST(CmwParseTest, RejectsMalformedJson) {
    CmwCollection cmw;
    std::string junk = "{not json";
    EXPECT_EQ(CmwCollection::parse(
                  reinterpret_cast<const uint8_t *>(junk.data()), junk.size(),
                  CmwFormat::kJson, cmw),
              Error::EvidenceMalformed);
}

TEST(CmwParseTest, RejectsNonObjectRoot) {
    CmwCollection cmw;
    std::string arr = "[]";
    EXPECT_EQ(CmwCollection::parse(
                  reinterpret_cast<const uint8_t *>(arr.data()), arr.size(),
                  CmwFormat::kJson, cmw),
              Error::EvidenceMalformed);
}

TEST(CmwParseTest, RejectsWrongRootProfile) {
    nlohmann::json root = valid_root();
    root["__cmwc_t"] = "tag:nvidia.com,2026:wrong/v1";
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, AcceptsMissingNonce) {
    nlohmann::json root = valid_root();
    root.erase("nonce");
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::Ok);
    EXPECT_TRUE(cmw.nonce().empty());
}

TEST(CmwParseTest, RejectsShortNonce) {
    nlohmann::json root = valid_root();
    root["nonce"] = record(kCmwMediaOctetStream, filler(31));
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, RejectsWrongNonceMediaType) {
    nlohmann::json root = valid_root();
    root["nonce"] = record(kCmwMediaJson, filler(32));
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, RejectsRecordNotTwoElements) {
    nlohmann::json root = valid_root();
    std::string encoded;
    encode_base64url(filler(32), encoded);
    root["nonce"] =
        nlohmann::json::array({kCmwMediaOctetStream, encoded, 0});
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, RejectsRecordNonStringEntries) {
    nlohmann::json root = valid_root();
    root["nonce"] = nlohmann::json::array({123, 456});
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, RejectsEvidenceItemWrongProfile) {
    nlohmann::json root = valid_root();
    root["gpu_0"]["__cmwc_t"] = "tag:nvidia.com,2026:wrong-item/v1";
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, RejectsEvidenceItemMissingEvidence) {
    nlohmann::json root = valid_root();
    root["gpu_0"].erase("evidence");
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, AcceptsEvidenceItemMissingNonce) {
    nlohmann::json root = valid_root();
    root["gpu_0"].erase("nonce");
    CmwCollection cmw;
    ASSERT_EQ(parse_root(root, cmw), Error::Ok);
    ASSERT_EQ(cmw.evidence_items().size(), 1u);
    EXPECT_TRUE(cmw.evidence_items()[0].second.nonce.empty());
}

TEST(CmwParseTest, RejectsShortEvidenceItemNonce) {
    nlohmann::json root = valid_root();
    root["gpu_0"]["nonce"] = record(kCmwMediaOctetStream, filler(31));
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, RejectsEvidenceItemNotObject) {
    nlohmann::json root = valid_root();
    root["gpu_0"] = "not an object";
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, AcceptsUnknownEvidenceMediaType) {
    // The wire layer validates structure only; an unknown evidence media type
    // is a per-item verifier error surfaced at appraisal, not a parse failure.
    nlohmann::json root = valid_root();
    root["gpu_0"]["evidence"] =
        record("application/vnd.nvidia.not-real", filler(16));
    CmwCollection cmw;
    ASSERT_EQ(parse_root(root, cmw), Error::Ok);
    ASSERT_EQ(cmw.evidence_items().size(), 1u);
    EXPECT_EQ(cmw.evidence_items()[0].second.evidence.media_type,
              "application/vnd.nvidia.not-real");
}

TEST(CmwParseTest, RejectsUnsupportedCertificateMediaType) {
    nlohmann::json root = valid_root();
    root["gpu_0"]["certificate"] = record(kCmwMediaJson, filler(16));
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, RejectsNoEvidenceItems) {
    nlohmann::json root = nlohmann::json::object();
    root["__cmwc_t"] = kCmwInputProfile;
    root["nonce"] = record(kCmwMediaOctetStream, filler(32));
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwParseTest, RejectsNoncePayloadWithPadding) {
    nlohmann::json root = valid_root();
    // Hand-craft a padded (thus invalid) base64url value.
    root["nonce"] = nlohmann::json::array({kCmwMediaOctetStream, "QQ=="});
    CmwCollection cmw;
    EXPECT_EQ(parse_root(root, cmw), Error::EvidenceMalformed);
}

TEST(CmwSerializeTest, RoundTrips) {
    nlohmann::json root = valid_root();
    const std::vector<uint8_t> settings = bytes({0x7B, 0x7D}); // {}
    root["appraisal-settings"] = record(kCmwMediaJson, settings);

    CmwCollection original;
    ASSERT_EQ(parse_root(root, original), Error::Ok);

    std::vector<uint8_t> serialized;
    ASSERT_EQ(original.serialize(CmwFormat::kJson, serialized), Error::Ok);

    CmwCollection reparsed;
    ASSERT_EQ(CmwCollection::parse(serialized.data(), serialized.size(),
                                   CmwFormat::kJson, reparsed),
              Error::Ok);
    EXPECT_EQ(reparsed.nonce(), original.nonce());
    EXPECT_EQ(reparsed.appraisal_settings(), settings);
    ASSERT_EQ(reparsed.evidence_items().size(),
              original.evidence_items().size());
    const auto &orig_item = original.evidence_items()[0].second;
    const auto &reparsed_item = reparsed.evidence_items()[0].second;
    EXPECT_EQ(orig_item.evidence.media_type,
              reparsed_item.evidence.media_type);
    EXPECT_EQ(orig_item.evidence.value, reparsed_item.evidence.value);
    ASSERT_NE(reparsed_item.certificate, nullptr);
    EXPECT_EQ(orig_item.certificate->value,
              reparsed_item.certificate->value);
}

TEST(CmwSerializeTest, RoundTripsWithoutNonce) {
    nlohmann::json root = valid_root();
    root.erase("nonce");
    CmwCollection original;
    ASSERT_EQ(parse_root(root, original), Error::Ok);
    EXPECT_TRUE(original.nonce().empty());

    std::vector<uint8_t> serialized;
    ASSERT_EQ(original.serialize(CmwFormat::kJson, serialized), Error::Ok);

    CmwCollection reparsed;
    ASSERT_EQ(CmwCollection::parse(serialized.data(), serialized.size(),
                                   CmwFormat::kJson, reparsed),
              Error::Ok);
    EXPECT_TRUE(reparsed.nonce().empty());
}

TEST(CmwFormatTest, CborParseNotEnabled) {
    std::vector<uint8_t> data = {0x00};
    CmwCollection cmw;
    EXPECT_EQ(CmwCollection::parse(data.data(), data.size(), CmwFormat::kCbor,
                                   cmw),
              Error::FeatureNotEnabled);
}

TEST(CmwFormatTest, CborSerializeNotEnabled) {
    CmwCollection cmw;
    std::vector<uint8_t> out;
    EXPECT_EQ(cmw.serialize(CmwFormat::kCbor, out), Error::FeatureNotEnabled);
}

} // namespace
} // namespace nvattestation
