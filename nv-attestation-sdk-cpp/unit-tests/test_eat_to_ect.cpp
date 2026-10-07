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
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "nv_attestation/corim.h"                      // EnvironmentMap, InstanceId, ByteString, MeasurementMap
#include "nv_attestation/corim_evidence/coev.h"        // ConciseEvidence, EvTriples, EvidenceTripleRecord, CorimLocatorMap
#include "nv_attestation/corim_evidence/eat.h"         // Eat, MeasurementsFormat
#include "nv_attestation/corim_evidence/eat_to_ect.h"  // eat_to_ects

namespace nvattestation {
namespace {

// Build a MeasurementsFormat wrapping a ConciseEvidence with `triple_count`
// evidence triples, each carrying one default measurement. The caller's
// environment goes on the first triple; any others are bare.
MeasurementsFormat make_measurement(EnvironmentMap env, size_t triple_count) {
    std::vector<EvidenceTripleRecord> records;
    records.reserve(triple_count);
    for (size_t i = 0; i < triple_count; ++i) {
        std::vector<MeasurementMap> m;
        m.emplace_back();
        records.emplace_back(i == 0 ? std::move(env) : EnvironmentMap{}, std::move(m));
    }
    MeasurementsFormat mf;
    mf.content_format_id = kConciseEvidenceContentFormatId;
    mf.evidence = ConciseEvidence(EvTriples(std::move(records)));
    return mf;
}

Eat make_eat(std::vector<MeasurementsFormat> measurements) {
    Eat eat;
    eat.setMeasurements(std::move(measurements));
    return eat;
}

// Loads a compiled .cbor EAT claims-set fixture (same fixtures as test_eat.cpp).
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

}  // namespace

TEST(EatToEct, SingleMeasurementSingleTripleBecomesOneEct) {
    std::vector<MeasurementsFormat> ms;
    ms.push_back(make_measurement(EnvironmentMap{}, 1));
    Eat eat = make_eat(std::move(ms));

    std::vector<Ect> ects;
    std::vector<CorimLocatorMap> locators;
    ASSERT_EQ(eat_to_ects(eat, ects, locators), Error::Ok);
    ASSERT_EQ(ects.size(), 1u);
    EXPECT_EQ(ects[0].getClaims().size(), 1u);
}

TEST(EatToEct, MultipleMeasurementsConcatenateInOrder) {
    // One triple each so the environment-to-Ect mapping is 1:1 and order is provable.
    EnvironmentMap env_a(
        nullptr,
        std::unique_ptr<InstanceId>(new InstanceId(
            InstanceId::Kind::kBytes, ByteString(std::vector<uint8_t>{0xAA}))),
        nullptr);
    EnvironmentMap env_b(
        nullptr,
        std::unique_ptr<InstanceId>(new InstanceId(
            InstanceId::Kind::kBytes, ByteString(std::vector<uint8_t>{0xBB}))),
        nullptr);

    std::vector<MeasurementsFormat> ms;
    ms.push_back(make_measurement(std::move(env_a), 1));
    ms.push_back(make_measurement(std::move(env_b), 1));
    Eat eat = make_eat(std::move(ms));

    std::vector<Ect> ects;
    std::vector<CorimLocatorMap> locators;
    ASSERT_EQ(eat_to_ects(eat, ects, locators), Error::Ok);
    ASSERT_EQ(ects.size(), 2u);

    // Verify each Ect carries the instance-id from its source measurement.
    const InstanceId* inst0 = ects[0].getEnvironment().getInstance();
    ASSERT_NE(inst0, nullptr);
    EXPECT_EQ(inst0->getKind(), InstanceId::Kind::kBytes);
    ASSERT_EQ(inst0->getValue().size(), 1u);
    EXPECT_EQ(inst0->getValue().data()[0], 0xAAu);

    const InstanceId* inst1 = ects[1].getEnvironment().getInstance();
    ASSERT_NE(inst1, nullptr);
    EXPECT_EQ(inst1->getKind(), InstanceId::Kind::kBytes);
    ASSERT_EQ(inst1->getValue().size(), 1u);
    EXPECT_EQ(inst1->getValue().data()[0], 0xBBu);
}

TEST(EatToEct, EmptyEvidenceMeasurementPropagatesError) {
    // A MeasurementsFormat with default-constructed evidence has zero
    // evidence-triples, which concise_evidence_to_ects rejects as EvidenceMalformed.
    // The good measurement is processed first and its Ect is already appended
    // before the error is returned (eat_to_ects does not clear ects_out on
    // error).
    MeasurementsFormat empty_mf;
    empty_mf.content_format_id = kConciseEvidenceContentFormatId;
    // evidence is default-constructed: no triples.

    std::vector<MeasurementsFormat> ms;
    ms.push_back(make_measurement(EnvironmentMap{}, 1));  // good measurement
    ms.push_back(std::move(empty_mf));                    // bad measurement

    Eat eat = make_eat(std::move(ms));

    std::vector<Ect> ects;
    std::vector<CorimLocatorMap> locators;
    ASSERT_EQ(eat_to_ects(eat, ects, locators), Error::EvidenceMalformed);
    // The good measurement was appended before the error; verify the contract.
    EXPECT_GE(ects.size(), 1u);
}

TEST(EatToEct, RimLocatorsPassThrough) {
    std::vector<MeasurementsFormat> ms;
    ms.push_back(make_measurement(EnvironmentMap{}, 1));
    Eat eat = make_eat(std::move(ms));
    std::vector<CorimLocatorMap> rl;
    rl.emplace_back(std::vector<std::string>{"https://rim.example/a"});
    rl.emplace_back(std::vector<std::string>{"https://rim.example/b", "https://rim.example/c"});
    eat.setRimLocators(std::move(rl));

    std::vector<Ect> ects;
    std::vector<CorimLocatorMap> locators;
    ASSERT_EQ(eat_to_ects(eat, ects, locators), Error::Ok);
    ASSERT_EQ(locators.size(), 2u);
    EXPECT_EQ(locators[0].getUris().size(), 1u);
    EXPECT_EQ(locators[1].getUris().size(), 2u);
}

// End-to-end: parse a real OCP-EAT claims-set CBOR fixture and convert it,
// exercising the parse -> eat_to_ects seam that the synthetic tests skip.
TEST(EatToEct, RealOcpEatFixtureRoundTrips) {
    auto bytes = load_eat_fixture("full_all_optionals");
    ASSERT_FALSE(bytes.empty());
    Eat eat;
    ASSERT_EQ(parse_eat_claims(bytes, eat), Error::Ok);

    std::vector<Ect> ects;
    std::vector<CorimLocatorMap> locators;
    ASSERT_EQ(eat_to_ects(eat, ects, locators), Error::Ok);

    // Measurements produced at least one evidence Ect.
    EXPECT_FALSE(ects.empty());
    // Rim-locators are passed through verbatim.
    EXPECT_EQ(locators.size(), eat.getRimLocators().size());
}

}  // namespace nvattestation
