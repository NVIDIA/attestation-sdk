/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <iostream>

#include "gtest/gtest.h"

#include "nv_attestation/gpu/claims.h"
#include <nlohmann/json.hpp>
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/switch/claims.h"
#include <jwt-cpp/jwt.h>
#include "jwt-cpp/traits/nlohmann-json/traits.h"
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace nvattestation;

static bool load_subobject_from_file(const std::string& path, const std::string& top_key, nlohmann::json& out_obj) {
    std::string file_contents;
    Error err = readFileIntoString(path, file_contents);
    if (err != Error::Ok) {
        return false;
    }
    try {
        nlohmann::json root = nlohmann::json::parse(file_contents);
        if (!root.contains(top_key)) {
            return false;
        }
        out_obj = root[top_key];
        return true;
    } catch (...) {
        return false;
    }
}

// End-to-end test for detached EAT generation and verification
TEST(DetachedEatTest, CreateAndVerify) {
    // Arrange: load GPU and SWITCH claim JSON objects
    nlohmann::json gpu_claim_obj;
    ASSERT_TRUE(load_subobject_from_file("testdata/sample_attestation_data/hopperClaimsv3_decoded.json", "GPU-0", gpu_claim_obj))
        << "Failed to load GPU-0 from hopperClaimsv3_decoded.json";

    nlohmann::json switch_claim_obj;
    ASSERT_TRUE(load_subobject_from_file("testdata/sample_attestation_data/switch_decoded.json", "SWITCH-0", switch_claim_obj))
        << "Failed to load SWITCH-0 from switch_decoded.json";

    // Deserialize into SDK claim objects
    SerializableGpuClaimsV3 gpu_claims;
    ASSERT_NO_THROW(from_json(gpu_claim_obj, gpu_claims));

    SerializableSwitchClaimsV3 switch_claims;
    ASSERT_NO_THROW(from_json(switch_claim_obj, switch_claims));

    // Build ClaimsCollection
    ClaimsCollection claims_collection;
    auto gpu_ptr = std::make_shared<SerializableGpuClaimsV3>(gpu_claims);
    auto switch_ptr = std::make_shared<SerializableSwitchClaimsV3>(switch_claims);
    claims_collection.append(gpu_ptr);
    claims_collection.append(switch_ptr);

    // ES384 key material and issuer
    const std::string issuer = "test-issuer";
    std::string private_key_pem;
    std::string public_key_pem;
    Error err = readFileIntoString("testdata/x509_cert_chain/ec_p384_private.pem", private_key_pem);
    if (err != Error::Ok) {
        FAIL() << "Failed to read ES384 private key. Make sure to run 'unit-tests/testdata/x509_cert_chain/generate_test_certs.sh'";
    }
    err = readFileIntoString("testdata/x509_cert_chain/ec_p384_public.pem", public_key_pem);
    if (err != Error::Ok) {
        FAIL() << "Failed to read ES384 public key. Make sure to run 'unit-tests/testdata/x509_cert_chain/generate_test_certs.sh'";
    }

    // Act: generate detached EAT
    std::string detached_eat_json;
    err = claims_collection.get_detached_eat(detached_eat_json, private_key_pem, issuer);
    ASSERT_EQ(err, Error::Ok) << "get_detached_eat failed: " << to_string(err);


    // Parse final detached EAT shape
    nlohmann::json detached = nlohmann::json::parse(detached_eat_json);
    LOG_DEBUG("Detached EAT: " << detached.dump(2));
    ASSERT_TRUE(detached.is_array());
    ASSERT_EQ(detached.size(), 2u);
    ASSERT_TRUE(detached[0].is_array());
    ASSERT_EQ(detached[0].size(), 2u);
    ASSERT_EQ(detached[0][0].get<std::string>(), "JWT");
    ASSERT_TRUE(detached[1].is_object());
    std::string overall_jwt = detached[0][1].get<std::string>();

    // Expect both GPU-0 and SWITCH-0 submodules in the submods object
    nlohmann::json submods = detached[1];
    ASSERT_TRUE(submods.contains("GPU-0"));
    ASSERT_TRUE(submods.contains("SWITCH-0"));
    std::string gpu_jwt = submods["GPU-0"].get<std::string>();
    std::string switch_jwt = submods["SWITCH-0"].get<std::string>();

    // Prepare verifier
    auto verifier = jwt::verify<jwt::traits::nlohmann_json>()
        .allow_algorithm(jwt::algorithm::es384(public_key_pem));

    // Verify submodule JWTs
    auto verify_and_decode = [&](const std::string& jwt_str, nlohmann::json& out_payload) {
        auto decoded = jwt::decode<jwt::traits::nlohmann_json>(jwt_str);
        ASSERT_NO_THROW(verifier.verify(decoded));
        out_payload = nlohmann::json::parse(decoded.get_payload());
    };

    nlohmann::json gpu_payload;
    verify_and_decode(gpu_jwt, gpu_payload);
    nlohmann::json switch_payload;
    verify_and_decode(switch_jwt, switch_payload);

    // Common payload checks
    auto check_payload_claims = [&](const nlohmann::json& payload) {
        ASSERT_TRUE(payload.contains("iss"));
        EXPECT_EQ(payload["iss"].get<std::string>(), issuer);
        ASSERT_TRUE(payload.contains("iat"));
        ASSERT_TRUE(payload.contains("exp"));
        auto iat = payload["iat"].get<std::int64_t>();
        auto exp = payload["exp"].get<std::int64_t>();
        EXPECT_EQ(exp - iat, 3600);
    };

    LOG_DEBUG("Checking GPU payload claims: " << gpu_payload.dump(2));
    check_payload_claims(gpu_payload);

    // make sure that the gpu and switch claims can be deserialized from the payload
    SerializableGpuClaimsV3 gpu_claims_from_payload;
    err = deserialize_from_json<SerializableGpuClaimsV3>(gpu_payload.dump(), gpu_claims_from_payload);
    ASSERT_EQ(err, Error::Ok) << "deserialize_from_json failed: " << to_string(err);
    SerializableSwitchClaimsV3 switch_claims_from_payload;
    err = deserialize_from_json<SerializableSwitchClaimsV3>(switch_payload.dump(), switch_claims_from_payload);
    ASSERT_EQ(err, Error::Ok) << "deserialize_from_json failed: " << to_string(err);

    LOG_DEBUG("Checking SWITCH payload claims: " << switch_payload.dump(2));
    check_payload_claims(switch_payload);

    // Verify overall JWT signature and payload
    nlohmann::json overall_payload;
    verify_and_decode(overall_jwt, overall_payload);
    ASSERT_TRUE(overall_payload.contains("submods"));
    ASSERT_TRUE(overall_payload["submods"].is_object());
    auto submods_digest = overall_payload["submods"];
    ASSERT_TRUE(submods_digest.contains("GPU-0"));
    ASSERT_TRUE(submods_digest.contains("SWITCH-0"));
    check_payload_claims(overall_payload);
}

// Test that get_detached_eat returns OverallResultFalse when any claim's measres != success
TEST(DetachedEatTest, CreateReturnsOverallResultFalse) {
    // Arrange: load GPU and SWITCH claim JSON objects
    nlohmann::json gpu_claim_obj;
    ASSERT_TRUE(load_subobject_from_file("testdata/sample_attestation_data/hopperClaimsv3_decoded.json", "GPU-0", gpu_claim_obj))
        << "Failed to load GPU-0 from hopperClaimsv3_decoded.json";

    nlohmann::json switch_claim_obj;
    ASSERT_TRUE(load_subobject_from_file("testdata/sample_attestation_data/switch_decoded.json", "SWITCH-0", switch_claim_obj))
        << "Failed to load SWITCH-0 from switch_decoded.json";

    // Deserialize into SDK claim objects
    SerializableGpuClaimsV3 gpu_claims;
    ASSERT_NO_THROW(from_json(gpu_claim_obj, gpu_claims));

    SerializableSwitchClaimsV3 switch_claims;
    ASSERT_NO_THROW(from_json(switch_claim_obj, switch_claims));

    // Force one claim's measres to indicate failure
    gpu_claims.m_measurements_matching = SerializableMeasresClaim::Failure;

    // Build ClaimsCollection
    ClaimsCollection claims_collection;
    auto gpu_ptr = std::make_shared<SerializableGpuClaimsV3>(gpu_claims);
    auto switch_ptr = std::make_shared<SerializableSwitchClaimsV3>(switch_claims);
    claims_collection.append(gpu_ptr);
    claims_collection.append(switch_ptr);

    // Act: generate detached EAT without signing
    std::string detached_eat_json;
    Error err = claims_collection.get_detached_eat(detached_eat_json, "", "test-issuer");

    // Assert
    ASSERT_EQ(err, Error::OverallResultFalse) << "Expected OverallResultFalse when any claim has measres != success";
}