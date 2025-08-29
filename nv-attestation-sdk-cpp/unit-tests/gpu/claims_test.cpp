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

using namespace nvattestation;

// Test fixture for GPU Claims tests
class GpuClaimsTest : public ::testing::Test {
protected:
    nlohmann::json m_test_json;
    
    void SetUp() override {
        // Load the test JSON data from hopperClaimsv3_decoded.json and extract GPU-0 content
        std::ifstream test_file("testdata/sample_attestation_data/hopperClaimsv3_decoded.json");
        ASSERT_TRUE(test_file.is_open()) << "Failed to open test data file";
        
        nlohmann::json full_json;
        test_file >> full_json;
        test_file.close();
        
        // Extract the GPU-0 content (removing the top-level wrapper)
        ASSERT_TRUE(full_json.contains("GPU-0")) << "Test data must contain GPU-0 key";
        m_test_json = full_json["GPU-0"];
    }
};

// Test deserialization from JSON to SerializableGpuClaimsV3
TEST_F(GpuClaimsTest, DeserializationFromJson) {
    SerializableGpuClaimsV3 claims;
    ASSERT_NO_THROW(from_json(m_test_json, claims));
    
    // Verify top-level claims
    EXPECT_EQ(claims.m_measurements_matching, SerializableMeasresClaim::Success);
    EXPECT_EQ(claims.m_gpu_arch_match, true);
    EXPECT_EQ(claims.m_driver_version, "550.90.07");
    EXPECT_EQ(claims.m_vbios_version, "96.00.9F.00.01");
    
    // Verify attestation report claims
    EXPECT_EQ(claims.m_ar_cert_chain_fwid_match, true);
    EXPECT_EQ(claims.m_ar_parsed, true);
    EXPECT_EQ(claims.m_gpu_ar_nonce_match, true);
    EXPECT_EQ(claims.m_ar_signature_verified, true);
    
    // Verify attestation report certificate chain claims
    EXPECT_EQ(claims.m_ar_cert_chain.m_cert_status, "valid");
    EXPECT_EQ(claims.m_ar_cert_chain.m_cert_ocsp_status, "good");
    EXPECT_EQ(claims.m_ar_cert_chain.m_cert_expiration_date, "9999-12-31T23:59:59Z");
    EXPECT_EQ(claims.m_ar_cert_chain.m_cert_revocation_reason, nullptr);
    
    // Verify driver RIM claims
    EXPECT_EQ(claims.m_driver_rim_fetched, true);
    EXPECT_EQ(claims.m_driver_rim_signature_verified, true);
    EXPECT_EQ(claims.m_gpu_driver_rim_version_match, true);
    EXPECT_EQ(claims.m_driver_rim_measurements_available, true);
    
    // Verify driver RIM certificate chain claims
    EXPECT_EQ(claims.m_driver_rim_cert_chain.m_cert_status, "valid");
    EXPECT_EQ(claims.m_driver_rim_cert_chain.m_cert_ocsp_status, "good");
    EXPECT_EQ(claims.m_driver_rim_cert_chain.m_cert_expiration_date, "2026-06-01T02:08:29Z");
    EXPECT_EQ(claims.m_driver_rim_cert_chain.m_cert_revocation_reason, nullptr);
    
    // Verify VBIOS RIM claims
    EXPECT_EQ(claims.m_vbios_rim_fetched, true);
    EXPECT_EQ(claims.m_gpu_vbios_rim_version_match, true);
    EXPECT_EQ(claims.m_vbios_rim_signature_verified, true);
    EXPECT_EQ(claims.m_vbios_rim_measurements_available, true);
    EXPECT_EQ(claims.m_vbios_index_no_conflict, true);
    
    // Verify VBIOS RIM certificate chain claims
    EXPECT_EQ(claims.m_vbios_rim_cert_chain.m_cert_status, "valid");
    EXPECT_EQ(claims.m_vbios_rim_cert_chain.m_cert_ocsp_status, "good");
    EXPECT_EQ(claims.m_vbios_rim_cert_chain.m_cert_expiration_date, "2026-02-22T23:17:58Z");
    EXPECT_EQ(claims.m_vbios_rim_cert_chain.m_cert_revocation_reason, nullptr);
}

// Test serialization from SerializableGpuClaimsV3 to JSON
TEST_F(GpuClaimsTest, SerializationToJson) {
    // First deserialize from test JSON
    SerializableGpuClaimsV3 claims;
    ASSERT_NO_THROW(from_json(m_test_json, claims));
    
    // Convert back to JSON using to_json
    nlohmann::json serialized_json;
    ASSERT_NO_THROW(to_json(serialized_json, claims));
    
    EXPECT_TRUE(serialized_json.contains("measres"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-arch-check"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-driver-version"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-vbios-version"));
    
    // Verify attestation report related keys
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-attestation-report-cert-chain"));
    EXPECT_EQ(serialized_json["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-revocation-reason"], nullptr);
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-attestation-report-cert-chain-fwid-match"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-attestation-report-parsed"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-attestation-report-nonce-match"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-attestation-report-signature-verified"));
    
    // Verify driver RIM related keys
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-driver-rim-fetched"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-driver-rim-cert-chain"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-driver-rim-signature-verified"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-driver-rim-version-match"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-driver-rim-measurements-available"));
    
    // Verify VBIOS RIM related keys
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-vbios-rim-fetched"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-vbios-rim-cert-chain"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-vbios-rim-version-match"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-vbios-rim-signature-verified"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-vbios-rim-measurements-available"));
    EXPECT_TRUE(serialized_json.contains("x-nvidia-gpu-vbios-index-no-conflict"));
    
    // Verify specific values match the original test data
    EXPECT_EQ(serialized_json["measres"].get<std::string>(), "success");
    EXPECT_EQ(serialized_json["x-nvidia-gpu-arch-check"].get<bool>(), true);
    EXPECT_EQ(serialized_json["x-nvidia-gpu-driver-version"].get<std::string>(), "550.90.07");
    EXPECT_EQ(serialized_json["x-nvidia-gpu-vbios-version"].get<std::string>(), "96.00.9F.00.01");
    EXPECT_EQ(serialized_json["secboot"].get<bool>(), true);
    EXPECT_EQ(serialized_json["dbgstat"].get<std::string>(), "disabled");
    EXPECT_EQ(serialized_json["x-nvidia-mismatch-measurement-records"], nullptr);
}