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

#include "gtest/gtest.h"

#include <string>
#include <vector>

#include "nv_attestation/gpu/blackwell_fsp.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/utils.h"

using namespace nvattestation;

namespace {

const std::string kTestX509CertChainDir = "testdata/x509_cert_chain/";
const std::string kTestRootCertPath = kTestX509CertChainDir + "root_cert";

Error load_test_chain(const std::string &leaf_relative_path, X509CertChain &out_chain) {
    std::string root_pem;
    Error err = readFileIntoString(kTestRootCertPath, root_pem);
    if (err != Error::Ok) {
        return err;
    }
    std::string leaf_pem;
    err = readFileIntoString(kTestX509CertChainDir + leaf_relative_path, leaf_pem);
    if (err != Error::Ok) {
        return err;
    }

    X509CertChain chain;
    err = X509CertChain::create(CertificateChainType::GENERIC, root_pem, chain);
    if (err != Error::Ok) {
        return err;
    }
    err = chain.push_back(leaf_pem);
    if (err != Error::Ok) {
        return err;
    }
    out_chain = std::move(chain);
    return Error::Ok;
}

// Builds a synthetic device identifier measurement carrying the "APSKU"
// tag immediately followed by its 2-byte little-endian keyword.
std::vector<uint8_t> device_id_measurement_with_apsku(uint8_t low, uint8_t high) {
    return {0x00, 0x01, 'A', 'P', 'S', 'K', 'U', low, high, 0xFF};
}

}  // namespace

TEST(BlackwellFspTest, ValidFirmwareVersionAccepted) {
    EXPECT_EQ(validate_firmware_version_hint("96.00.81.00.0F"), Error::Ok);
}

TEST(BlackwellFspTest, MalformedFirmwareVersionRejected) {
    EXPECT_EQ(validate_firmware_version_hint(""), Error::EvidenceMalformed);
    EXPECT_EQ(validate_firmware_version_hint("96.00.81.00"), Error::EvidenceMalformed);
    EXPECT_EQ(validate_firmware_version_hint("96.00.81.00.0F; DROP TABLE"),
              Error::EvidenceMalformed);
    EXPECT_EQ(validate_firmware_version_hint("not-a-version"),
              Error::EvidenceMalformed);
}

TEST(BlackwellFspTest, BuildsLocatorFromValidInputs) {
    std::string locator;
    std::string reason;
    Error err = build_vbios_rim_locator(
        "GB100", device_id_measurement_with_apsku(0x93, 0x07), "96.00.81.00.0F",
        locator, reason);

    EXPECT_EQ(err, Error::Ok);
    EXPECT_EQ(locator,
              "https://rim.attestation.nvidia.com/v1/rim/NV_GPU_VBIOS_GB100_0793_960081000F");
}

// Ground-truth check against the real GB100 FSP capture in
// test_evidence_handler.cpp (ExposesRealBlackwellFspDeviceIdentifierMeasurement),
// which carries "...4150534B555C06..." -> APSKU + {0x5C, 0x06} -> 0x065C.
TEST(BlackwellFspTest, ExtractsApskuFromRealCapturedMeasurement) {
    std::vector<uint8_t> measurement = hex_string_to_bytes(
        "0043000000070100040047160000020010007865bed953204b6ab94d"
        "8fa70b6283d6ffff0b0001054150534b555c06000000000200de1000"
        "010200412901010200de10020102004620");

    std::string locator;
    std::string reason;
    Error err = build_vbios_rim_locator("GB100", measurement, "96.00.81.00.0F",
                                        locator, reason);

    EXPECT_EQ(err, Error::Ok);
    EXPECT_EQ(locator,
              "https://rim.attestation.nvidia.com/v1/rim/NV_GPU_VBIOS_GB100_065C_960081000F");
}

TEST(BlackwellFspTest, LocatorBuildRejectsMalformedFwVersion) {
    std::string locator;
    std::string reason;
    Error err = build_vbios_rim_locator(
        "GB100", device_id_measurement_with_apsku(0x93, 0x07), "garbage",
        locator, reason);

    EXPECT_EQ(err, Error::EvidenceMalformed);
    EXPECT_TRUE(locator.empty());
    EXPECT_FALSE(reason.empty());
}

TEST(BlackwellFspTest, LocatorBuildRejectsEmptyHwModelOrMeasurement) {
    std::string locator;
    std::string reason;
    EXPECT_EQ(build_vbios_rim_locator(
                  "", device_id_measurement_with_apsku(0x93, 0x07),
                  "96.00.81.00.0F", locator, reason),
              Error::EvidenceMalformed);
    EXPECT_FALSE(reason.empty());
    EXPECT_EQ(build_vbios_rim_locator("GB100", {}, "96.00.81.00.0F", locator, reason),
              Error::EvidenceMalformed);
    EXPECT_FALSE(reason.empty());
}

TEST(BlackwellFspTest, LocatorBuildRejectsMeasurementWithoutApskuTag) {
    std::string locator;
    std::string reason;
    EXPECT_EQ(build_vbios_rim_locator("GB100", {0x07, 0x93}, "96.00.81.00.0F",
                                      locator, reason),
              Error::EvidenceMalformed);
    EXPECT_TRUE(locator.empty());
    EXPECT_EQ(reason, "APSKU tag not found in device identifier measurement");
}

TEST(BlackwellFspTest, LocatorBuildRejectsMeasurementTruncatedAfterApskuTag) {
    std::string locator;
    std::vector<uint8_t> truncated = {'A', 'P', 'S', 'K', 'U', 0x07};
    std::string reason;
    EXPECT_EQ(build_vbios_rim_locator("GB100", truncated, "96.00.81.00.0F",
                                      locator, reason),
              Error::EvidenceMalformed);
    EXPECT_TRUE(locator.empty());
    EXPECT_EQ(reason, "device identifier measurement truncated after APSKU tag");
}

TEST(BlackwellFspTest, DetectsFspResponderFromLeafCn) {
    X509CertChain fsp_chain;
    ASSERT_EQ(load_test_chain("leaf_cert_fsp_cn", fsp_chain), Error::Ok);
    EXPECT_TRUE(is_blackwell_fsp_responder(fsp_chain, "GB100"));

    X509CertChain gsp_chain;
    ASSERT_EQ(load_test_chain("leaf_cert_gsp_cn", gsp_chain), Error::Ok);
    EXPECT_FALSE(is_blackwell_fsp_responder(gsp_chain, "GB100"));
}

TEST(BlackwellFspTest, DetectsFspResponderForAnyBlackwellSku) {
    X509CertChain fsp_chain;
    ASSERT_EQ(load_test_chain("leaf_cert_fsp_cn", fsp_chain), Error::Ok);
    EXPECT_TRUE(is_blackwell_fsp_responder(fsp_chain, "GB102"));
    EXPECT_TRUE(is_blackwell_fsp_responder(fsp_chain, "GB202"));
}

TEST(BlackwellFspTest, DoesNotFireForNonBlackwellHwModel) {
    X509CertChain fsp_chain;
    ASSERT_EQ(load_test_chain("leaf_cert_fsp_cn", fsp_chain), Error::Ok);
    EXPECT_FALSE(is_blackwell_fsp_responder(fsp_chain, "GH100"));
    EXPECT_FALSE(is_blackwell_fsp_responder(fsp_chain, ""));
}
