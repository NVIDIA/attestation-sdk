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

#include "../src/internal/debug.hpp"

using namespace nvattestation;

class DebugHelpersTest : public ::testing::Test {};

TEST_F(DebugHelpersTest, EncodeBase64ForLogKnownInput) {
    // "Hello" -> "SGVsbG8="
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    std::string result = encode_base64_for_log(data);
    EXPECT_EQ(result, "SGVsbG8=");
}

TEST_F(DebugHelpersTest, EncodeBase64ForLogEmptyInput) {
    std::vector<uint8_t> data;
    std::string result = encode_base64_for_log(data);
    EXPECT_EQ(result, "");
}

TEST_F(DebugHelpersTest, EncodeBase64ForLogBinaryData) {
    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0xFF};
    std::string result = encode_base64_for_log(data);
    EXPECT_EQ(result, "AAEC/w==");
}

TEST_F(DebugHelpersTest, FormatCertChainForLogSingleCert) {
    std::string pem =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIB+jCCAaCgAwIBAgIUe3L/\n"
        "aqFsQW5xZGRjb21wYW55\n"
        "-----END CERTIFICATE-----\n";

    std::string result = format_cert_chain_for_log(pem);
    EXPECT_EQ(result, "  cert[0]: MIIB+jCCAaCgAwIBAgIUe3L/aqFsQW5xZGRjb21wYW55");
}

TEST_F(DebugHelpersTest, FormatCertChainForLogMultipleCerts) {
    std::string pem =
        "-----BEGIN CERTIFICATE-----\n"
        "AAAA\n"
        "BBBB\n"
        "-----END CERTIFICATE-----\n"
        "-----BEGIN CERTIFICATE-----\n"
        "CCCC\n"
        "DDDD\n"
        "-----END CERTIFICATE-----\n";

    std::string result = format_cert_chain_for_log(pem);
    std::string expected =
        "  cert[0]: AAAABBBB\n"
        "  cert[1]: CCCCDDDD";
    EXPECT_EQ(result, expected);
}

TEST_F(DebugHelpersTest, FormatCertChainForLogNoCerts) {
    std::string pem = "some random string with no certs";
    std::string result = format_cert_chain_for_log(pem);
    EXPECT_EQ(result, "");
}

TEST_F(DebugHelpersTest, FormatCertChainForLogCarriageReturns) {
    std::string pem =
        "-----BEGIN CERTIFICATE-----\r\n"
        "AAAA\r\n"
        "BBBB\r\n"
        "-----END CERTIFICATE-----\r\n";

    std::string result = format_cert_chain_for_log(pem);
    EXPECT_EQ(result, "  cert[0]: AAAABBBB");
}
