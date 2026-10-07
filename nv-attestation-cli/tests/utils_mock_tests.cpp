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

// In-process white-box tests for the utils.cpp helpers that back the v2
// (CMW) CLI paths, driven against the fake nvat C API (fake_nvat.cpp). The v2
// subcommand sources aren't linked into the test binary, so these call the
// helpers directly to exercise every SDK-error branch without hardware.

#include <cstdint>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "fake_nvat_control.h"
#include "nvat.h"
#include "nvattest_options.h"
#include "utils.h"

using namespace nvattest;

TEST(Utils, TrimAsciiWhitespaceRemovesOnlyBoundaryWhitespace) {
    std::string token = " \t\r\neyJhbGciOiJFUzM4NCJ9.payload.signature\n\f ";

    trim_ascii_whitespace(token);

    EXPECT_EQ(token, "eyJhbGciOiJFUzM4NCJ9.payload.signature");
}

class CollectCmwJsonMock : public ::testing::Test {
  protected:
    nvat_gpu_evidence_source_t source = nullptr;
    nvat_nonce_t nonce = nullptr;

    void SetUp() override {
        fake_nvat_reset();
        ASSERT_EQ(nvat_gpu_evidence_source_nvml_create(&source), NVAT_RC_OK);
        ASSERT_EQ(nvat_nonce_from_hex(&nonce, "00"), NVAT_RC_OK);
    }

    void TearDown() override {
        nvat_gpu_evidence_source_free(&source);
        nvat_nonce_free(&nonce);
    }
};

TEST_F(CollectCmwJsonMock, SuccessReturnsSerializedBytes) {
    std::vector<uint8_t> out;
    EXPECT_EQ(collect_cmw_json(source, nonce, out), NVAT_RC_OK);
    EXPECT_EQ(std::string(out.begin(), out.end()), g_fake_nvat.cmw_json);
}

TEST_F(CollectCmwJsonMock, CollectFailurePropagates) {
    g_fake_nvat.collect_rc = NVAT_RC_INTERNAL_ERROR;
    std::vector<uint8_t> out;
    EXPECT_EQ(collect_cmw_json(source, nonce, out), NVAT_RC_INTERNAL_ERROR);
}

TEST_F(CollectCmwJsonMock, CmwCreateFailurePropagates) {
    g_fake_nvat.cmw_create_rc = NVAT_RC_INTERNAL_ERROR;
    std::vector<uint8_t> out;
    EXPECT_EQ(collect_cmw_json(source, nonce, out), NVAT_RC_INTERNAL_ERROR);
}

TEST_F(CollectCmwJsonMock, CmwSerializeFailurePropagates) {
    g_fake_nvat.cmw_serialize_rc = NVAT_RC_INTERNAL_ERROR;
    std::vector<uint8_t> out;
    EXPECT_EQ(collect_cmw_json(source, nonce, out), NVAT_RC_INTERNAL_ERROR);
}

TEST_F(CollectCmwJsonMock, StrGetDataFailurePropagates) {
    g_fake_nvat.str_get_data_rc = NVAT_RC_INTERNAL_ERROR;
    std::vector<uint8_t> out;
    EXPECT_EQ(collect_cmw_json(source, nonce, out), NVAT_RC_INTERNAL_ERROR);
}

TEST_F(CollectCmwJsonMock, StrLengthFailurePropagates) {
    g_fake_nvat.str_length_rc = NVAT_RC_INTERNAL_ERROR;
    std::vector<uint8_t> out;
    EXPECT_EQ(collect_cmw_json(source, nonce, out), NVAT_RC_INTERNAL_ERROR);
}

class MakeHttpOptionsMock : public ::testing::Test {
  protected:
    EvidenceVerificationOptions options;

    void SetUp() override { fake_nvat_reset(); }
};

TEST_F(MakeHttpOptionsMock, NoTlsFieldsYieldsNullHandle) {
    nvat_http_options_t http_options = nullptr;
    EXPECT_EQ(make_http_options(options, http_options), NVAT_RC_OK);
    EXPECT_EQ(http_options, nullptr);
}

TEST_F(MakeHttpOptionsMock, CaCertBuildsHandle) {
    options.tls_ca_cert = "/path/to/ca.pem";
    nvat_http_options_t http_options = nullptr;
    EXPECT_EQ(make_http_options(options, http_options), NVAT_RC_OK);
    ASSERT_NE(http_options, nullptr);
    nvat_http_options_free(&http_options);
}

TEST_F(MakeHttpOptionsMock, CaPathBuildsHandle) {
    options.tls_ca_path = "/path/to/ca-dir";
    nvat_http_options_t http_options = nullptr;
    EXPECT_EQ(make_http_options(options, http_options), NVAT_RC_OK);
    ASSERT_NE(http_options, nullptr);
    nvat_http_options_free(&http_options);
}

TEST_F(MakeHttpOptionsMock, BothCaFieldsBuildHandle) {
    options.tls_ca_cert = "/path/to/ca.pem";
    options.tls_ca_path = "/path/to/ca-dir";
    nvat_http_options_t http_options = nullptr;
    EXPECT_EQ(make_http_options(options, http_options), NVAT_RC_OK);
    ASSERT_NE(http_options, nullptr);
    nvat_http_options_free(&http_options);
}

TEST_F(MakeHttpOptionsMock, CreateFailurePropagates) {
    options.tls_ca_cert = "/path/to/ca.pem";
    g_fake_nvat.http_options_rc = NVAT_RC_INTERNAL_ERROR;
    nvat_http_options_t http_options = nullptr;
    EXPECT_EQ(make_http_options(options, http_options), NVAT_RC_INTERNAL_ERROR);
}

class MakeOcspClientOptionsMock : public ::testing::Test {
  protected:
    void SetUp() override { fake_nvat_reset(); }
};

TEST_F(MakeOcspClientOptionsMock, UsesSdkParserResult) {
    nvat_ocsp_client_options_t options = nullptr;
    ASSERT_EQ(make_ocsp_client_options("sha-384", options), NVAT_RC_OK);
    ASSERT_NE(options, nullptr);

    nvat_ocsp_client_t client = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_default_with_options(
                  &client, nullptr, nullptr, nullptr, options),
              NVAT_RC_OK);
    EXPECT_EQ(g_fake_nvat.last_ocsp_cert_id_hash,
              NVAT_OCSP_CERT_ID_HASH_SHA384);
    nvat_ocsp_client_free(&client);
    nvat_ocsp_client_options_free(&options);
}

TEST_F(MakeOcspClientOptionsMock, RejectsUnsupportedNameBeforeAllocation) {
    nvat_ocsp_client_options_t options = nullptr;
    EXPECT_EQ(make_ocsp_client_options("sha-512", options),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(options, nullptr);
    EXPECT_EQ(g_fake_nvat.ocsp_options_create_calls, 0);
}

TEST_F(MakeOcspClientOptionsMock, CreateFailurePropagates) {
    g_fake_nvat.ocsp_options_create_rc = NVAT_RC_INTERNAL_ERROR;
    nvat_ocsp_client_options_t options = nullptr;
    EXPECT_EQ(make_ocsp_client_options("sha-256", options),
              NVAT_RC_INTERNAL_ERROR);
    EXPECT_EQ(options, nullptr);
}

TEST_F(MakeOcspClientOptionsMock, SetFailureFreesAllocatedHandle) {
    g_fake_nvat.ocsp_options_set_rc = NVAT_RC_INTERNAL_ERROR;
    nvat_ocsp_client_options_t options = nullptr;
    EXPECT_EQ(make_ocsp_client_options("sha-256", options),
              NVAT_RC_INTERNAL_ERROR);
    EXPECT_EQ(options, nullptr);
    EXPECT_EQ(g_fake_nvat.ocsp_options_create_calls, 1);
    EXPECT_EQ(g_fake_nvat.ocsp_options_free_calls, 1);
}
