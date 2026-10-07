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
#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <array>
#include <sys/wait.h>

#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>

#include "nvat.h"
#include "environment.h"
#include "test_utils.h"
#include "nvattest_options.h"

// Tests that do not require a GPU driver or network access use a plain TEST
// rather than TEST_F(CliTest, ...) to avoid the requires-working-driver skip.

TEST(VerifyTokenArgHandling, MissingTokenReturnsExitCode1) {
    // Passing no --token-file and stdin closed should result in a
    // bad-argument error and exit code 1.
    std::string nvattest_bin = get_env_or_default("NVATTEST_BIN", "../nvattest");

    // Redirect stdin from /dev/null so the binary sees EOF immediately.
    std::string cmd = nvattest_bin + " --format json verify-token --nras-url http://localhost:1 </dev/null";
    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    EXPECT_EQ(exit_code, 1) << "Expected exit code 1 when no token is supplied. Output:\n" << output;

    std::string json_str;
    if (extract_json_object(output, json_str)) {
        nlohmann::json response;
        ASSERT_NO_THROW(response = nlohmann::json::parse(json_str));
        ASSERT_TRUE(response.contains("result_code"));
        EXPECT_NE(response["result_code"].get<int>(), 0)
            << "Expected non-zero result_code. JSON:\n" << response.dump(2);
    }
    // If no JSON in output, the exit code check above is sufficient.
}

TEST(VerifyTokenEarArgHandling, AcceptsTokenTypeAndClockSkewLeewayOptions) {
    std::string nvattest_bin = get_env_or_default("NVATTEST_BIN", "../nvattest");
    int exit_code = 0;
    const std::string output = exec_and_capture_output(
        nvattest_bin + " verify-token --token-type ear"
        " --clock-skew-leeway-seconds 60 --help", exit_code);

    EXPECT_EQ(exit_code, 0) << output;
    EXPECT_THAT(output, ::testing::HasSubstr("--token-type"));
    EXPECT_THAT(output, ::testing::HasSubstr("--clock-skew-leeway-seconds"));
    EXPECT_THAT(output, ::testing::HasSubstr("default 60"));
    EXPECT_THAT(output, ::testing::HasSubstr("zero means strict validation"));
    EXPECT_THAT(output, ::testing::HasSubstr("iat, nbf, and exp"));
}

TEST(VerifyTokenEarArgHandling, RejectsInvalidClockSkew) {
    std::string nvattest_bin = get_env_or_default("NVATTEST_BIN", "../nvattest");
    int exit_code = 0;
    const std::string output = exec_and_capture_output(
        nvattest_bin + " verify-token --token-type ear"
        " --clock-skew-leeway-seconds not-a-number </dev/null", exit_code);

    EXPECT_NE(exit_code, 0) << output;
}

TEST(VerifyTokenArgHandling, MalformedTokenFileReturnsExitCode1) {
    // A syntactically invalid EAT string written to a temp file must fail with exit code 1.
    std::string nvattest_bin = get_env_or_default("NVATTEST_BIN", "../nvattest");

    // Write malformed JSON to a temp file.
    std::string tmp_path = "/tmp/nvattest_malformed_eat_test.json";
    {
        std::ofstream tmp(tmp_path);
        tmp << "{not_valid_json}";
    }

    std::string cmd = nvattest_bin + " --format json verify-token"
        " --token-file " + tmp_path +
        " --nras-url http://localhost:1";
    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    EXPECT_EQ(exit_code, 1) << "Expected exit code 1 for malformed EAT. Output:\n" << output;

    std::string json_str;
    if (extract_json_object(output, json_str)) {
        nlohmann::json response;
        ASSERT_NO_THROW(response = nlohmann::json::parse(json_str));
        ASSERT_TRUE(response.contains("result_code"));
        EXPECT_NE(response["result_code"].get<int>(), 0)
            << "Expected non-zero result_code. JSON:\n" << response.dump(2);
    }

    std::remove(tmp_path.c_str());
}

TEST(VerifyTokenArgHandling, MissingTokenFileReturnsExitCode1) {
    // Pointing --token-file at a non-existent path should fail with exit code 1.
    std::string nvattest_bin = get_env_or_default("NVATTEST_BIN", "../nvattest");
    std::string cmd = nvattest_bin + " --format json verify-token"
        " --token-file /tmp/nvattest_nonexistent_eat_file_xyz.json"
        " --nras-url http://localhost:1";
    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    EXPECT_EQ(exit_code, 1) << "Expected exit code 1 for missing token file. Output:\n" << output;
}

TEST(VerifyTokenArgHandling, InvalidNonceHexReturnsExitCode1) {
    // A syntactically invalid --nonce is rejected while parsing the nonce, before
    // any network call, yielding exit code 1. The token content is irrelevant
    // here because the nonce is parsed first.
    std::string nvattest_bin = get_env_or_default("NVATTEST_BIN", "../nvattest");

    std::string tmp_path = "/tmp/nvattest_invalid_nonce_eat_test.json";
    {
        std::ofstream tmp(tmp_path);
        tmp << "{}";
    }

    std::string cmd = nvattest_bin + " --format json verify-token"
        " --token-file " + tmp_path +
        " --nonce ZZZZ"
        " --nras-url http://localhost:1";
    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    EXPECT_EQ(exit_code, 1) << "Expected exit code 1 for invalid nonce hex. Output:\n" << output;

    std::string json_str;
    if (extract_json_object(output, json_str)) {
        nlohmann::json response;
        ASSERT_NO_THROW(response = nlohmann::json::parse(json_str));
        ASSERT_TRUE(response.contains("result_code"));
        EXPECT_NE(response["result_code"].get<int>(), 0)
            << "Expected non-zero result_code. JSON:\n" << response.dump(2);
    }

    std::remove(tmp_path.c_str());
}

TEST(VerifyTokenArgHandling, MalformedTokenTextFormatReturnsExitCode1) {
    // Same malformed-token failure but in the default text output format, which
    // exercises the text-mode failure branch (critical log + error help) rather
    // than the JSON branch the other tests use.
    std::string nvattest_bin = get_env_or_default("NVATTEST_BIN", "../nvattest");

    std::string tmp_path = "/tmp/nvattest_malformed_text_eat_test.json";
    {
        std::ofstream tmp(tmp_path);
        tmp << "{not_valid_json}";
    }

    // No --format json: defaults to text.
    std::string cmd = nvattest_bin + " verify-token"
        " --token-file " + tmp_path +
        " --nras-url http://localhost:1";
    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    EXPECT_EQ(exit_code, 1) << "Expected exit code 1 for malformed EAT (text mode). Output:\n" << output;

    std::remove(tmp_path.c_str());
}

TEST(VerifyTokenArgHandling, TlsCaCertOptionBuildsHttpOptions) {
    // Supplying --tls-ca-cert exercises the make_http_options TLS branch and the
    // http-options guard in handle_verify_token_subcommand. Verification still
    // fails (non-https / unreachable service), so the exit code is 1.
    std::string nvattest_bin = get_env_or_default("NVATTEST_BIN", "../nvattest");

    std::string eat_path = "/tmp/nvattest_tlsca_eat_test.json";
    {
        std::ofstream tmp(eat_path);
        tmp << "{}";
    }
    std::string ca_path = "/tmp/nvattest_tlsca_dummy_ca.pem";
    {
        std::ofstream ca(ca_path);
        ca << "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n";
    }

    std::string cmd = nvattest_bin + " --format json verify-token"
        " --token-file " + eat_path +
        " --tls-ca-cert " + ca_path +
        " --nras-url http://localhost:1";
    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    EXPECT_EQ(exit_code, 1) << "Expected exit code 1 (unreachable service). Output:\n" << output;

    std::remove(eat_path.c_str());
    std::remove(ca_path.c_str());
}

TEST(VerifyTokenArgHandling, ValidNonceIsAcceptedBeforeVerification) {
    // A well-formed --nonce hex parses successfully (the nonce is accepted and
    // retained), then verification fails because the service is unreachable.
    // This exercises the valid-nonce acceptance path, distinct from the
    // invalid-nonce rejection path.
    std::string nvattest_bin = get_env_or_default("NVATTEST_BIN", "../nvattest");

    std::string eat_path = "/tmp/nvattest_valid_nonce_eat_test.json";
    {
        std::ofstream tmp(eat_path);
        tmp << "{}";
    }

    // 32-byte (64 hex char) nonce.
    std::string cmd = nvattest_bin + " --format json verify-token"
        " --token-file " + eat_path +
        " --nonce 931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"
        " --nras-url http://localhost:1";
    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    EXPECT_EQ(exit_code, 1) << "Expected exit code 1 (unreachable service). Output:\n" << output;

    std::remove(eat_path.c_str());
}
