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

// Black-box coverage for the attest-v2 subcommand. Every case is hermetic: the
// Blackwell CMW carries no tagged-spdm-toc, so no RIM is fetched, and revocation
// is disabled so no OCSP network is required.

#include <cstdio>
#include <cctype>
#include <climits>
#include <fstream>
#include <string>

#include "gtest/gtest.h"
#include <nlohmann/json.hpp>

#include "environment.h"
#include "nvat.h"
#include "test_utils.h"

namespace {

// This evidence carries no CoEV, so nothing is appraised and attest-v2 exits 1.
// The tests below cover argument handling and output shape, not a passing
// appraisal.
const std::string kBlackwellCmw =
    "../../../common-test-data/cmw/blackwell_evidence.cmw.json";

std::string base_verify_cmd_no_revocation_flag() {
    return g_cli_env->nvattest_bin +
           " attest-v2 --evidence-source file --evidence-file " +
           kBlackwellCmw;
}

std::string base_verify_cmd() {
    return base_verify_cmd_no_revocation_flag() + " --no-verify-revocation";
}

nlohmann::json run_and_parse(const std::string &cmd, int &exit_code) {
    std::string output = exec_and_capture_output(cmd, exit_code);
    std::string json_str;
    EXPECT_TRUE(extract_json_object(output, json_str))
        << "No JSON in output:\n"
        << output;
    return nlohmann::json::parse(json_str, nullptr, /*allow_exceptions=*/false);
}

std::string base64url_decode(const std::string &in) {
    static const std::string kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::array<int, 256> rev{};
    rev.fill(-1);
    for (size_t i = 0; i < kAlphabet.size(); ++i) {
        rev[static_cast<unsigned char>(kAlphabet[i])] = static_cast<int>(i);
    }
    std::string out;
    int buf = 0;
    int bits = 0;
    for (char ch : in) {
        const int val = rev[static_cast<unsigned char>(ch)];
        if (val < 0) continue;
        buf = (buf << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

void write_file(const std::string &path, const std::string &bytes) {
    std::ofstream out(path, std::ios::binary);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::string to_hex(const std::string &bytes) {
    static const char *kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) {
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 0x0F]);
    }
    return out;
}

} // namespace

TEST(AttestV2Cli, VerifyBlackwellJsonProducesResult) {
    int exit_code = 0;
    nlohmann::json response =
        run_and_parse(base_verify_cmd() + " --format json", exit_code);
    ASSERT_FALSE(response.is_discarded());
    EXPECT_EQ(exit_code, 1);
    EXPECT_TRUE(response.contains("submods")) << response.dump(2);
}

TEST(AttestV2Cli, RelyingPartyPolicyCanAcceptContraindicatedBlackwellEar) {
    const std::string policy_path = "attest_v2_accept_contraindicated.rego";
    write_file(policy_path,
               "package policy\n"
               "nv_match := input.submods.gpu_0.ear_status == \"contraindicated\"\n");

    int exit_code = 0;
    nlohmann::json response = run_and_parse(
        base_verify_cmd() + " --relying-party-policy " + policy_path +
        " --format json",
        exit_code);
    std::remove(policy_path.c_str());

    EXPECT_EQ(exit_code, 0) << response.dump(2);
    EXPECT_EQ(response["submods"]["gpu_0"]["ear_status"], "contraindicated")
        << response.dump(2);
}

TEST(AttestV2Cli, VerifyBlackwellTextProducesResult) {
    int exit_code = 0;
    std::string output =
        exec_and_capture_output(base_verify_cmd() + " --format text", exit_code);
    EXPECT_EQ(exit_code, 1) << output;
    // Text mode renders a human-readable summary instead of raw JSON.
    EXPECT_NE(output.find("Submods:"), std::string::npos) << output;
}

TEST(AttestV2Cli, VerifyWithRimUrlRewriteIsAccepted) {
    // Blackwell fetches no RIM, so the rewrite is merely registered; this
    // exercises the rewrite-parsing loop.
    int exit_code = 0;
    const std::string cmd = base_verify_cmd() +
                            " --rim-url-rewrite https://example.com/a "
                            "file:///dev/null --format json";
    run_and_parse(cmd, exit_code);
    EXPECT_EQ(exit_code, 1);
}

TEST(AttestV2Cli, MalformedCmwReportsError) {
    const std::string tmp_path = "attest_v2_malformed.cmw.json";
    {
        std::ofstream out(tmp_path);
        out << "this is not a cmw";
    }
    int exit_code = 0;
    const std::string cmd =
        g_cli_env->nvattest_bin +
        " attest-v2 --evidence-source file --evidence-file " + tmp_path +
        " --no-verify-revocation --format json";
    nlohmann::json response = run_and_parse(cmd, exit_code);
    std::remove(tmp_path.c_str());

    EXPECT_NE(exit_code, 0);
}

// Text-mode failure exercises print_error_help.
TEST(AttestV2Cli, MalformedCmwTextModePrintsErrorHelp) {
    const std::string tmp_path = "attest_v2_malformed_text.cmw.json";
    {
        std::ofstream out(tmp_path);
        out << "not a cmw";
    }
    int exit_code = 0;
    const std::string cmd =
        g_cli_env->nvattest_bin +
        " attest-v2 --evidence-source file --evidence-file " + tmp_path +
        " --no-verify-revocation --format text";
    std::string output = exec_and_capture_output(cmd, exit_code);
    std::remove(tmp_path.c_str());

    EXPECT_NE(exit_code, 0) << output;
    EXPECT_NE(output.find("Error"), std::string::npos) << output;
}

TEST(AttestV2Cli, EarSigningIssuerWithoutKeyFileIsAcceptedOnUnsignedEar) {
    int exit_code = 0;
    nlohmann::json response = run_and_parse(
        base_verify_cmd() + " --ear-signing-issuer test-issuer --format json",
        exit_code);
    EXPECT_EQ(exit_code, 1) << response.dump(2);
    EXPECT_TRUE(response.contains("iss")) << response.dump(2);
    EXPECT_EQ(response["iss"].get<std::string>(), "test-issuer") << response.dump(2);
    ASSERT_TRUE(response.contains("ear_jwt")) << response.dump(2);

    const std::string& ear_jwt = response["ear_jwt"].get<std::string>();
    const size_t first_dot = ear_jwt.find('.');
    ASSERT_NE(first_dot, std::string::npos);
    nlohmann::json header =
        nlohmann::json::parse(base64url_decode(ear_jwt.substr(0, first_dot)),
                              nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(header.is_discarded());
    EXPECT_EQ(header["alg"].get<std::string>(), "none");
}

TEST(AttestV2Cli, EarSigningKidWithoutKeyFileIsRejected) {
    int exit_code = 0;
    const std::string cmd =
        base_verify_cmd() + " --ear-signing-kid test-kid --format json";
    exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0);
}

TEST(AttestV2Cli, OddRimUrlRewriteIsRejected) {
    int exit_code = 0;
    const std::string cmd =
        base_verify_cmd() + " --rim-url-rewrite only-one-token --format json";
    exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0);
}

TEST(AttestV2Cli, FileSourceWithoutFileIsRejected) {
    int exit_code = 0;
    const std::string cmd = g_cli_env->nvattest_bin +
                            " attest-v2 --evidence-source file --format json";
    exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0);
}

TEST(AttestV2Cli, NonexistentFileIsRejected) {
    int exit_code = 0;
    const std::string cmd =
        g_cli_env->nvattest_bin +
        " attest-v2 --evidence-source file --evidence-file "
        "/nonexistent/does_not_exist.cmw.json --format json";
    exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0);
}

TEST(AttestV2Cli, NonexistentRelyingPartyPolicyIsRejected) {
    int exit_code = 0;
    const std::string output = exec_and_capture_output(
        base_verify_cmd() +
        " --relying-party-policy /nonexistent/does_not_exist.rego --format json",
        exit_code);

    // CLI11 uses 105 for validation failures.
    EXPECT_EQ(exit_code, 105) << output;
    EXPECT_NE(output.find("--relying-party-policy"), std::string::npos) << output;
}

// Exercises the NVML collection path; NVML init fails on a GPU-less runner, so
// this reports an error rather than hanging.
TEST(AttestV2Cli, NvmlSourceReportsErrorWithoutGpu) {
    int exit_code = 0;
    const std::string cmd = g_cli_env->nvattest_bin +
                            " attest-v2 --evidence-source nvml --format json";
    exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0);
}

TEST(AttestV2Cli, SpdmFilesSourceWithoutTranscriptIsRejected) {
    int exit_code = 0;
    const std::string cmd = g_cli_env->nvattest_bin +
                            " attest-v2 --evidence-source spdm-files";
    exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0);
}

TEST(AttestV2Cli, SpdmFilesSourceWithoutCertChainIsRejected) {
    int exit_code = 0;
    const std::string cmd =
        g_cli_env->nvattest_bin +
        " attest-v2 --evidence-source spdm-files --spdm-transcript-file " +
        kBlackwellCmw;
    exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0);
}

TEST(AttestV2Cli, EatFileSourceWithoutFileIsRejected) {
    int exit_code = 0;
    const std::string cmd = g_cli_env->nvattest_bin +
                            " attest-v2 --evidence-source eat-file";
    exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0);
}

TEST(AttestV2Cli, EatFileSourceWithNonexistentFileIsRejected) {
    int exit_code = 0;
    const std::string cmd = g_cli_env->nvattest_bin +
                            " attest-v2 --evidence-source eat-file --eat-file "
                            "/nonexistent/does_not_exist.eat.cbor";
    exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0);
}

TEST(AttestV2Cli, EatFileSourceDoesNotRequireNonce) {
    int exit_code = 0;
    const std::string cmd =
        g_cli_env->nvattest_bin +
        " attest-v2 --evidence-source eat-file --eat-file " + kBlackwellCmw;
    const std::string output = exec_and_capture_output(cmd, exit_code);

    EXPECT_NE(exit_code, 0);
    EXPECT_EQ(output.find("nonce must be provided"), std::string::npos)
        << output;
}

TEST(AttestV2Cli, NoVerifyRimSignaturesIsAccepted) {
    int exit_code = 0;
    run_and_parse(
        base_verify_cmd() + " --no-verify-rim-signatures --format json", exit_code);
    EXPECT_EQ(exit_code, 1);
}

TEST(AttestV2Cli, EarSigningKeyFileIsAccepted) {
    // Generated signing key
    const std::string key_path = "attest_v2_ear_signing_key.pem";
    int gen_exit_code = 0;
    exec_and_capture_output(
        "openssl ecparam -name secp384r1 -genkey -noout -out " + key_path,
        gen_exit_code);
    ASSERT_EQ(gen_exit_code, 0) << "failed to generate EC P-384 test key";

    int exit_code = 0;
    nlohmann::json response = run_and_parse(
        base_verify_cmd() +
        " --ear-signing-key-file " + key_path +
        " --ear-signing-issuer test-issuer"
        " --ear-signing-kid test-kid"
        " --format json",
        exit_code);
    std::remove(key_path.c_str());

    EXPECT_EQ(exit_code, 1) << response.dump(2);
    EXPECT_TRUE(response.contains("submods")) << response.dump(2);
    EXPECT_TRUE(response.contains("iss")) << response.dump(2);
    EXPECT_EQ(response["iss"].get<std::string>(), "test-issuer") << response.dump(2);
    EXPECT_TRUE(response.contains("ear_jwt")) << response.dump(2);
    EXPECT_FALSE(response["ear_jwt"].get<std::string>().empty()) << response.dump(2);
}

TEST(AttestV2Cli, BackupRimLocatorIsAccepted) {
    int exit_code = 0;
    nlohmann::json response = run_and_parse(
        base_verify_cmd() +
        " --backup-rim-locator https://example.com/rim1"
        " --backup-rim-locator https://example.com/rim2"
        " --format json",
        exit_code);
    // The locators are registered and a fetch is attempted; it fails against
    // example.com, so the appraisal does not affirm.
    EXPECT_EQ(exit_code, 1) << response.dump(2);
    EXPECT_TRUE(response.contains("submods")) << response.dump(2);
}

// A CoRIM whose reference triple matches the fixture's cert-chain ECT. The
// measurement carries no mkey, mirroring what the DICE mapper emits; mkey is
// optional in both the CoRIM and CoEV grammars.
//
//   501_1({0: "test-corim-blackwell", 1: [506_1({
//       1: {0: "test-comid-blackwell"},
//       4: {0: [[ {0: {0: 560(h'00'), 1: "NVIDIA", 2: "GB100 A01 GSP",
//                      3: 0, 4: 0}},
//                 [{1: {2: [[7, h'<sha-384 of the GSP measurement>']]}}] ]]}})]})
const std::string kMatchingCorimHex =
    "d901f5a20074746573742d636f72696d2d626c61636b77656c6c0181d901fa587ca201a100"
    "74746573742d636f6d69642d626c61636b77656c6c04a1008182a100a500d9023041000166"
    "4e5649444941026d4742313030204130312047535003000400 81a101a1028182075830d090"
    "cab1b6e6ffddca83d1781e25b3f040fa1f3c7608230cb5f41b1c1b99f5f748349e59d0ef8eb"
    "830c9bc79ccf77502";

// The only case in the suite where attestation affirms: the fixture carries no
// CoEV, so a backup locator supplies the CoRIM that its cert-chain ECT matches.
TEST(AttestV2Cli, MatchingCorimAffirms) {
    const std::string tmp_path = "attest_v2_matching.corim";
    {
        std::string hex;
        for (char c : kMatchingCorimHex) {
            if (!std::isspace(static_cast<unsigned char>(c))) hex.push_back(c);
        }
        std::ofstream out(tmp_path, std::ios::binary);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            out << static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16));
        }
    }
    char resolved[PATH_MAX];
    ASSERT_NE(::realpath(tmp_path.c_str(), resolved), nullptr);
    const std::string dir = std::string(resolved).substr(
        0, std::string(resolved).find_last_of('/') + 1);

    int exit_code = 0;
    nlohmann::json response = run_and_parse(
        base_verify_cmd() + " --no-verify-rim-signatures --format json"
        " --backup-rim-locator https://rim.attestation.nvidia.com/v1/rim/" + tmp_path +
        " --rim-url-rewrite https://rim.attestation.nvidia.com/v1/rim/ file://" + dir,
        exit_code);
    std::remove(tmp_path.c_str());

    EXPECT_EQ(exit_code, 0) << response.dump(2);
    ASSERT_TRUE(response.contains("submods")) << response.dump(2);
    const auto& submods = response["submods"];
    ASSERT_TRUE(submods.is_object());
    ASSERT_FALSE(submods.empty()) << response.dump(2);
    for (const auto& submod : submods.items()) {
        EXPECT_EQ(submod.value().value("ear_status", std::string()), "affirming")
            << submod.value().dump(2);
    }
}

TEST(AttestV2Cli, BackupCoevFileIsAccepted) {
    const std::string tmp_path = "attest_v2_backup_coev.cbor";
    {
        std::ofstream out(tmp_path, std::ios::binary);
        // Minimal valid CBOR: empty map (0xa0).
        out << '\xa0';
    }
    int exit_code = 0;
    nlohmann::json response = run_and_parse(
        base_verify_cmd() +
        " --backup-spdm-concise-evidence " + tmp_path + " --format json",
        exit_code);
    std::remove(tmp_path.c_str());
    // An empty map fails to map to ECTs, so the appraisal does not affirm.
    EXPECT_EQ(exit_code, 1) << response.dump(2);
    EXPECT_TRUE(response.contains("submods")) << response.dump(2);
}

// Drives the revocation-enabled branch (OCSP AIA client construction + the
// ocsp-url-rewrite loop). The OCSP outcome depends on network reachability, so
// only the structured response is asserted, not the verdict.
TEST(AttestV2Cli, RevocationEnabledConstructsOcspClient) {
    int exit_code = 0;
    const std::string cmd =
        base_verify_cmd_no_revocation_flag() +
        " --ocsp-url-rewrite https://example.com/a https://example.com/b "
        "--format json";
    run_and_parse(cmd, exit_code);
}

// Reconstructs the raw SPDM transcript + PEM cert chain from the Blackwell CMW
// fixture and drives the spdm-files source (transcript/cert read,
// create_from_spdm_transcript, serialize). This mirrors the single evidence
// item the fixture carries, so verification proceeds end-to-end.
class AttestV2SpdmFiles : public ::testing::Test {
  protected:
    std::string transcript_path = "attest_v2_spdm_transcript.bin";
    std::string cert_path = "attest_v2_spdm_cert.pem";
    std::string nonce_hex;

    void SetUp() override {
        std::ifstream cmw_file(kBlackwellCmw, std::ios::binary);
        ASSERT_TRUE(cmw_file) << "missing fixture: " << kBlackwellCmw;
        nlohmann::json cmw = nlohmann::json::parse(cmw_file, nullptr, false);
        ASSERT_FALSE(cmw.is_discarded());
        const auto &item = cmw.at("gpu_0");
        write_file(transcript_path,
                   base64url_decode(item.at("evidence").at(1).get<std::string>()));
        write_file(cert_path,
                   base64url_decode(item.at("certificate").at(1).get<std::string>()));
        nonce_hex =
            to_hex(base64url_decode(item.at("nonce").at(1).get<std::string>()));
    }

    void TearDown() override {
        std::remove(transcript_path.c_str());
        std::remove(cert_path.c_str());
    }

    std::string base_cmd() const {
        return g_cli_env->nvattest_bin +
               " attest-v2 --evidence-source spdm-files"
               " --spdm-transcript-file " + transcript_path +
               " --cert-chain-file " + cert_path + " --no-verify-revocation";
    }
};

TEST_F(AttestV2SpdmFiles, WithNonceProducesStructuredResult) {
    int exit_code = 0;
    nlohmann::json response = run_and_parse(
        base_cmd() + " --nonce " + nonce_hex + " --format json", exit_code);
    ASSERT_FALSE(response.is_discarded());
    EXPECT_EQ(exit_code, 1);
}

// Omitting --nonce covers the optional-nonce skip branch in run_verify.
TEST_F(AttestV2SpdmFiles, WithoutNonceProducesStructuredResult) {
    int exit_code = 0;
    nlohmann::json response =
        run_and_parse(base_cmd() + " --format json", exit_code);
    ASSERT_FALSE(response.is_discarded());
    EXPECT_EQ(exit_code, 1);
}
