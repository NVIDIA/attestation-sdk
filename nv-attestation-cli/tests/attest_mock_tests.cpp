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

// In-process white-box tests for handle_attest_subcommand, driven against the
// fake nvat C API (fake_nvat.cpp). The real attestation flow needs GPU/switch
// hardware or live services, so these steer the SDK responses to exercise the
// CLI orchestration (device/verifier/evidence-source branches, RIM/OCSP/policy
// setup, result and exit-code mapping) without any of that.

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "gtest/gtest.h"

#include "nvat.h"
#include "attest.h"
#include "nvattest_options.h"
#include "logging.h"
#include "fake_nvat_control.h"
#include "mock_cli_logger.h"

using namespace nvattest;

namespace {
const char* const kPolicyPath = "/tmp/nvattest_attest_mock_policy.rego";
} // namespace

class AttestMock : public ::testing::Test {
  protected:
    EvidenceCollectionOptions collect;
    EvidenceVerificationOptions verify;
    EvidencePolicyOptions policy;
    CommonOptions common;
    std::streambuf* m_old_cout = nullptr;
    std::ostringstream m_captured_cout;

    void SetUp() override {
        fake_nvat_reset();
        // Default happy config: GPU, local verifier with a remote RIM store, JSON.
        collect.device = "gpu";
        verify.verifier = "local";
        verify.rim_store = "remote";
        verify.ocsp_cert_id_hash = "sha-256";
        common.format = "json";
        m_old_cout = std::cout.rdbuf(m_captured_cout.rdbuf());
    }

    void TearDown() override {
        std::cout.rdbuf(m_old_cout);
        std::remove(kPolicyPath);
    }

    int run() {
        return handle_attest_subcommand(shared_mock_logger(), collect, verify, policy, common);
    }

    void write_policy(const char* contents) {
        std::ofstream(kPolicyPath) << contents;
        verify.relying_party_policy = kPolicyPath;
    }
};

// --- success across the main branch clusters ---

TEST_F(AttestMock, GpuLocalRemoteRimSuccessJson) {
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, GpuLocalSuccessText) {
    common.format = "text";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, GpuFileEvidenceSource) {
    collect.gpu_evidence_source = "file";
    collect.gpu_evidence_file = "/tmp/ignored-by-fake.json";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, GpuCorelibSourceRejected) {
    collect.gpu_evidence_source = "corelib";  // not valid for attest
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_BAD_ARGUMENT));
}

TEST_F(AttestMock, SwitchLocalNscqSuccess) {
    collect.device = "nvswitch";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, SwitchFileEvidenceSource) {
    collect.device = "nvswitch";
    collect.switch_evidence_source = "file";
    collect.switch_evidence_file = "/tmp/ignored-by-fake.json";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, RimStoreFilesystem) {
    verify.rim_store = "dir";
    verify.rim_path = "/tmp/rims";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, RemoteVerifier) {
    verify.verifier = "remote";  // skips RIM store setup
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, OcspClientConfigured) {
    verify.ocsp_url = "https://ocsp.example.com";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, OcspCertIdHashReachesDefaultClientConstructor) {
    verify.ocsp_url = "https://ocsp.example.com";
    verify.ocsp_cert_id_hash = "sha-384";

    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
    EXPECT_EQ(g_fake_nvat.ocsp_default_with_options_create_calls, 1);
    EXPECT_EQ(g_fake_nvat.ocsp_default_create_calls, 0);
    EXPECT_EQ(g_fake_nvat.last_ocsp_cert_id_hash,
              NVAT_OCSP_CERT_ID_HASH_SHA384);
}

TEST_F(AttestMock, ServiceKeyProvided) {
    verify.service_key = "test-key";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, NrasUrlOverride) {
    verify.verifier = "remote";
    verify.nras_url = "https://nras.example.com";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, EvidencePolicyFlags) {
    policy.verify_rim_signature = false;
    policy.verify_rim_cert_chain = false;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, NonceProvided) {
    collect.nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, RelyingPartyPolicyApplied) {
    write_policy("package policy\n");
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

// --- result-code pass-through (attest returns the raw result code) ---

TEST_F(AttestMock, RelyingPartyPolicyMismatchPassesThrough) {
    g_fake_nvat.attest_rc = NVAT_RC_RP_POLICY_MISMATCH;  // still yields claims
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_RP_POLICY_MISMATCH));
}

TEST_F(AttestMock, OverallResultFalsePassesThrough) {
    g_fake_nvat.attest_rc = NVAT_RC_OVERALL_RESULT_FALSE;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OVERALL_RESULT_FALSE));
}

TEST_F(AttestMock, AttestFailureReturnsCode) {
    g_fake_nvat.attest_rc = NVAT_RC_NRAS_TOKEN_INVALID;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_NRAS_TOKEN_INVALID));
}

// --- setup / SDK-call failure branches ---

TEST_F(AttestMock, InitSdkFailure) {
    g_fake_nvat.sdk_init_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(AttestMock, CtxCreateFailure) {
    g_fake_nvat.ctx_create_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(AttestMock, EvidencePolicyCreateFailure) {
    g_fake_nvat.evidence_policy_create_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(AttestMock, RimStoreCreateFailure) {
    g_fake_nvat.rim_store_create_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(AttestMock, OcspCreateFailure) {
    verify.ocsp_url = "https://ocsp.example.com";
    g_fake_nvat.ocsp_create_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(AttestMock, SerializeFailure) {
    g_fake_nvat.serialize_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(AttestMock, RelyingPartyPolicyFileNotFound) {
    verify.relying_party_policy = "/tmp/nvattest_attest_mock_missing_policy_xyz.rego";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_BAD_ARGUMENT));
}

// --- text-mode claims formatting (print_device_claims) ---
// These steer the fake serialized claims to various shapes and run in text mode
// so the device-claims pretty printer is exercised.

// A fully-populated GPU claim: device fields, GPU-specifics, three cert chains
// (with revocation reason), a measurement-mismatch record list, and an
// opaque-data-mismatch record list.
TEST_F(AttestMock, TextRichGpuClaims) {
    common.format = "text";
    g_fake_nvat.claims_json = R"([{
        "x-nvidia-device-type":"gpu","hwmodel":"GH100","ueid":"abc",
        "x-nvidia-gpu-vbios-version":"96.00","x-nvidia-gpu-driver-version":"575.00",
        "x-nvidia-gpu-mode":"CC","measres":"success",
        "x-nvidia-gpu-attestation-report-cert-chain":{"x-nvidia-cert-status":"valid","x-nvidia-cert-ocsp-status":"good","x-nvidia-cert-expiration-date":"2030-01-01","x-nvidia-cert-revocation-reason":"none"},
        "x-nvidia-gpu-driver-rim-cert-chain":{"x-nvidia-cert-status":"valid","x-nvidia-cert-ocsp-status":"good","x-nvidia-cert-expiration-date":"2030"},
        "x-nvidia-gpu-vbios-rim-cert-chain":{"x-nvidia-cert-status":"valid","x-nvidia-cert-ocsp-status":"good","x-nvidia-cert-expiration-date":"2030"},
        "x-nvidia-mismatch-measurement-records":[{"index":5,"measurementSource":"driver","goldenValue":"aa","runtimeValue":"bb"},"not-an-object"],
        "x-nvidia-mismatch-opaque-data-records":[{"id":37,"name":"example_min_svn","goldenType":"MIN_SVN","goldenValue":5,"runtimeType":"MIN_SVN","runtimeValue":4},"not-an-object"]
    }])";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, TextRichSwitchClaims) {
    common.format = "text";
    g_fake_nvat.claims_json = R"([{
        "x-nvidia-device-type":"nvswitch","hwmodel":"NVSwitch","ueid":"sw1",
        "x-nvidia-switch-bios-version":"1.0","measres":"success",
        "x-nvidia-switch-attestation-report-cert-chain":{"x-nvidia-cert-status":"valid","x-nvidia-cert-ocsp-status":"good","x-nvidia-cert-expiration-date":"2030"},
        "x-nvidia-switch-bios-rim-cert-chain":{"x-nvidia-cert-status":"valid","x-nvidia-cert-ocsp-status":"good","x-nvidia-cert-expiration-date":"2030"}
    }])";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

// Invalid cert-chain value (not an object) + empty measurement-mismatch array.
TEST_F(AttestMock, TextGpuClaimsInvalidCertChain) {
    common.format = "text";
    g_fake_nvat.claims_json = R"([{
        "x-nvidia-device-type":"gpu",
        "x-nvidia-gpu-attestation-report-cert-chain":"not-an-object",
        "x-nvidia-mismatch-measurement-records":[]
    }])";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

// Mismatch records present but null (the null branch), null cert field.
TEST_F(AttestMock, TextGpuClaimsNullMismatches) {
    common.format = "text";
    g_fake_nvat.claims_json = R"([{"x-nvidia-device-type":"gpu","hwmodel":null,"x-nvidia-mismatch-measurement-records":null}])";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, TextClaimsNotAnArray) {
    common.format = "text";
    g_fake_nvat.claims_json = "{}";  // object, not the expected array
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, TextClaimsArrayWithNonObject) {
    common.format = "text";
    g_fake_nvat.claims_json = "[1]";  // array element is not an object
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, TextClaimsMalformedJson) {
    common.format = "text";
    g_fake_nvat.claims_json = "{not valid json";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

// JSON output with malformed claims + detached-EAT exercises to_json's catch paths.
TEST_F(AttestMock, JsonToJsonHandlesMalformedPayloads) {
    g_fake_nvat.claims_json = "{not valid json";
    g_fake_nvat.detached_eat_json = "{not valid json";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

// Text mode + a failure: no claims are produced, so the printer hits its
// empty-claims path and the handler hits the failure log + error-help branch.
TEST_F(AttestMock, TextModeAttestFailure) {
    common.format = "text";
    g_fake_nvat.attest_rc = NVAT_RC_NRAS_TOKEN_INVALID;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_NRAS_TOKEN_INVALID));
}

// Mismatch-measurement-records present but neither an array nor null.
TEST_F(AttestMock, TextMismatchInvalidRecord) {
    common.format = "text";
    g_fake_nvat.claims_json =
        R"([{"x-nvidia-device-type":"gpu","x-nvidia-mismatch-measurement-records":"oops"}])";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, RelyingPartyPolicyCreateFailure) {
    write_policy("not valid rego\n");
    g_fake_nvat.policy_create_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

// --- structural / argument-guard branches ---

TEST_F(AttestMock, UnknownVerifierRejected) {
    verify.verifier = "bogus";  // neither local nor remote
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_BAD_ARGUMENT));
}

TEST_F(AttestMock, UnknownRimStoreRejected) {
    verify.rim_store = "bogus";  // local verifier, neither remote nor dir
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_BAD_ARGUMENT));
}

TEST_F(AttestMock, TlsCaCertBuildsHttpOptions) {
    verify.tls_ca_cert = "/tmp/ignored-by-fake.pem";  // exercises the http-options guard
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(AttestMock, ClaimsStrGetDataFailure) {
    g_fake_nvat.str_get_data_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(AttestMock, NonceParseFailure) {
    collect.nonce = "zz";  // fake nonce parse is steered to fail
    g_fake_nvat.nonce_rc = NVAT_RC_BAD_ARGUMENT;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_BAD_ARGUMENT));
}
