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

// C-API coverage for the V2 CoRIM verifier surface (CMW collection, CoRIM
// store, local CoRIM verifier, AIA OCSP client). The hermetic verify paths
// mirror test_local_corim_verifier.cpp but drive the handles through nvat.h.

#include <climits>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include <jwt-cpp/jwt.h>
#include <nlohmann/json.hpp>

#include "jwt-cpp/traits/nlohmann-json/traits.h"

#include "gtest/gtest.h"

#include "internal/certs.h"
#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/nvat_private.hpp"
#include "nv_attestation/request_id.h"
#include "nv_attestation/utils.h"
#include "nvat.h"
#include "test_utils.h"

using nvattestation::readFileIntoString;

constexpr const char *kBlackwellCmwPath =
    "testdata/sample_attestation_data/blackwell_evidence.cmw.json";
constexpr const char *kRubinCmwPath =
    "testdata/sample_attestation_data/rubin_evidence.cmw.json";
constexpr const char *kRubinVbiosCorimPath =
    "testdata/sample_rims/corim/rubin_vbios_example.cbor";
constexpr const char *kRubinDriverCorimPath =
    "testdata/sample_rims/corim/rubin_driver_example.cbor";
constexpr const char *kGpuEvidenceJsonPath = "testdata/evidence_hopper_590_12.json";

constexpr const char *kRubinVbiosUrl =
    "https://rim.attestation.nvidia.com/v1/rim/"
    "GR100_081D_9900230000";
constexpr const char *kRubinDriverUrl =
    "https://rim.attestation.nvidia.com/v1/rim/NV_GPU_DRIVER_GR100_620.54";

static std::string file_url(const char *relative_path) {
    char resolved[PATH_MAX];
    if (::realpath(relative_path, resolved) == nullptr) {
        return "";
    }
    return "file://" + std::string(resolved);
}

static nvat_str_t verify_cmw(nvat_local_corim_verifier_t verifier,
                             const std::string &cmw, nvat_rc_t &out_rc) {
    nvat_str_t result = nullptr;
    out_rc = nvat_local_corim_verifier_verify_cmw(
        verifier, reinterpret_cast<const uint8_t *>(cmw.data()), cmw.size(),
        NVAT_CMW_FORMAT_JSON, nullptr, nullptr, nullptr, &result);
    return result;
}

// Parses the verifier's serialized result and returns it; empty object on any
// failure so callers can assert structure without crashing.
static nlohmann::json result_json(nvat_str_t result) {
    if (result == nullptr) {
        return nlohmann::json::object();
    }
    char *data = nullptr;
    if (nvat_str_get_data(result, &data) != NVAT_RC_OK || data == nullptr) {
        return nlohmann::json::object();
    }
    return nlohmann::json::parse(data, nullptr, /*allow_exceptions=*/false);
}

TEST(CApiCorimVerifierTest, AddsValidatedTrustRoots) {
    std::string device_root_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/eat_jwks_root",
                                 device_root_pem), nvattestation::Error::Ok);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);

    EXPECT_EQ(nvat_local_corim_verifier_add_device_identity_trust_root_pem(
                  nullptr, "unused"),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_add_device_identity_trust_root_pem(
                  verifier, nullptr), NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_add_rim_signing_trust_root_pem(
                  verifier, "not a certificate"), NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_add_device_identity_trust_root_pem(
                  verifier, device_root_pem.c_str()),
              NVAT_RC_OK);
    EXPECT_EQ(nvat_local_corim_verifier_add_rim_signing_trust_root_pem(
                  verifier, nvattestation::RIM_ROOT_CERT_CA001_DEV.c_str()),
              NVAT_RC_OK);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, VerifyCmwBlackwellNoTocSucceeds) {
    std::string cmw;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw),
              nvattestation::Error::Ok);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);

    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false),
              NVAT_RC_OK);

    nvat_rc_t rc = NVAT_RC_OK;
    nvat_str_t result = verify_cmw(verifier, cmw, rc);
    EXPECT_EQ(rc, NVAT_RC_OK);
    nlohmann::json parsed = result_json(result);
    EXPECT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.contains("submods"));
    EXPECT_TRUE(parsed.contains("ear_status"));

    nvat_str_free(&result);
    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, VerifyCmwRubinTocMatchesRewrittenRims) {
    std::string cmw;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw), nvattestation::Error::Ok);
    const std::string vbios_url = file_url(kRubinVbiosCorimPath);
    const std::string driver_url = file_url(kRubinDriverCorimPath);
    ASSERT_FALSE(vbios_url.empty());
    ASSERT_FALSE(driver_url.empty());

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    ASSERT_EQ(
        nvat_corim_store_add_url_rewrite(store, kRubinVbiosUrl, vbios_url.c_str()),
        NVAT_RC_OK);
    ASSERT_EQ(nvat_corim_store_add_url_rewrite(store, kRubinDriverUrl,
                                               driver_url.c_str()),
              NVAT_RC_OK);

    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);
    ASSERT_EQ(
        nvat_local_corim_verifier_set_verify_rim_signature(verifier, false),
        NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false),
              NVAT_RC_OK);

    nvat_rc_t rc = NVAT_RC_OK;
    nvat_str_t result = verify_cmw(verifier, cmw, rc);
    EXPECT_EQ(rc, NVAT_RC_OK);
    nlohmann::json parsed = result_json(result);
    EXPECT_EQ(parsed.value("ear_status", std::string{}), "affirming");
    ASSERT_TRUE(parsed.contains("submods"));
    ASSERT_EQ(parsed["submods"].size(), 1u);
    EXPECT_EQ(parsed["submods"]["gpu_0"]["ear_status"], "affirming");

    nvat_str_free(&result);
    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, CmwCollectionFromGpuEvidenceRoundTrips) {
    nvat_gpu_evidence_source_t source = nullptr;
    ASSERT_EQ(nvat_gpu_evidence_source_from_json_file(&source,
                                                      kGpuEvidenceJsonPath),
              NVAT_RC_OK);

    // The JSON evidence source validates against the nonce the fixture was
    // generated with.
    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_from_hex(
                  &nonce,
                  "e97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576"),
              NVAT_RC_OK);

    nvat_gpu_evidence_t *evidences = nullptr;
    size_t num_evidences = 0;
    ASSERT_EQ(nvat_gpu_evidence_collect(source, nonce, &evidences,
                                        &num_evidences),
              NVAT_RC_OK);
    ASSERT_GT(num_evidences, 0U);

    nvat_cmw_collection_t cmw = nullptr;
    ASSERT_EQ(nvat_cmw_collection_create_from_gpu_evidence(&cmw, evidences,
                                                           num_evidences, nonce),
              NVAT_RC_OK);

    nvat_str_t serialized = nullptr;
    ASSERT_EQ(
        nvat_cmw_collection_serialize(cmw, NVAT_CMW_FORMAT_JSON, &serialized),
        NVAT_RC_OK);
    char *data = nullptr;
    ASSERT_EQ(nvat_str_get_data(serialized, &data), NVAT_RC_OK);
    nlohmann::json parsed =
        nlohmann::json::parse(data, nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.is_object());
    EXPECT_TRUE(parsed.contains("__cmwc_t"));

    nvat_str_t cbor = nullptr;
    EXPECT_EQ(
        nvat_cmw_collection_serialize(cmw, NVAT_CMW_FORMAT_CBOR, &cbor),
        NVAT_RC_FEATURE_NOT_ENABLED);

    nvat_str_free(&serialized);
    nvat_cmw_collection_free(&cmw);
    nvat_gpu_evidence_array_free(&evidences, num_evidences);
    nvat_nonce_free(&nonce);
    nvat_gpu_evidence_source_free(&source);
}

TEST(CApiCorimVerifierTest, OcspClientCreateAiaAcceptsRewrites) {
    const char *patterns[] = {"^http://ocsp\\.example\\.com"};
    const char *replacements[] = {"http://ocsp.internal.example.com"};
    nvat_ocsp_client_t client = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_aia(&client, nullptr, nullptr, nullptr,
                                          patterns, replacements, 1, nullptr),
              NVAT_RC_OK);
    ASSERT_NE(client, nullptr);
    nvat_ocsp_client_free(&client);
}

TEST(CApiCorimVerifierTest, OcspClientCreateAiaRejectsBadArgs) {
    nvat_ocsp_client_t client = nullptr;
    EXPECT_EQ(nvat_ocsp_client_create_aia(nullptr, nullptr, nullptr, nullptr,
                                          nullptr, nullptr, 0, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    // num_rewrites > 0 with null arrays.
    EXPECT_EQ(nvat_ocsp_client_create_aia(&client, nullptr, nullptr, nullptr,
                                          nullptr, nullptr, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    // A null entry inside otherwise-valid arrays.
    const char *patterns[] = {nullptr};
    const char *replacements[] = {"replacement"};
    EXPECT_EQ(nvat_ocsp_client_create_aia(&client, nullptr, nullptr, nullptr,
                                          patterns, replacements, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
}

TEST(CApiCorimVerifierTest, OcspClientOptionsValidateAndFree) {
    EXPECT_EQ(nvat_ocsp_client_options_create_default(nullptr),
              NVAT_RC_BAD_ARGUMENT);

    nvat_ocsp_client_options_t options = nullptr;
    ASSERT_EQ(nvat_ocsp_client_options_create_default(&options), NVAT_RC_OK);
    ASSERT_NE(options, nullptr);
    EXPECT_EQ(nvat_ocsp_client_options_set_cert_id_hash_algorithm(
                  nullptr, NVAT_OCSP_CERT_ID_HASH_SHA256),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_ocsp_client_options_set_cert_id_hash_algorithm(
                  options, NVAT_OCSP_CERT_ID_HASH_SHA1),
              NVAT_RC_OK);
    // Not a supported hash algorithm. Keep the value within the enum's valid
    // range (0..3); loading a wider value trips UBSan before validation.
    EXPECT_EQ(nvat_ocsp_client_options_set_cert_id_hash_algorithm(
                  options,
                  static_cast<nvat_ocsp_cert_id_hash_algorithm_t>(3)),
              NVAT_RC_BAD_ARGUMENT);

    nvat_ocsp_client_options_free(&options);
    EXPECT_EQ(options, nullptr);
}

TEST(CApiCorimVerifierTest, OcspCertIdHashAlgorithmParsesNames) {
    nvat_ocsp_cert_id_hash_algorithm_t algorithm{};
    EXPECT_EQ(nvat_ocsp_cert_id_hash_algorithm_from_name("SHA384", &algorithm),
              NVAT_RC_OK);
    EXPECT_EQ(algorithm, NVAT_OCSP_CERT_ID_HASH_SHA384);
    EXPECT_EQ(nvat_ocsp_cert_id_hash_algorithm_from_name("sha-512", &algorithm),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_ocsp_cert_id_hash_algorithm_from_name(nullptr, &algorithm),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_ocsp_cert_id_hash_algorithm_from_name("sha-256", nullptr),
              NVAT_RC_BAD_ARGUMENT);
}

TEST(CApiCorimVerifierTest,
     OcspClientExplicitNullOptionsIgnoreHashEnvironment) {
    ScopedEnvironmentVariable environment("NVAT_OCSP_CERT_ID_HASH_ALGORITHM");
    environment.set("invalid");

    nvat_ocsp_client_t default_client = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_default_with_options(
                  &default_client, nullptr, nullptr, nullptr, nullptr),
              NVAT_RC_OK);
    ASSERT_NE(default_client, nullptr);

    nvat_ocsp_client_t aia_client = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_aia(
                  &aia_client, nullptr, nullptr, nullptr, nullptr, nullptr, 0,
                  nullptr),
              NVAT_RC_OK);
    ASSERT_NE(aia_client, nullptr);

    nvat_ocsp_client_free(&aia_client);
    nvat_ocsp_client_free(&default_client);
}

TEST(CApiCorimVerifierTest,
     OcspClientConstructorsCopyOptions) {
    nvat_ocsp_client_options_t options = nullptr;
    ASSERT_EQ(nvat_ocsp_client_options_create_default(&options), NVAT_RC_OK);
    ASSERT_EQ(nvat_ocsp_client_options_set_cert_id_hash_algorithm(
                  options, NVAT_OCSP_CERT_ID_HASH_SHA384),
              NVAT_RC_OK);

    nvat_ocsp_client_t default_client = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_default_with_options(
                  &default_client, nullptr, nullptr, nullptr, options),
              NVAT_RC_OK);
    nvat_ocsp_client_t aia_client = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_aia(
                  &aia_client, nullptr, nullptr, nullptr, nullptr, nullptr, 0,
                  options),
              NVAT_RC_OK);
    nvat_ocsp_client_options_free(&options);

    auto default_cpp = std::static_pointer_cast<nvattestation::NvHttpOcspClient>(
        *nvat_ocsp_client_to_cpp(default_client));
    auto aia_cpp = std::static_pointer_cast<nvattestation::NvHttpOcspClient>(
        *nvat_ocsp_client_to_cpp(aia_client));
    EXPECT_EQ(default_cpp->cert_id_hash_algorithm(),
              nvattestation::OcspCertIdHashAlgorithm::Sha384);
    EXPECT_EQ(aia_cpp->cert_id_hash_algorithm(),
              nvattestation::OcspCertIdHashAlgorithm::Sha384);

    nvat_ocsp_client_free(&aia_client);
    nvat_ocsp_client_free(&default_client);
}

TEST(CApiCorimVerifierTest, CorimStoreRejectsBadArgs) {
    EXPECT_EQ(nvat_corim_store_create(nullptr, nullptr, nullptr),
              NVAT_RC_BAD_ARGUMENT);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    EXPECT_EQ(nvat_corim_store_add_url_rewrite(store, nullptr, "x"),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_add_url_rewrite(store, "x", nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_add_url_rewrite(nullptr, "x", "y"),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_add_allowed_url_prefix(store, "https://x/"),
              NVAT_RC_OK);
    EXPECT_EQ(nvat_corim_store_add_allowed_url_prefix(store, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_add_allowed_url_prefix(nullptr, "https://x/"),
              NVAT_RC_BAD_ARGUMENT);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, CmwParseErrorsReachCaller) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);

    struct ParseCase {
        const char *input;
        nvat_rc_t code;
        const char *message;
    };
    const ParseCase cases[] = {
        {"not json", NVAT_RC_CMW_JSON_INVALID, "JSON"},
        {"[]", NVAT_RC_CMW_STRUCTURE_INVALID, "object"},
        {"{}", NVAT_RC_CMW_PROFILE_INVALID, "__cmwc_t"},
        {R"({"__cmwc_t":"tag:nvidia.com,2026:verifier-input/profiles/base/pre-1.0.0"})",
         NVAT_RC_CMW_EVIDENCE_MISSING, "evidence"},
        {R"({"__cmwc_t":"tag:nvidia.com,2026:verifier-input/profiles/base/pre-1.0.0","nonce":[]})",
         NVAT_RC_CMW_RECORD_INVALID, "record"},
        {R"({"__cmwc_t":"tag:nvidia.com,2026:verifier-input/profiles/base/pre-1.0.0","nonce":["application/octet-stream","!"]})",
         NVAT_RC_CMW_ENCODING_INVALID, "base64url"},
        {R"({"__cmwc_t":"tag:nvidia.com,2026:verifier-input/profiles/base/pre-1.0.0","nonce":["application/json","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]})",
         NVAT_RC_CMW_MEDIA_TYPE_UNSUPPORTED, "media type"},
        {R"({"__cmwc_t":"tag:nvidia.com,2026:verifier-input/profiles/base/pre-1.0.0","nonce":["application/octet-stream","AA"]})",
         NVAT_RC_CMW_NONCE_INVALID, "32"},
    };
    for (const auto &test : cases) {
        SCOPED_TRACE(test.input);
        const std::string input(test.input);
        nvat_str_t ear_jwt = nullptr;
        nvat_str_t ear_json = nullptr;
        const nvat_rc_t rc = nvat_local_corim_verifier_verify_cmw(
            verifier, reinterpret_cast<const uint8_t *>(input.data()),
            input.size(), NVAT_CMW_FORMAT_JSON, nullptr, nullptr, &ear_jwt,
            &ear_json);
        EXPECT_EQ(rc, test.code);
        EXPECT_NE(std::string(nvat_rc_to_string(rc)).find(test.message),
                  std::string::npos);
        EXPECT_EQ(ear_jwt, nullptr);
        EXPECT_EQ(ear_json, nullptr);
        nvat_str_free(&ear_jwt);
        nvat_str_free(&ear_json);
    }
    nvat_local_corim_verifier_free(&verifier);
}

TEST(CApiCorimVerifierTest, VerifierCreateAndVerifyRejectBadArgs) {
    EXPECT_EQ(nvat_local_corim_verifier_create(nullptr, nullptr, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    nvat_local_corim_verifier_t verifier = nullptr;
    EXPECT_EQ(nvat_local_corim_verifier_create(&verifier, nullptr, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    nvat_corim_store_t null_store = nullptr;
    EXPECT_EQ(nvat_local_corim_verifier_create(&verifier, &null_store, nullptr),
              NVAT_RC_BAD_ARGUMENT);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);
    // create() takes ownership and NULLs the store handle.
    EXPECT_EQ(store, nullptr);

    nvat_str_t result = nullptr;
    const uint8_t one_byte = 0;
    EXPECT_EQ(nvat_local_corim_verifier_verify_cmw(nullptr, &one_byte, 1,
                                                   NVAT_CMW_FORMAT_JSON,
                                                   nullptr, nullptr, nullptr,
                                                   &result),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_verify_cmw(verifier, nullptr, 0,
                                                   NVAT_CMW_FORMAT_JSON,
                                                   nullptr, nullptr, nullptr,
                                                   &result),
              NVAT_RC_BAD_ARGUMENT);

    const std::string garbage = "not json at all";
    nvat_rc_t rc = NVAT_RC_OK;
    nvat_str_t parse_result = verify_cmw(verifier, garbage, rc);
    EXPECT_NE(rc, NVAT_RC_OK);
    nvat_str_free(&parse_result);

    const uint8_t byte = 0;
    EXPECT_EQ(nvat_local_corim_verifier_verify_cmw(verifier, &byte, 1,
                                                   NVAT_CMW_FORMAT_CBOR,
                                                   nullptr, nullptr, nullptr,
                                                   &result),
              NVAT_RC_FEATURE_NOT_ENABLED);
    nvat_str_free(&result);

    EXPECT_EQ(
        nvat_local_corim_verifier_set_verify_revocation(nullptr, true),
        NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(
        nvat_local_corim_verifier_set_verify_rim_signature(nullptr, true),
        NVAT_RC_BAD_ARGUMENT);
    const uint8_t coev = 0xa0;
    EXPECT_EQ(nvat_local_corim_verifier_set_backup_spdm_coev(nullptr, &coev, 1),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_add_backup_rim_locator(nullptr,
                                                               "https://x/"),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(
        nvat_local_corim_verifier_add_backup_rim_locator(verifier, nullptr),
        NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_local_corim_verifier_add_backup_rim_locator(verifier, ""),
              NVAT_RC_BAD_ARGUMENT);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, GpuEvidenceSourceFromJsonFileRejectsMissingFile) {
    nvat_gpu_evidence_source_t source = nullptr;
    EXPECT_NE(nvat_gpu_evidence_source_from_json_file(
                  &source, "testdata/does_not_exist_evidence.json"),
              NVAT_RC_OK);
    EXPECT_EQ(source, nullptr);
    EXPECT_EQ(nvat_gpu_evidence_source_from_json_file(nullptr, "x.json"),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_gpu_evidence_source_from_json_file(&source, nullptr),
              NVAT_RC_BAD_ARGUMENT);
}

TEST(CApiCorimVerifierTest, CmwCollectionCreateRejectsBadArgs) {
    nvat_gpu_evidence_t null_array[] = {nullptr};

    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_create(&nonce, 32), NVAT_RC_OK);

    nvat_cmw_collection_t cmw = nullptr;
    EXPECT_EQ(nvat_cmw_collection_create_from_gpu_evidence(nullptr, null_array,
                                                           1, nonce),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_gpu_evidence(&cmw, nullptr, 0,
                                                           nonce),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_gpu_evidence(&cmw, null_array, 1,
                                                           nullptr),
              NVAT_RC_BAD_ARGUMENT);
    // Non-null array carrying a null element.
    EXPECT_EQ(nvat_cmw_collection_create_from_gpu_evidence(&cmw, null_array, 1,
                                                           nonce),
              NVAT_RC_BAD_ARGUMENT);

    nvat_nonce_free(&nonce);
}

TEST(CApiCorimVerifierTest, CmwCollectionSerializeRejectsBadArgs) {
    nvat_str_t out = nullptr;
    EXPECT_EQ(nvat_cmw_collection_serialize(nullptr, NVAT_CMW_FORMAT_JSON, &out),
              NVAT_RC_BAD_ARGUMENT);
}

TEST(CApiCorimVerifierTest, CmwCollectionFromSpdmTranscriptRoundTrips) {
    const std::string transcript = "raw-spdm-transcript-bytes";
    const std::string cert_pem =
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    const auto *transcript_bytes =
        reinterpret_cast<const uint8_t *>(transcript.data());
    const auto *cert_bytes = reinterpret_cast<const uint8_t *>(cert_pem.data());

    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_create(&nonce, 32), NVAT_RC_OK);

    // With a nonce.
    nvat_cmw_collection_t cmw = nullptr;
    ASSERT_EQ(nvat_cmw_collection_create_from_spdm_transcript(
                  &cmw, "device_0", transcript_bytes, transcript.size(),
                  cert_bytes, cert_pem.size(), nonce),
              NVAT_RC_OK);

    nvat_str_t serialized = nullptr;
    ASSERT_EQ(
        nvat_cmw_collection_serialize(cmw, NVAT_CMW_FORMAT_JSON, &serialized),
        NVAT_RC_OK);
    char *data = nullptr;
    ASSERT_EQ(nvat_str_get_data(serialized, &data), NVAT_RC_OK);
    nlohmann::json parsed =
        nlohmann::json::parse(data, nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.contains("__cmwc_t"));

    // A non-null collection with a null output pointer is rejected.
    EXPECT_EQ(nvat_cmw_collection_serialize(cmw, NVAT_CMW_FORMAT_JSON, nullptr),
              NVAT_RC_BAD_ARGUMENT);

    nvat_str_free(&serialized);
    nvat_cmw_collection_free(&cmw);

    // Without a nonce (optional-nonce branch).
    nvat_cmw_collection_t cmw_no_nonce = nullptr;
    ASSERT_EQ(nvat_cmw_collection_create_from_spdm_transcript(
                  &cmw_no_nonce, "device_0", transcript_bytes, transcript.size(),
                  cert_bytes, cert_pem.size(), nullptr),
              NVAT_RC_OK);
    nvat_cmw_collection_free(&cmw_no_nonce);

    nvat_nonce_free(&nonce);
}

TEST(CApiCorimVerifierTest, CmwCollectionFromSpdmTranscriptRejectsBadArgs) {
    const uint8_t bytes[] = {0x01};
    nvat_cmw_collection_t cmw = nullptr;
    EXPECT_EQ(nvat_cmw_collection_create_from_spdm_transcript(
                  nullptr, "d", bytes, 1, bytes, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_spdm_transcript(
                  &cmw, nullptr, bytes, 1, bytes, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_spdm_transcript(
                  &cmw, "d", nullptr, 0, bytes, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_spdm_transcript(
                  &cmw, "d", bytes, 1, nullptr, 0, nullptr),
              NVAT_RC_BAD_ARGUMENT);
}

static std::vector<uint8_t> read_binary_fixture(const char *path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
}

TEST(CApiCorimVerifierTest, CmwCollectionFromEatRoundTrips) {
    const std::vector<uint8_t> token =
        read_binary_fixture("testdata/sample_rims/eat/full_signed.cbor");
    ASSERT_FALSE(token.empty());

    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_create(&nonce, 32), NVAT_RC_OK);

    nvat_cmw_collection_t cmw = nullptr;
    ASSERT_EQ(nvat_cmw_collection_create_from_eat(
                  &cmw, "device_0", token.data(), token.size(), nonce),
              NVAT_RC_OK);

    nvat_str_t serialized = nullptr;
    ASSERT_EQ(
        nvat_cmw_collection_serialize(cmw, NVAT_CMW_FORMAT_JSON, &serialized),
        NVAT_RC_OK);
    char *data = nullptr;
    ASSERT_EQ(nvat_str_get_data(serialized, &data), NVAT_RC_OK);
    nlohmann::json parsed =
        nlohmann::json::parse(data, nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(parsed.is_discarded());
    ASSERT_TRUE(parsed.contains("device_0"));
    EXPECT_EQ(parsed["device_0"]["evidence"][0], "application/eat+cwt");

    nvat_str_free(&serialized);
    nvat_cmw_collection_free(&cmw);

    nvat_cmw_collection_t cmw_no_nonce = nullptr;
    ASSERT_EQ(nvat_cmw_collection_create_from_eat(&cmw_no_nonce, "device_0",
                                                  token.data(), token.size(),
                                                  nullptr),
              NVAT_RC_OK);
    nvat_cmw_collection_free(&cmw_no_nonce);

    nvat_nonce_free(&nonce);
}

TEST(CApiCorimVerifierTest, CmwCollectionFromEatRejectsBadArgs) {
    const uint8_t bytes[] = {0x01};
    nvat_cmw_collection_t cmw = nullptr;
    EXPECT_EQ(nvat_cmw_collection_create_from_eat(nullptr, "d", bytes, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_eat(&cmw, nullptr, bytes, 1, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_eat(&cmw, "d", nullptr, 0, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_cmw_collection_create_from_eat(&cmw, "d", bytes, 0, nullptr),
              NVAT_RC_BAD_ARGUMENT);
}

TEST(CApiCorimVerifierTest, VerifierBackupSettersAcceptInputs) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);

    const uint8_t coev[] = {0xa0};  // Minimal valid CBOR: empty map.
    EXPECT_EQ(nvat_local_corim_verifier_set_backup_spdm_coev(verifier, coev, 1),
              NVAT_RC_OK);
    EXPECT_EQ(nvat_local_corim_verifier_add_backup_rim_locator(
                  verifier, "https://example.com/rim1"),
              NVAT_RC_OK);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

// The algorithms select which digests of the CMW input land in
// ear_nvidia_inputs; an empty list disables the computation entirely.
TEST(CApiCorimVerifierTest, SetDefaultHashAlgorithmsAcceptsEveryAlgorithm) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);

    const nvat_hash_algorithm_t algs[] = {NVAT_HASH_ALGORITHM_SHA256,
                                          NVAT_HASH_ALGORITHM_SHA384,
                                          NVAT_HASH_ALGORITHM_SHA512};
    EXPECT_EQ(nvat_local_corim_verifier_set_default_hash_algorithms(verifier,
                                                                    algs, 3),
              NVAT_RC_OK);
    // Empty list is the documented way to switch the digests off.
    EXPECT_EQ(nvat_local_corim_verifier_set_default_hash_algorithms(verifier,
                                                                    nullptr, 0),
              NVAT_RC_OK);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, SetDefaultHashAlgorithmsRejectsBadArgs) {
    const nvat_hash_algorithm_t algs[] = {NVAT_HASH_ALGORITHM_SHA256};
    EXPECT_EQ(nvat_local_corim_verifier_set_default_hash_algorithms(nullptr,
                                                                    algs, 1),
              NVAT_RC_BAD_ARGUMENT);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);

    EXPECT_EQ(nvat_local_corim_verifier_set_default_hash_algorithms(verifier,
                                                                    nullptr, 2),
              NVAT_RC_BAD_ARGUMENT);
    // Not an IANA Named Information registry ID the SDK maps. Must stay within
    // the enum's value range (0..15 for enumerators up to 8): loading a wider
    // value through the enum type is undefined behaviour and trips UBSan.
    const nvat_hash_algorithm_t unknown[] = {
        static_cast<nvat_hash_algorithm_t>(9)};
    EXPECT_EQ(nvat_local_corim_verifier_set_default_hash_algorithms(verifier,
                                                                    unknown, 1),
              NVAT_RC_BAD_ARGUMENT);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, VerifyCmwDiscardsResultAndRejectsEmptyInput) {
    std::string cmw;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw),
              nvattestation::Error::Ok);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false),
              NVAT_RC_OK);

    // Both out_ear_jwt/out_ear_json null discards the EAR result.
    EXPECT_EQ(nvat_local_corim_verifier_verify_cmw(
                  verifier, reinterpret_cast<const uint8_t *>(cmw.data()),
                  cmw.size(), NVAT_CMW_FORMAT_JSON, nullptr, nullptr, nullptr,
                  nullptr),
              NVAT_RC_OK);

    // Non-null pointer with zero length reaches the parser and fails there.
    const uint8_t byte = 0;
    nvat_str_t result = nullptr;
    EXPECT_NE(nvat_local_corim_verifier_verify_cmw(
                  verifier, &byte, 0, NVAT_CMW_FORMAT_JSON, nullptr, nullptr,
                  nullptr, &result),
              NVAT_RC_OK);
    nvat_str_free(&result);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, VerifyCmwNullSigningOptionsProducesUnsignedEar) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false), NVAT_RC_OK);

    std::string cmw;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw), nvattestation::Error::Ok);

    nvat_str_t result = nullptr;
    nvat_rc_t rc = nvat_local_corim_verifier_verify_cmw(
        verifier, reinterpret_cast<const uint8_t *>(cmw.data()), cmw.size(),
        NVAT_CMW_FORMAT_JSON, nullptr, nullptr, &result, nullptr);
    ASSERT_EQ(rc, NVAT_RC_OK);
    ASSERT_NE(result, nullptr);
    char *data = nullptr;
    ASSERT_EQ(nvat_str_get_data(result, &data), NVAT_RC_OK);
    auto decoded = jwt::decode<jwt::traits::nlohmann_json>(std::string(data));
    EXPECT_EQ(decoded.get_algorithm(), "none");
    nvat_str_free(&result);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, VerifyCmwOptionsRequestIdValidated) {
    EXPECT_EQ(nvat_verify_cmw_options_create(nullptr), NVAT_RC_BAD_ARGUMENT);
    nvat_verify_cmw_options_t options = nullptr;
    ASSERT_EQ(nvat_verify_cmw_options_create(&options), NVAT_RC_OK);

    EXPECT_EQ(nvat_verify_cmw_options_set_request_id(nullptr, "abc"),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_verify_cmw_options_set_request_id(options, nullptr),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_verify_cmw_options_set_request_id(options, ""),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_verify_cmw_options_set_request_id(options, "a b"),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_verify_cmw_options_set_request_id(options, "abc\r\nx-evil: 1"),
              NVAT_RC_BAD_ARGUMENT);
    const std::string too_long(nvattestation::MAX_REQUEST_ID_LEN + 1, 'a');
    EXPECT_EQ(nvat_verify_cmw_options_set_request_id(options, too_long.c_str()),
              NVAT_RC_BAD_ARGUMENT);
    const std::string longest(nvattestation::MAX_REQUEST_ID_LEN, 'a');
    EXPECT_EQ(nvat_verify_cmw_options_set_request_id(options, longest.c_str()),
              NVAT_RC_OK);
    EXPECT_EQ(nvat_verify_cmw_options_set_request_id(
                  options, "3f2b9c1e-7a4d-4e8a-9b1c-2d3e4f5a6b7c"),
              NVAT_RC_OK);

    nvat_verify_cmw_options_free(&options);
    EXPECT_EQ(options, nullptr);
    nvat_verify_cmw_options_free(&options);
}

TEST(CApiCorimVerifierTest, VerifyCmwRequestIdScopedToCall) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false), NVAT_RC_OK);
    nvat_verify_cmw_options_t options = nullptr;
    ASSERT_EQ(nvat_verify_cmw_options_create(&options), NVAT_RC_OK);
    ASSERT_EQ(nvat_verify_cmw_options_set_request_id(options, "req-123"), NVAT_RC_OK);

    std::string cmw;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw), nvattestation::Error::Ok);

    nvat_str_t result = nullptr;
    nvat_rc_t rc = nvat_local_corim_verifier_verify_cmw(
        verifier, reinterpret_cast<const uint8_t *>(cmw.data()), cmw.size(),
        NVAT_CMW_FORMAT_JSON, nullptr, options, &result, nullptr);
    EXPECT_EQ(rc, NVAT_RC_OK);
    // The id must not leak to later work on this thread.
    EXPECT_TRUE(nvattestation::current_request_id().empty());
    nvat_str_free(&result);

    nvat_verify_cmw_options_free(&options);
    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, VerifyCmwSigningOptionsProducesSignedEar) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr), NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false), NVAT_RC_OK);

    std::string cmw;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw), nvattestation::Error::Ok);
    std::string private_key_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/ec_p384_private.pem", private_key_pem),
              nvattestation::Error::Ok);

    nvat_detached_eat_options_t options = nullptr;
    ASSERT_EQ(nvat_detached_eat_options_create(&options, private_key_pem.c_str(), "test-issuer", "test-kid"),
              NVAT_RC_OK);

    nvat_str_t result = nullptr;
    nvat_str_t result_json = nullptr;
    nvat_rc_t rc = nvat_local_corim_verifier_verify_cmw(
        verifier, reinterpret_cast<const uint8_t *>(cmw.data()), cmw.size(),
        NVAT_CMW_FORMAT_JSON, options, nullptr, &result, &result_json);
    ASSERT_EQ(rc, NVAT_RC_OK);
    ASSERT_NE(result, nullptr);
    char *data = nullptr;
    ASSERT_EQ(nvat_str_get_data(result, &data), NVAT_RC_OK);
    auto decoded = jwt::decode<jwt::traits::nlohmann_json>(std::string(data));
    EXPECT_EQ(decoded.get_algorithm(), "ES384");
    nvat_str_free(&result);

    // out_ear_json carries the same claims as unsigned JSON, no JWT decode needed.
    ASSERT_NE(result_json, nullptr);
    char *json_data = nullptr;
    ASSERT_EQ(nvat_str_get_data(result_json, &json_data), NVAT_RC_OK);
    nlohmann::json parsed =
        nlohmann::json::parse(std::string(json_data), nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.contains("submods"));
    EXPECT_TRUE(parsed.contains("ear_status"));
    nvat_str_free(&result_json);

    nvat_detached_eat_options_free(&options);
    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, StoreAndVerifierAcceptInjectedDependencies) {
    nvat_http_options_t http = nullptr;
    ASSERT_EQ(nvat_http_options_create_default(&http), NVAT_RC_OK);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, "service-key", http), NVAT_RC_OK);

    const char *patterns[] = {"^http://a"};
    const char *replacements[] = {"http://b"};
    nvat_ocsp_client_t ocsp = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_aia(&ocsp, nullptr, nullptr, http,
                                          patterns, replacements, 1, nullptr),
              NVAT_RC_OK);

    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, ocsp),
              NVAT_RC_OK);

    nvat_local_corim_verifier_free(&verifier);
    nvat_ocsp_client_free(&ocsp);
    nvat_corim_store_free(&store);
    nvat_http_options_free(&http);
}

TEST(CApiCorimVerifierTest, VerifierSettingsAcceptToggles) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);

    EXPECT_EQ(nvat_local_corim_verifier_set_verify_rim_signature(verifier, true),
              NVAT_RC_OK);
    EXPECT_EQ(
        nvat_local_corim_verifier_set_verify_rim_signature(verifier, false),
        NVAT_RC_OK);
    EXPECT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, true),
              NVAT_RC_OK);
    EXPECT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false),
              NVAT_RC_OK);

    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

// The C enum values are IANA NI registry IDs; this pins the C-to-C++ mapping
// so a renumbering cannot silently emit the wrong algorithm.
TEST(CApiCorimVerifierTest, InputHashAlgorithmsSelectEmittedDigests) {
    std::string cmw;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw),
              nvattestation::Error::Ok);

    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);
    ASSERT_EQ(nvat_local_corim_verifier_set_verify_revocation(verifier, false),
              NVAT_RC_OK);

    const nvat_hash_algorithm_t algs[] = {NVAT_HASH_ALGORITHM_SHA384,
                                          NVAT_HASH_ALGORITHM_SHA512};
    ASSERT_EQ(
        nvat_local_corim_verifier_set_default_hash_algorithms(verifier, algs, 2),
        NVAT_RC_OK);

    nvat_rc_t rc = NVAT_RC_OK;
    nvat_str_t result = verify_cmw(verifier, cmw, rc);
    EXPECT_EQ(rc, NVAT_RC_OK);
    nlohmann::json parsed = result_json(result);
    ASSERT_TRUE(parsed.contains("ear_nvidia_inputs"));
    const auto& digests = parsed["ear_nvidia_inputs"]["digests"];
    ASSERT_EQ(digests.size(), 2U);
    EXPECT_EQ(digests[0]["alg"].get<std::string>(), "sha-384");
    EXPECT_EQ(digests[1]["alg"].get<std::string>(), "sha-512");

    nvat_str_free(&result);
    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest, EnableInMemoryCacheOnStore) {
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    ASSERT_NE(store, nullptr);

    EXPECT_EQ(nvat_corim_store_enable_in_memory_cache(store, 1024 * 1024, 3600),
              NVAT_RC_OK);

    EXPECT_NE(nvat_corim_store_enable_in_memory_cache(store, 0, 3600), NVAT_RC_OK);
    EXPECT_NE(nvat_corim_store_enable_in_memory_cache(store, 1024 * 1024, -1), NVAT_RC_OK);

    nvat_corim_store_free(&store);
    EXPECT_EQ(store, nullptr);
}

TEST(CApiCorimVerifierTest, EnableNegativeCacheOnStore) {
    // Check C argument validation, zero-TTL disabling and transfer to the verifier.
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    EXPECT_EQ(nvat_corim_store_enable_negative_cache(store, 1048576, 600),
              NVAT_RC_OK);
    EXPECT_EQ(nvat_corim_store_enable_negative_cache(nullptr, 1048576, 600),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_enable_negative_cache(store, 0, 600),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_enable_negative_cache(store, 1048576, -1),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_enable_negative_cache(store, 0, 0),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_enable_negative_cache(store, 1048576, 0),
              NVAT_RC_OK);
    EXPECT_EQ(nvat_corim_store_enable_in_memory_cache(store, 1048576, 3600),
              NVAT_RC_OK);
    EXPECT_EQ(nvat_corim_store_enable_negative_cache(store, 1048576, 600),
              NVAT_RC_OK);
    nvat_local_corim_verifier_t verifier = nullptr;
    EXPECT_EQ(nvat_local_corim_verifier_create(&verifier, &store, nullptr),
              NVAT_RC_OK);
    EXPECT_EQ(store, nullptr);
    nvat_local_corim_verifier_free(&verifier);
    nvat_corim_store_free(&store);
}

TEST(CApiCorimVerifierTest,
     NegativeCacheInvalidSettingsPreserveEntriesAndZeroTtlDisables) {
    // Seed a marker for a closed local port: a cache hit and a live fetch return different errors.
    nvat_corim_store_t store = nullptr;
    ASSERT_EQ(nvat_corim_store_create(&store, nullptr, nullptr), NVAT_RC_OK);
    auto *cpp = nvat_corim_store_to_cpp(store);
    const std::string raw =
        "https://rim.attestation.nvidia.com/cache-validation";
    const std::string effective = "http://127.0.0.1:9/rim";
    ASSERT_EQ(cpp->add_url_rewrite(raw, effective), nvattestation::Error::Ok);
    auto cache = std::make_shared<nvattestation::NvCache>(
        std::make_shared<nvattestation::NvCacheOptions>(1024, 600));
    ASSERT_EQ(cache->put(effective, std::make_shared<bool>(true), 512),
              nvattestation::Error::Ok);
    cpp->set_negative_cache(cache);
    // Invalid configuration must leave the seeded marker usable.
    EXPECT_EQ(nvat_corim_store_enable_negative_cache(store, 0, 600),
              NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_corim_store_enable_negative_cache(store, 1024, -1),
              NVAT_RC_BAD_ARGUMENT);
    std::vector<uint8_t> bytes;
    EXPECT_EQ(cpp->fetch(raw, bytes), nvattestation::Error::RimNotFound);
    // Disabling removes the cache, so the next fetch exposes the connection failure.
    EXPECT_EQ(nvat_corim_store_enable_negative_cache(store, 1024, 0),
              NVAT_RC_OK);
    EXPECT_NE(cpp->fetch(raw, bytes), nvattestation::Error::RimNotFound);
    nvat_corim_store_free(&store);
}
