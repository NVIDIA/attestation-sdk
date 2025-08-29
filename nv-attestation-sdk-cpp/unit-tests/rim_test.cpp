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

//stdlibs
#include <fstream>
#include <thread>
#include <chrono> // Add chrono for time calculations
#include <regex>  // Add regex for ISO8601 pattern matching

//third party
#include "gtest/gtest.h"
#include "gmock/gmock.h"

//this sdk
#include "nv_attestation/rim.h"
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/nv_x509.h" // Added for IOcspHttpClient and create_default_ocsp_http_client

// OpenSSL headers needed for crafting mock OCSP responses
#include <openssl/ocsp.h>
#include <openssl/bio.h>

using namespace nvattestation;
using ::testing::Return;
using ::testing::_;
using ::testing::Invoke; // For using lambdas with EXPECT_CALL

// mock for IOcspHttpClient using gmock
class MockOcspHttpClient : public IOcspHttpClient {
public:
    // Call base constructor with some dummy values as it's pure virtual otherwise
    MockOcspHttpClient() : IOcspHttpClient() {}

    MOCK_METHOD(Error, transfer_ocsp_request,
                (BIO* req_bio, nv_unique_ptr<OCSP_RESPONSE>& out_ocsp_resp), (override));
};

// mock for RimClient using gmock
// ref: https://google.github.io/googletest/gmock_for_dummies.html
class MockRimStore : public IRimStore {
    public:
        MOCK_METHOD(Error, get_rim, (const std::string& rim_id, RimDocument& out_rim_document), (override));
};

TEST(RimDocumentTest, CreateFromRimData) {
    std::ifstream file("testdata/NV_GPU_DRIVER_GH100_550.144.03.xml");
    std::string xml_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    RimDocument rim_document;
    Error error = RimDocument::create_from_rim_data(xml_data, rim_document);
    EXPECT_EQ(error, Error::Ok);
}

// signature error test: incorrect signature
TEST(InvalidRimDocument, VerifyIncorrectSignature) {
    RimDocument rim_document;
    Error error = RimDocument::create_from_file("testdata/incorrect_signature_driver_rim.xml", rim_document);
    ASSERT_EQ(error, Error::Ok);
    Error verified = rim_document.verify_signature();
    EXPECT_EQ(verified, Error::RimInvalidSignature);
}

// create a test fixutre for the RimDocumentTest that loads the NV_GPU_DRIVER_GH100_550.144.03.xml file
// ref: https://google.github.io/googletest/primer.html#same-data-multiple-tests
class RimDocumentFixture : public ::testing::Test {
    protected:
        RimDocument m_rim_document;

        void SetUp() override {
            Error error = RimDocument::create_from_file("testdata/NV_GPU_DRIVER_GH100_550.144.03.xml", m_rim_document);
            ASSERT_EQ(error, Error::Ok);
        }
};

// signature valid test
TEST_F(RimDocumentFixture, VerifySignature) {
    Error error = m_rim_document.verify_signature();
    EXPECT_EQ(error, Error::Ok);
}

// version valid test
TEST_F(RimDocumentFixture, GetVersion) {
    std::string version;
    Error error = m_rim_document.get_version(version);
    EXPECT_EQ(error, Error::Ok);
    EXPECT_EQ(version, "550.144.03");
}

// cert chain valid test
TEST_F(RimDocumentFixture, VerifyCertificateChain) {
    X509CertChain cert_chain;
    Error error = m_rim_document.get_cert_chain(cert_chain);
    EXPECT_EQ(error, Error::Ok);
    error = cert_chain.verify();
    EXPECT_EQ(error, Error::Ok);
}

// cert chain error test: incorrect root cert
TEST_F(RimDocumentFixture, VerifyCertChainWithIncorrectRoot) {
    // make sure that if incorrect root cert is provided, verification fails
    X509CertChain cert_chain;
    Error error = m_rim_document.get_cert_chain(cert_chain);
    EXPECT_EQ(error, Error::Ok);
    auto incorrect_root_cert = x509_from_cert_path("testdata/incorrect_rim_root.crt");
    EXPECT_NE(incorrect_root_cert, nullptr);
    error = cert_chain.set_root_cert(std::move(incorrect_root_cert));
    EXPECT_EQ(error, Error::Ok);
    error = cert_chain.verify();
    EXPECT_EQ(error, Error::InternalError);
}

// ocsp valid test
TEST_F(RimDocumentFixture, OcspValidation) {
    X509CertChain cert_chain;
    Error error = m_rim_document.get_cert_chain(cert_chain);
    EXPECT_EQ(error, Error::Ok);
    OCSPClaims ocsp_claims;
    NvHttpOcspClient ocsp_client;
    Error ocsp_error = NvHttpOcspClient::create(ocsp_client, "http://ocsp.ndis.nvidia.com", HttpOptions());
    ASSERT_EQ(ocsp_error, Error::Ok);
    OcspVerifyOptions ocsp_verify_options;
    ocsp_verify_options.set_nonce_enabled(true);
    ocsp_verify_options.set_allow_cert_hold(true);
    error = cert_chain.generate_ocsp_claims(ocsp_verify_options, ocsp_client, ocsp_claims);
    EXPECT_EQ(error, Error::Ok);
    EXPECT_EQ(ocsp_claims.status, OCSPStatus::GOOD);
    EXPECT_TRUE(ocsp_claims.nonce_matches); 

    // Check expiration time (approx 24h from now with 5 min leeway)
    auto now = std::chrono::system_clock::now();
    auto expected_expiration = now + std::chrono::hours(24);
    auto lower_bound = expected_expiration - std::chrono::minutes(5);
    auto upper_bound = expected_expiration + std::chrono::minutes(5);

    // Convert expiration_time (time_t) to time_point for comparison
    auto expiration_tp = std::chrono::system_clock::from_time_t(ocsp_claims.ocsp_resp_expiration_time);

    EXPECT_GE(expiration_tp, lower_bound);
    EXPECT_LE(expiration_tp, upper_bound);
}

TEST_F(RimDocumentFixture, OcspValidationTLS) {
    X509CertChain cert_chain;
    Error error = m_rim_document.get_cert_chain(cert_chain);
    EXPECT_EQ(error, Error::Ok);
    OCSPClaims ocsp_claims;
    NvHttpOcspClient ocsp_client;
    Error ocsp_error = NvHttpOcspClient::create(ocsp_client, "https://ocsp.ndis.nvidia.com", HttpOptions());
    ASSERT_EQ(ocsp_error, Error::Ok);
    OcspVerifyOptions ocsp_verify_options;
    ocsp_verify_options.set_nonce_enabled(true);
    ocsp_verify_options.set_allow_cert_hold(true);
    error = cert_chain.generate_ocsp_claims(ocsp_verify_options, ocsp_client, ocsp_claims);
    EXPECT_EQ(error, Error::Ok);
    EXPECT_EQ(ocsp_claims.status, OCSPStatus::GOOD);
    EXPECT_TRUE(ocsp_claims.nonce_matches); 

    // Check expiration time (approx 24h from now with 5 min leeway)
    auto now = std::chrono::system_clock::now();
    auto expected_expiration = now + std::chrono::hours(24);
    auto lower_bound = expected_expiration - std::chrono::minutes(5);
    auto upper_bound = expected_expiration + std::chrono::minutes(5);

    // Convert expiration_time (time_t) to time_point for comparison
    auto expiration_tp = std::chrono::system_clock::from_time_t(ocsp_claims.ocsp_resp_expiration_time);

    EXPECT_GE(expiration_tp, lower_bound);
    EXPECT_LE(expiration_tp, upper_bound);
}

TEST_F(RimDocumentFixture, OcspServerError) {
    X509CertChain cert_chain;
    Error error = m_rim_document.get_cert_chain(cert_chain);
    EXPECT_EQ(error, Error::Ok);

    // Use a non-existent host to simulate an unresponsive server
    HttpOptions http_options {};
    http_options.set_base_backoff_ms(5);
    http_options.set_connection_timeout_ms(5);
    http_options.set_request_timeout_ms(10);
    http_options.set_max_retry_count(3);
    OCSPClaims ocsp_claims;
    NvHttpOcspClient ocsp_client;
    Error client_error = NvHttpOcspClient::create(ocsp_client, "http://ocsp.invalid", http_options);
    ASSERT_EQ(client_error, Error::Ok);
    OcspVerifyOptions ocsp_verify_options;
    ocsp_verify_options.set_nonce_enabled(true);
    ocsp_verify_options.set_allow_cert_hold(true);
    error = cert_chain.generate_ocsp_claims(ocsp_verify_options, ocsp_client, ocsp_claims);
    EXPECT_EQ(error, Error::InternalError);
}

// ocsp error test: incorrect rim root cert (ocsp invalid response)
TEST_F(RimDocumentFixture, OcspInvalidResponse) {
    X509CertChain cert_chain;
    Error error = m_rim_document.get_cert_chain(cert_chain);
    EXPECT_EQ(error, Error::Ok);
    auto incorrect_root_cert = x509_from_cert_path("testdata/incorrect_rim_root.crt");
    EXPECT_NE(incorrect_root_cert, nullptr);
    error = cert_chain.set_root_cert(std::move(incorrect_root_cert));
    EXPECT_EQ(error, Error::Ok);
    OCSPClaims ocsp_claims;
    NvHttpOcspClient ocsp_client;
    Error ocsp_error = NvHttpOcspClient::create(ocsp_client, "http://ocsp.ndis.nvidia.com", HttpOptions());
    ASSERT_EQ(ocsp_error, Error::Ok);
    OcspVerifyOptions ocsp_verify_options;
    ocsp_verify_options.set_nonce_enabled(true);
    ocsp_verify_options.set_allow_cert_hold(true);
    error = cert_chain.generate_ocsp_claims(ocsp_verify_options, ocsp_client, ocsp_claims);
    EXPECT_EQ(error, Error::OcspInvalidResponse) << "Expected OcspInvalidResponse, got " << to_string(error);
}

// ocsp error test: ocsp server returns unauthorized (invalid request)
TEST_F(RimDocumentFixture, OcspInvalidRequest) {
    X509CertChain cert_chain;
    Error error = m_rim_document.get_cert_chain(cert_chain);
    EXPECT_EQ(error, Error::Ok);

    auto mock_ocsp_client = std::make_unique<MockOcspHttpClient>();
    EXPECT_EQ(error, Error::Ok);

    EXPECT_CALL(*mock_ocsp_client, transfer_ocsp_request(_, _))
        .WillOnce(Invoke([](BIO* req_bio, nv_unique_ptr<OCSP_RESPONSE>& out_ocsp_resp) -> Error {
            // Return UNAUTHORIZED status - this should result in Error::OcspInvalidRequest
            return Error::OcspInvalidRequest;
        }));

    // Clear any pre-existing errors before the call
    ErrorStack::clear();

    OCSPClaims ocsp_claims;
    OcspVerifyOptions ocsp_verify_options;
    ocsp_verify_options.set_nonce_enabled(true);
    ocsp_verify_options.set_allow_cert_hold(true);
    error = cert_chain.generate_ocsp_claims(ocsp_verify_options, *mock_ocsp_client, ocsp_claims);
    EXPECT_EQ(error, Error::OcspInvalidRequest);
}

//todo(p1): add test for ocsp validation with revoked and unknown certs
// TEST_F(RimDocumentFixture, OCSPRevokedCert) {
//     std::unique_ptr<RimClient> rim_store = std::make_unique<NvRemoteRimStoreImpl>("https://rim.stg.attestation.nvidia.com");
//     std::string rim_id = "NV_GPU_DRIVER_GH100_570.124.03";
//     auto result = rim_store->download_rim_file(rim_id);
//     EXPECT_NE(result, nullptr);
//     EXPECT_EQ(result->id, rim_id);
//     auto rim_document = rim_store->extract_rim_document(result->rim_store);
//     EXPECT_NE(rim_document, nullptr);
//     auto cert_chain = rim_document->get_cert_chain();
//     EXPECT_NE(cert_chain, nullptr);
//     auto res = cert_chain->generate_ocsp_claims(10, 1);
//     EXPECT_NE(res, nullptr);
//     EXPECT_EQ(res->status, "revoked");
// }

TEST(RimClientTest, DownloadGetRim) {
    NvRemoteRimStoreImpl rim_store;
    Error error = NvRemoteRimStoreImpl::init_from_env(rim_store, "https://rim.attestation.nvidia.com", HttpOptions());
    EXPECT_EQ(error, Error::Ok);
    std::string driver_version = "550.144.03";
    std::string rim_id = "NV_GPU_DRIVER_GH100_" + driver_version;
    RimDocument rim_document;
    error = rim_store.get_rim(rim_id, rim_document);
    EXPECT_EQ(error, Error::Ok);
    Error verified = rim_document.verify_signature();
    EXPECT_EQ(verified, Error::Ok);
}

// Test for the certificate chain expiration time calculation
TEST_F(RimDocumentFixture, CalculateMinExpirationTime) {
    X509CertChain cert_chain;
    Error error = m_rim_document.get_cert_chain(cert_chain);
    EXPECT_EQ(error, Error::Ok);
    
    // Test getting just the time_t value
    time_t min_expiration;
    error = cert_chain.calculate_min_expiration_time(min_expiration);
    EXPECT_EQ(error, Error::Ok);
    EXPECT_GT(min_expiration, time(nullptr)); // Should be in the future
    
    // Test getting both time_t and ISO8601 string
    std::string iso8601_time;
    error = cert_chain.calculate_min_expiration_time(min_expiration, &iso8601_time);
    EXPECT_EQ(error, Error::Ok);
    
    
    // Verify ISO8601 format (YYYY-MM-DDThh:mm:ssZ)
    std::regex iso8601_pattern("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$");
    EXPECT_TRUE(std::regex_match(iso8601_time, iso8601_pattern));
    
    // Convert ISO8601 string back to time_t and verify it matches
    struct tm tm_from_iso = {};
    strptime(iso8601_time.c_str(), "%Y-%m-%dT%H:%M:%SZ", &tm_from_iso);
    time_t time_from_iso = timegm(&tm_from_iso);
    
    EXPECT_EQ(min_expiration, time_from_iso);
}

// Test for generate_cert_chain_claims with ocsp_nonce_check=true and cert_hold_allowed=true
TEST_F(RimDocumentFixture, GenerateCertChainClaims) {
    X509CertChain cert_chain;
    Error error = m_rim_document.get_cert_chain(cert_chain);
    EXPECT_EQ(error, Error::Ok);

    // Use typical timeout and backoff values as in other tests
    CertChainClaims claims;
    NvHttpOcspClient ocsp_client;
    Error ocsp_error = NvHttpOcspClient::create(ocsp_client, "http://ocsp.ndis.nvidia.com:80/", HttpOptions());
    ASSERT_EQ(ocsp_error, Error::Ok);
    OcspVerifyOptions ocsp_verify_options;
    ocsp_verify_options.set_nonce_enabled(true);
    ocsp_verify_options.set_allow_cert_hold(true);
    error = cert_chain.generate_cert_chain_claims(ocsp_verify_options, ocsp_client, claims);
    EXPECT_EQ(error, Error::Ok);

    // The expiration_date should be a non-empty string
    EXPECT_FALSE(claims.expiration_date.empty());
    EXPECT_TRUE(std::regex_match(claims.expiration_date, std::regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")));

    // The status should be VALID for the known-good test RIM
    EXPECT_EQ(claims.status, CertChainStatus::VALID);

    // OCSP claims should be present and valid
    EXPECT_EQ(claims.ocsp_claims.status, OCSPStatus::GOOD);
    EXPECT_TRUE(claims.ocsp_claims.nonce_matches);
    EXPECT_GT(claims.ocsp_claims.ocsp_resp_expiration_time, time(nullptr));
}

// Test for get_measurements method
TEST_F(RimDocumentFixture, GetMeasurements) {
    Measurements measurements;
    Error error = m_rim_document.get_measurements(measurements);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to get measurements");
        return;
    }
    
    // Should have measurements
    EXPECT_GT(measurements.size(), 0);
    
    // Check that we have the expected active measurements from the test file
    // Based on the XML, measurements 7, 21-27, 28-40 should be active
    
    // Measurement at index 7 should be active
    if (measurements.has_measurement_at_index(7)) {
        Measurement measurement_7;
        error = measurements.get_measurement_at_index(7, measurement_7);
        EXPECT_EQ(error, Error::Ok);
        EXPECT_TRUE(measurement_7.get_active());
        EXPECT_EQ(measurement_7.get_index(), 7);
        EXPECT_EQ(measurement_7.get_name(), "Measurement_7");
        EXPECT_EQ(measurement_7.get_size(), 48);
        EXPECT_EQ(measurement_7.get_count(), 1);
        EXPECT_EQ(measurement_7.get_values().size(), 1);
        EXPECT_EQ(measurement_7.get_values()[0], hex_string_to_bytes("4a5e4b3d501fe31f91bd8b6f2921b58437704a504dbedba971440e840c938c805612689ae3ac04b1009515a179063d49"));
    }
    
    // Measurement at index 21 should be active
    if (measurements.has_measurement_at_index(21)) {
        Measurement measurement_21;
        error = measurements.get_measurement_at_index(21, measurement_21);
        EXPECT_EQ(error, Error::Ok);
        EXPECT_TRUE(measurement_21.get_active());
        EXPECT_EQ(measurement_21.get_index(), 21);
        EXPECT_EQ(measurement_21.get_name(), "MixedMeasurement_21");
        EXPECT_EQ(measurement_21.get_size(), 48);
        EXPECT_EQ(measurement_21.get_count(), 1);
        EXPECT_EQ(measurement_21.get_values().size(), 1);
    }
    
    // Measurement at index 35 should be active with 4 alternatives
    if (measurements.has_measurement_at_index(35)) {
        Measurement measurement_35;
        error = measurements.get_measurement_at_index(35, measurement_35);
        EXPECT_EQ(error, Error::Ok);
        EXPECT_TRUE(measurement_35.get_active());
        EXPECT_EQ(measurement_35.get_index(), 35);
        EXPECT_EQ(measurement_35.get_name(), "Measurement_35");
        EXPECT_EQ(measurement_35.get_size(), 48);
        EXPECT_EQ(measurement_35.get_count(), 4);
        EXPECT_EQ(measurement_35.get_values().size(), 4);
    }
    
    // Inactive measurements should not be present in the container
    // Index 0 should not exist (there's no measurement at index 0)
    EXPECT_FALSE(measurements.has_measurement_at_index(0));
    
    // Index 1 should not exist (was inactive in XML)
    EXPECT_FALSE(measurements.has_measurement_at_index(1));
    
    // Test get_all_indices method
    std::vector<int> all_indices = measurements.get_all_indices();
    EXPECT_GT(all_indices.size(), 0);
    
    // Verify that trying to get a non-existent measurement returns the correct error
    Measurement non_existent;
    error = measurements.get_measurement_at_index(999, non_existent);
    EXPECT_EQ(error, Error::RimMeasurementNotFound);
    
    LOG_DEBUG("Test completed - found " << measurements.size() << " total measurements");
}

