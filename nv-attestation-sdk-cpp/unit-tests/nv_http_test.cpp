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


#include "nlohmann/json.hpp"

#include "nv_attestation/nv_http.h"
#include "nv_attestation/log.h"

#include "gtest/gtest.h"

#include "local_https_test_server.h"

using namespace nvattestation;

TEST(HttpOptions, DefaultTlsCaCertIsEmpty) {
    HttpOptions options;
    ASSERT_TRUE(options.tls_ca_cert.empty());
    ASSERT_TRUE(options.tls_ca_path.empty());
}

TEST(HttpOptions, SetTlsCaCert) {
    HttpOptions options;
    options.set_tls_ca_cert("/path/to/ca-bundle.pem");
    ASSERT_EQ(options.tls_ca_cert, "/path/to/ca-bundle.pem");
    ASSERT_TRUE(options.tls_ca_path.empty());
}

TEST(HttpOptions, SetTlsCaPath) {
    HttpOptions options;
    options.set_tls_ca_path("/etc/ssl/certs");
    ASSERT_TRUE(options.tls_ca_cert.empty());
    ASSERT_EQ(options.tls_ca_path, "/etc/ssl/certs");
}

TEST(HttpOptions, SetBothTlsCaCertAndCaPath) {
    HttpOptions options;
    options.set_tls_ca_cert("/path/to/ca-bundle.pem");
    options.set_tls_ca_path("/etc/ssl/certs");
    ASSERT_EQ(options.tls_ca_cert, "/path/to/ca-bundle.pem");
    ASSERT_EQ(options.tls_ca_path, "/etc/ssl/certs");
}

// === TLS Integration Tests ===
// Spins up a local Python HTTPS server with self-signed certs and verifies
// that NvHttpClient respects CURLOPT_CAINFO/CURLOPT_CAPATH options.

class NvHttpClientTlsTest : public ::testing::Test {
protected:
    static LocalHttpsTestServer m_server;
    static bool m_setup_ok;

    static void SetUpTestSuite() {
        m_setup_ok = m_server.start();
    }

    static void TearDownTestSuite() {
        m_server.stop();
    }

    void SetUp() override {
        ASSERT_TRUE(m_setup_ok) << "TLS test server not available";
    }

    std::string server_url() const { return m_server.url(); }
    std::string cert_path(const std::string& filename) const { return m_server.cert_path(filename); }
};

LocalHttpsTestServer NvHttpClientTlsTest::m_server;
bool NvHttpClientTlsTest::m_setup_ok = false;

TEST_F(NvHttpClientTlsTest, GetAsString) {
    HttpOptions options;
    options.set_tls_ca_cert(cert_path("tls_ca_cert.pem"));
    options.set_max_retry_count(0);
    options.set_connection_timeout_ms(5000);
    options.set_request_timeout_ms(5000);

    NvHttpClient client;
    Error error = NvHttpClient::create(client, "", options);
    ASSERT_EQ(error, Error::Ok);

    NvRequest request(server_url(), NvHttpMethod::HTTP_METHOD_GET);
    long status = 0;
    std::string response;
    error = client.do_request_as_string(request, status, response);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_EQ(status, NvHttpStatus::HTTP_STATUS_OK);
    ASSERT_FALSE(response.empty());
}

TEST_F(NvHttpClientTlsTest, GetAsStruct) {
    HttpOptions options;
    options.set_tls_ca_cert(cert_path("tls_ca_cert.pem"));
    options.set_max_retry_count(0);
    options.set_connection_timeout_ms(5000);
    options.set_request_timeout_ms(5000);

    NvHttpClient client;
    Error error = NvHttpClient::create(client, "", options);
    ASSERT_EQ(error, Error::Ok);

    NvRequest request(server_url(), NvHttpMethod::HTTP_METHOD_GET);
    long status = 0;
    nlohmann::json json_response;
    error = client.do_request_as_json_struct(request, status, json_response);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_EQ(status, NvHttpStatus::HTTP_STATUS_OK);
    ASSERT_FALSE(json_response.empty());
    ASSERT_EQ(json_response["method"], "GET");
    ASSERT_EQ(json_response["status"], "ok");
}

TEST_F(NvHttpClientTlsTest, PostAsString) {
    HttpOptions options;
    options.set_tls_ca_cert(cert_path("tls_ca_cert.pem"));
    options.set_max_retry_count(0);
    options.set_connection_timeout_ms(5000);
    options.set_request_timeout_ms(5000);

    NvHttpClient client;
    Error error = NvHttpClient::create(client, "", options);
    ASSERT_EQ(error, Error::Ok);

    NvRequest request(server_url(), NvHttpMethod::HTTP_METHOD_POST, {}, "{\"test\": \"test\"}");
    long status = 0;
    std::string response;
    error = client.do_request_as_string(request, status, response);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_EQ(status, NvHttpStatus::HTTP_STATUS_OK);
    ASSERT_FALSE(response.empty());
}

TEST_F(NvHttpClientTlsTest, PostAsStruct) {
    HttpOptions options;
    options.set_tls_ca_cert(cert_path("tls_ca_cert.pem"));
    options.set_max_retry_count(0);
    options.set_connection_timeout_ms(5000);
    options.set_request_timeout_ms(5000);

    NvHttpClient client;
    Error error = NvHttpClient::create(client, "", options);
    ASSERT_EQ(error, Error::Ok);

    NvRequest request(server_url(), NvHttpMethod::HTTP_METHOD_POST, {}, "{\"test\": \"test\"}");
    long status = 0;
    nlohmann::json json_response;
    error = client.do_request_as_json_struct(request, status, json_response);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_EQ(status, NvHttpStatus::HTTP_STATUS_OK);
    ASSERT_EQ(json_response["method"], "POST");
    ASSERT_EQ(json_response["body"], "{\"test\": \"test\"}");
}

TEST_F(NvHttpClientTlsTest, CaCertSuccess) {
    HttpOptions options;
    options.set_tls_ca_cert(cert_path("tls_ca_cert.pem"));
    options.set_max_retry_count(0);
    options.set_connection_timeout_ms(5000);
    options.set_request_timeout_ms(5000);

    NvHttpClient client;
    Error error = NvHttpClient::create(client, "", options);
    ASSERT_EQ(error, Error::Ok);

    NvRequest request(server_url(), NvHttpMethod::HTTP_METHOD_GET);
    long status = 0;
    std::string response;
    error = client.do_request_as_string(request, status, response);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_EQ(status, 200);
    ASSERT_FALSE(response.empty());
}

TEST_F(NvHttpClientTlsTest, CaPathSuccess) {
    HttpOptions options;
    options.set_tls_ca_path(m_server.cert_dir());
    options.set_max_retry_count(0);
    options.set_connection_timeout_ms(5000);
    options.set_request_timeout_ms(5000);

    NvHttpClient client;
    Error error = NvHttpClient::create(client, "", options);
    ASSERT_EQ(error, Error::Ok);

    NvRequest request(server_url(), NvHttpMethod::HTTP_METHOD_GET);
    long status = 0;
    std::string response;
    error = client.do_request_as_string(request, status, response);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_EQ(status, 200);
    ASSERT_FALSE(response.empty());
}

TEST_F(NvHttpClientTlsTest, WrongCaCertFails) {
    HttpOptions options;
    options.set_tls_ca_cert(cert_path("tls_wrong_ca_cert.pem"));
    options.set_max_retry_count(0);
    options.set_connection_timeout_ms(5000);
    options.set_request_timeout_ms(5000);

    NvHttpClient client;
    Error error = NvHttpClient::create(client, "", options);
    ASSERT_EQ(error, Error::Ok);

    NvRequest request(server_url(), NvHttpMethod::HTTP_METHOD_GET);
    long status = 0;
    std::string response;
    testing::internal::CaptureStderr();
    error = client.do_request_as_string(request, status, response);
    const std::string logs = testing::internal::GetCapturedStderr();
    // curl should fail TLS verification — returns InternalError
    ASSERT_NE(error, Error::Ok);
    EXPECT_NE(logs.find("SSL certificate"), std::string::npos)
        << "expected libcurl's detailed TLS diagnostic, got:\n" << logs;
}

TEST_F(NvHttpClientTlsTest, RateLimited429MapsToRateLimitedError) {
    HttpOptions options;
    options.set_tls_ca_cert(cert_path("tls_ca_cert.pem"));
    options.set_max_retry_count(0);
    options.set_connection_timeout_ms(5000);
    options.set_request_timeout_ms(5000);

    NvHttpClient client;
    ASSERT_EQ(NvHttpClient::create(client, "", options), Error::Ok);

    NvRequest request(server_url() + "ratelimited", NvHttpMethod::HTTP_METHOD_GET);
    long status = 0;
    std::string response;
    Error error = client.do_request_as_string(request, status, response);
    EXPECT_EQ(error, Error::RateLimited);
    EXPECT_EQ(status, 429);
}

TEST_F(NvHttpClientTlsTest, RequestIdHeaderIsSentAndUnique) {
    HttpOptions options;
    options.set_tls_ca_cert(cert_path("tls_ca_cert.pem"));
    options.set_max_retry_count(0);
    options.set_connection_timeout_ms(5000);
    options.set_request_timeout_ms(5000);

    NvHttpClient client;
    ASSERT_EQ(NvHttpClient::create(client, "", options), Error::Ok);

    NvRequest request(server_url() + "echo-headers", NvHttpMethod::HTTP_METHOD_GET);
    long status = 0;
    nlohmann::json first_response;
    ASSERT_EQ(client.do_request_as_json_struct(request, status, first_response), Error::Ok);
    ASSERT_EQ(status, NvHttpStatus::HTTP_STATUS_OK);
    ASSERT_TRUE(first_response["headers"].contains("x-request-id"));
    std::string first_id = first_response["headers"]["x-request-id"];
    EXPECT_FALSE(first_id.empty());

    nlohmann::json second_response;
    ASSERT_EQ(client.do_request_as_json_struct(request, status, second_response), Error::Ok);
    std::string second_id = second_response["headers"]["x-request-id"];
    EXPECT_NE(first_id, second_id) << "Each request should get its own x-request-id";
}

// A non-empty service key makes NvHttpClient add an "Authorization: Bearer"
// header, but only when the target host is nvidia.com or a subdomain
// (is_safe_service_key_target in nv_http.cpp). The local test server runs on
// 127.0.0.1, which fails that check, so the header must be suppressed here;
// assert against the actual echoed headers rather than just request success.
TEST_F(NvHttpClientTlsTest, ServiceKeySuppressedForNonNvidiaTarget) {
    HttpOptions options;
    options.set_tls_ca_cert(cert_path("tls_ca_cert.pem"));
    options.set_max_retry_count(0);
    options.set_connection_timeout_ms(5000);
    options.set_request_timeout_ms(5000);

    NvHttpClient client;
    Error error = NvHttpClient::create(client, "test-service-key", options);
    ASSERT_EQ(error, Error::Ok);

    NvRequest request(server_url() + "echo-headers", NvHttpMethod::HTTP_METHOD_GET);
    long status = 0;
    nlohmann::json response;
    error = client.do_request_as_json_struct(request, status, response);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_EQ(status, NvHttpStatus::HTTP_STATUS_OK);
    ASSERT_TRUE(response.contains("headers"));
    EXPECT_FALSE(response.at("headers").contains("Authorization"));
}

TEST_F(NvHttpClientTlsTest, NoCaCertFailsAgainstSelfSigned) {
    HttpOptions options;
    // No tls_ca_cert or tls_ca_path — system CA store won't trust our self-signed cert
    options.set_max_retry_count(0);
    options.set_connection_timeout_ms(5000);
    options.set_request_timeout_ms(5000);

    NvHttpClient client;
    Error error = NvHttpClient::create(client, "", options);
    ASSERT_EQ(error, Error::Ok);

    NvRequest request(server_url(), NvHttpMethod::HTTP_METHOD_GET);
    long status = 0;
    std::string response;
    error = client.do_request_as_string(request, status, response);
    // Should fail — self-signed CA is not in system store
    ASSERT_NE(error, Error::Ok);
}
