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

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include <unistd.h>

#include "gtest/gtest.h"

#include "local_https_test_server.h"
#include "nv_attestation/corim_evidence/corim_store.h"
#include "nv_attestation/nv_cache.h"
#include "nv_attestation/nv_http.h"
#include "nv_attestation/nvat_private.hpp"
#include "nv_attestation/observer.h"

using namespace nvattestation;

namespace {

struct HttpEvent {
    std::string service;
    std::string method;
    std::string url;
    long status;
    std::string error;
    size_t request_size;
    size_t response_size;
};

struct CacheEvent {
    std::string cache;
    bool hit;
};

struct Recorder {
    std::vector<HttpEvent> http;
    std::vector<CacheEvent> cache;
};

void record_http_call(const char* service, const char* method, const char* url, long status, const char* error, long duration_ms, size_t request_size, size_t response_size, void* user_data) {
    EXPECT_GE(duration_ms, 0);
    static_cast<Recorder*>(user_data)->http.push_back({service, method, url, status, error == nullptr ? "" : error, request_size, response_size});
}

void record_cache_lookup(const char* cache, bool hit, void* user_data) {
    static_cast<Recorder*>(user_data)->cache.push_back({cache, hit});
}

class ObserverTest : public ::testing::Test {
protected:
    static LocalHttpsTestServer m_server;
    static bool m_setup_ok;
    Recorder m_recorder;

    static void SetUpTestSuite() { m_setup_ok = m_server.start(); }
    static void TearDownTestSuite() { m_server.stop(); }

    void SetUp() override {
        set_observer(Observer{record_http_call, record_cache_lookup, &m_recorder});
    }
    void TearDown() override { destroy_observer(); }

    HttpOptions options(bool trust_server) const {
        HttpOptions result;
        if (trust_server) {
            result.set_tls_ca_cert(m_server.cert_path("tls_ca_cert.pem"));
        }
        result.set_max_retry_count(0);
        result.set_connection_timeout_ms(5000);
        result.set_request_timeout_ms(5000);
        return result;
    }
};

LocalHttpsTestServer ObserverTest::m_server;
bool ObserverTest::m_setup_ok = false;

}

TEST_F(ObserverTest, ReportsHttpResponse) {
    ASSERT_TRUE(m_setup_ok);
    NvHttpClient client;
    ASSERT_EQ(NvHttpClient::create(client, "", options(true), "rim"), Error::Ok);
    NvRequest request(m_server.url(), NvHttpMethod::HTTP_METHOD_GET);
    long status = 0;
    std::string response;
    ASSERT_EQ(client.do_request_as_string(request, status, response), Error::Ok);

    ASSERT_EQ(m_recorder.http.size(), 1U);
    EXPECT_EQ(m_recorder.http[0].service, "rim");
    EXPECT_EQ(m_recorder.http[0].method, "GET");
    EXPECT_EQ(m_recorder.http[0].url, m_server.url());
    EXPECT_EQ(m_recorder.http[0].status, 200);
    EXPECT_EQ(m_recorder.http[0].error, "");
    EXPECT_EQ(m_recorder.http[0].request_size, 0U);
    EXPECT_EQ(m_recorder.http[0].response_size, response.size());
}

TEST_F(ObserverTest, ReportsHttpFailureWithoutStatus) {
    ASSERT_TRUE(m_setup_ok);
    // The self-signed server cert is untrusted, so no response is received.
    NvHttpClient client;
    ASSERT_EQ(NvHttpClient::create(client, "", options(false), "ocsp"), Error::Ok);
    NvRequest request(m_server.url(), NvHttpMethod::HTTP_METHOD_POST);
    long status = 0;
    std::string response;
    ASSERT_NE(client.do_request_as_string(request, status, response), Error::Ok);

    ASSERT_EQ(m_recorder.http.size(), 1U);
    EXPECT_EQ(m_recorder.http[0].service, "ocsp");
    EXPECT_EQ(m_recorder.http[0].method, "POST");
    EXPECT_EQ(m_recorder.http[0].url, m_server.url());
    EXPECT_EQ(m_recorder.http[0].status, 0);
    EXPECT_EQ(m_recorder.http[0].error, "other");
    EXPECT_EQ(m_recorder.http[0].request_size, 0U);
    EXPECT_EQ(m_recorder.http[0].response_size, 0U);
}

TEST_F(ObserverTest, ReportsCorimCacheMissThenHit) {
    char buf[] = "/tmp/nvat_observer_test_rim_XXXXXX";
    int fd = ::mkstemp(buf);
    ASSERT_GE(fd, 0);
    ::close(fd);
    const std::string path = buf;
    {
        std::ofstream out(path, std::ios::binary);
        out << "RIM-BYTES";
    }
    CorimStore store;
    store.enable_in_memory_cache(1048576, 600);
    const std::string url = "https://rim.attestation.nvidia.com/observer";
    ASSERT_EQ(store.add_url_rewrite(url, "file://" + path), Error::Ok);
    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(url, body), Error::Ok);
    ASSERT_EQ(store.fetch(url, body), Error::Ok);
    std::remove(path.c_str());

    ASSERT_EQ(m_recorder.cache.size(), 2U);
    EXPECT_EQ(m_recorder.cache[0].cache, "rim");
    EXPECT_FALSE(m_recorder.cache[0].hit);
    EXPECT_EQ(m_recorder.cache[1].cache, "rim");
    EXPECT_TRUE(m_recorder.cache[1].hit);
}

TEST_F(ObserverTest, ReportsCachedRimNotFoundAsHit) {
    const std::string url = "https://rim.attestation.nvidia.com/observer-missing";
    auto negative_cache = std::make_shared<NvCache>(std::make_shared<NvCacheOptions>(1024, 600));
    ASSERT_EQ(negative_cache->put(url, std::make_shared<bool>(true), url.size() + sizeof(bool)), Error::Ok);
    CorimStore store;
    store.set_negative_cache(negative_cache);
    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(url, body), Error::RimNotFound);

    ASSERT_EQ(m_recorder.cache.size(), 1U);
    EXPECT_EQ(m_recorder.cache[0].cache, "rim");
    EXPECT_TRUE(m_recorder.cache[0].hit);
    EXPECT_TRUE(m_recorder.http.empty());
}

TEST(ObserverCApiTest, SetsObserverOnOptions) {
    Recorder recorder;
    nvat_observer_t observer = nullptr;
    ASSERT_EQ(nvat_observer_create(&observer, &recorder), NVAT_RC_OK);
    nvat_observer_set_http_call_callback(observer, record_http_call);
    nvat_observer_set_cache_lookup_callback(observer, record_cache_lookup);

    nvat_sdk_opts_t opts = nullptr;
    ASSERT_EQ(nvat_sdk_opts_create(&opts), NVAT_RC_OK);
    nvat_sdk_opts_set_observer(opts, observer);
    nvat_observer_free(&observer);
    EXPECT_EQ(observer, nullptr);

    const Observer& set = (*nvat_sdk_opts_to_cpp(opts))->observer;
    EXPECT_EQ(set.http_call_callback, record_http_call);
    EXPECT_EQ(set.cache_lookup_callback, record_cache_lookup);
    EXPECT_EQ(set.user_data, &recorder);
    nvat_sdk_opts_free(&opts);
}

TEST(ObserverUnsetTest, NotifyWithoutObserverIsNoop) {
    destroy_observer();
    notify_http_call("rim", "GET", "https://example.com", 200, nullptr, 100, 0, 0);
    notify_cache_lookup("rim", true);
}
