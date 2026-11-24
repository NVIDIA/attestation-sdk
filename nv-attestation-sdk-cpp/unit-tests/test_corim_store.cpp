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

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include "gtest/gtest.h"

#include <nlohmann/json.hpp>

#include "local_https_test_server.h"
#include "nv_attestation/corim_evidence/corim_store.h"
#include "nv_attestation/error.h"
#include "nv_attestation/nv_http.h"
#include "nv_attestation/utils.h"

namespace nvattestation {
namespace {

constexpr const char *kNvidiaRimPrefix =
    "https://rim.attestation.nvidia.com/";

class TempFile {
  public:
    explicit TempFile(const std::string &contents) {
        char buf[] = "/tmp/nvat_corim_store_XXXXXX";
        int fd = ::mkstemp(buf);
        if (fd < 0) {
            throw std::system_error(errno, std::generic_category(), "mkstemp");
        }
        ::close(fd);
        m_path = buf;
        std::ofstream out(m_path, std::ios::binary);
        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    }
    ~TempFile() { std::remove(m_path.c_str()); }
    const std::string &path() const { return m_path; }

  private:
    std::string m_path;
};

TEST(CorimStoreTest, RawNonHttpsRejected) {
    CorimStore store;
    std::vector<uint8_t> body;
    EXPECT_EQ(store.fetch("file:///etc/passwd", body), Error::BadArgument);
    EXPECT_EQ(store.fetch("http://example.com/rim", body),
              Error::BadArgument);
    EXPECT_EQ(store.fetch("ftp://example.com/rim", body),
              Error::BadArgument);
}

TEST(CorimStoreTest, RawHttpsOutsideAllowlistRejected) {
    CorimStore store;
    std::vector<uint8_t> body;
    // https but pointed at an arbitrary host: the verifier must not
    // honor it, even with no rewrites configured.
    EXPECT_EQ(store.fetch("https://attacker.example.com/anything", body),
              Error::BadArgument);
    // Also reject a URL whose host is the allowlist prefix's host but
    // not under the trailing-slash path boundary.
    EXPECT_EQ(store.fetch("https://rim.attestation.nvidia.com.evil/x",
                            body),
              Error::BadArgument);
}

TEST(CorimStoreTest, EffectiveUrlIsRawUrlOnAllowlistRejection) {
    // out_effective_url must still hold a usable value (the raw URL) on
    // the allowlist-rejection path, since callers log it on fetch failure.
    CorimStore store;
    std::vector<uint8_t> body;
    std::string effective = "not-yet-set";
    EXPECT_EQ(store.fetch("https://attacker.example.com/anything", body,
                            &effective),
              Error::BadArgument);
    EXPECT_EQ(effective, "https://attacker.example.com/anything");

    std::vector<uint8_t> corim_bytes, coev_bytes;
    bool coev_present = false;
    std::string coev_sha256;
    std::string coev_effective = "not-yet-set";
    EXPECT_EQ(store.fetch_with_coev("https://attacker.example.com/anything",
                                      corim_bytes, coev_bytes, coev_present,
                                      coev_sha256, &coev_effective),
              Error::BadArgument);
    EXPECT_EQ(coev_effective, "https://attacker.example.com/anything");
}

TEST(CorimStoreTest, EmptyPatternRejected) {
    CorimStore store;
    EXPECT_EQ(store.add_url_rewrite("", "https://anywhere/"),
              Error::BadArgument);
}

TEST(CorimStoreTest, RewriteToFileReadsBytes) {
    const std::string contents = "RIM-BYTES-12345";
    TempFile tmp(contents);

    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(
                  std::string(kNvidiaRimPrefix) + "foo",
                  "file://" + tmp.path()),
              Error::Ok);
    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(std::string(kNvidiaRimPrefix) + "foo", body),
              Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), contents);
}

// appraise_item calls fetch_with_coev unconditionally, so it must support
// file:// fixtures the same as fetch().
TEST(CorimStoreTest, FetchWithCoevRewriteToFileReadsBytesNoCoev) {
    const std::string contents = "RIM-BYTES-12345";
    TempFile tmp(contents);

    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(
                  std::string(kNvidiaRimPrefix) + "foo",
                  "file://" + tmp.path()),
              Error::Ok);
    std::vector<uint8_t> corim_bytes, coev_bytes;
    bool coev_present = true; // must be reset to false
    std::string coev_sha256 = "not-yet-set"; // must be reset to empty
    ASSERT_EQ(store.fetch_with_coev(std::string(kNvidiaRimPrefix) + "foo",
                                     corim_bytes, coev_bytes, coev_present,
                                     coev_sha256),
              Error::Ok);
    EXPECT_EQ(std::string(corim_bytes.begin(), corim_bytes.end()), contents);
    EXPECT_FALSE(coev_present);
    EXPECT_TRUE(coev_bytes.empty());
    EXPECT_TRUE(coev_sha256.empty());
}

TEST(CorimStoreTest, FirstMatchWins) {
    const std::string winner_contents = "WINNER";
    const std::string loser_contents = "LOSER";
    TempFile winner(winner_contents);
    TempFile loser(loser_contents);

    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(std::string(kNvidiaRimPrefix) + "a",
                                      "file://" + winner.path()),
              Error::Ok);
    // Second rule overlaps but should never fire. Drop the trailing
    // '/' from the prefix so PATTERN and REPLACEMENT both end without
    // one (matching-slash rule).
    std::string broader_pattern = kNvidiaRimPrefix;
    if (!broader_pattern.empty() && broader_pattern.back() == '/') {
        broader_pattern.pop_back();
    }
    ASSERT_EQ(store.add_url_rewrite(broader_pattern,
                                      "file://" + loser.path()),
              Error::Ok);

    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(std::string(kNvidiaRimPrefix) + "a", body),
              Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), winner_contents);
}

TEST(CorimStoreTest, RubinVbiosLocatorFixPrecedesConfiguredRewrite) {
    const std::string contents = "RUBIN-RIM-BYTES";
    TempFile tmp(contents);
    const std::string rim_prefix = std::string(kNvidiaRimPrefix) + "v1/rim/";
    const std::string canonical = rim_prefix + "GR100_081D_9900230000";
    const std::string legacy =
        rim_prefix + "NV_GPU_VBIOS_GR100_081D_9900230000";
    const std::string file_url = "file://" + tmp.path();
    const std::string fallback = "file:///definitely/not/here/";

    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(canonical, file_url), Error::Ok);
    ASSERT_EQ(store.add_url_rewrite(rim_prefix, fallback), Error::Ok);

    std::vector<uint8_t> corim_bytes, coev_bytes;
    bool coev_present = true;
    std::string coev_sha256 = "not-yet-set";
    std::string effective;
    ASSERT_EQ(store.fetch_with_coev(legacy, corim_bytes, coev_bytes,
                                    coev_present, coev_sha256, &effective),
              Error::Ok);
    EXPECT_EQ(std::string(corim_bytes.begin(), corim_bytes.end()), contents);
    EXPECT_FALSE(coev_present);
    EXPECT_TRUE(coev_bytes.empty());
    EXPECT_TRUE(coev_sha256.empty());
    EXPECT_EQ(effective, file_url);

    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(canonical, body, &effective), Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), contents);
    EXPECT_EQ(effective, file_url);

    const std::string driver = "NV_GPU_DRIVER_GR100_081D_9900230000";
    EXPECT_EQ(store.fetch(rim_prefix + driver, body, &effective),
              Error::RimNotFound);
    EXPECT_EQ(effective, fallback + driver);

    const std::string blackwell = "NV_GPU_VBIOS_GB100_081D_9900230000";
    EXPECT_EQ(store.fetch(rim_prefix + blackwell, body, &effective),
              Error::RimNotFound);
    EXPECT_EQ(effective, fallback + blackwell);

    const std::string off_allowlist =
        "https://other.example.com/v1/rim/NV_GPU_VBIOS_GR100_081D_9900230000";
    EXPECT_EQ(store.fetch(off_allowlist, body, &effective),
              Error::BadArgument);
    EXPECT_EQ(effective, off_allowlist);
}

TEST(CorimStoreTest, NonMatchingRulesLeaveSchemeIntact) {
    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite("https://other.example.com/",
                                      "file:///nonexistent/"),
              Error::Ok);
    std::vector<uint8_t> body;
    std::string effective;
    store.fetch(std::string(kNvidiaRimPrefix) + "rim", body, &effective);
    // Non-matching rule: effective URL must equal the raw input (no rewrite).
    EXPECT_EQ(effective, std::string(kNvidiaRimPrefix) + "rim");
}

TEST(CorimStoreTest, MismatchedTrailingSlashRejected) {
    CorimStore store;
    EXPECT_EQ(store.add_url_rewrite("https://a/", "file:///b"),
              Error::BadArgument);
    EXPECT_EQ(store.add_url_rewrite("https://a", "file:///b/"),
              Error::BadArgument);
    EXPECT_EQ(store.add_url_rewrite("https://a/", "file:///b/"),
              Error::Ok);
    EXPECT_EQ(store.add_url_rewrite("https://a", "file:///b"),
              Error::Ok);
}

TEST(CorimStoreTest, RewriteMustProduceKnownScheme) {
    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(kNvidiaRimPrefix, "ftp://elsewhere/"),
              Error::Ok);
    std::vector<uint8_t> body;
    EXPECT_EQ(store.fetch(std::string(kNvidiaRimPrefix) + "foo", body),
              Error::BadArgument);
}

TEST(CorimStoreTest, RewriteToHttpSchemeAccepted) {
    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(kNvidiaRimPrefix, "http://127.0.0.1:9/"),
              Error::Ok);
    std::vector<uint8_t> body;
    std::string effective;
    // Nothing listens on discard port 9, so the fetch fails at the transport
    // layer -- but the http:// scheme must be dispatched, not rejected like the
    // ftp:// case in RewriteMustProduceKnownScheme.
    Error err = store.fetch(std::string(kNvidiaRimPrefix) + "foo", body,
                            &effective);
    EXPECT_EQ(effective, "http://127.0.0.1:9/foo");
    EXPECT_NE(err, Error::BadArgument);
}

TEST(CorimStoreTest, FilePostRewriteNotFound) {
    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(kNvidiaRimPrefix,
                                      "file:///definitely/not/here/"),
              Error::Ok);
    std::vector<uint8_t> body;
    EXPECT_EQ(store.fetch(std::string(kNvidiaRimPrefix) + "foo", body),
              Error::RimNotFound);
}

TEST(CorimStoreTest, AllowlistPrefixMustBeHttps) {
    CorimStore store;
    EXPECT_EQ(store.add_allowed_url_prefix("file:///etc/"),
              Error::BadArgument);
    EXPECT_EQ(store.add_allowed_url_prefix("http://mirror.example.com/"),
              Error::BadArgument);
    EXPECT_EQ(store.add_allowed_url_prefix("https://mirror.example.com/"),
              Error::Ok);
}

TEST(CorimStoreTest, AddedAllowlistPrefixIsHonored) {
    const std::string contents = "MIRROR-RIM";
    TempFile tmp(contents);

    CorimStore store;
    // A URL outside the built-in NVIDIA prefix is rejected until allowlisted.
    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch("https://mirror.example.com/rim", body),
              Error::BadArgument);

    ASSERT_EQ(store.add_allowed_url_prefix("https://mirror.example.com/"),
              Error::Ok);
    ASSERT_EQ(store.add_url_rewrite("https://mirror.example.com/rim",
                                      "file://" + tmp.path()),
              Error::Ok);
    ASSERT_EQ(store.fetch("https://mirror.example.com/rim", body),
              Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), contents);
}


// === HTTPS content-type integration tests ===
// Spins up a local HTTPS server so the https:// dispatch path exercises a
// real Content-Type header rather than assuming any given response is CoRIM.

class CorimStoreHttpsTest : public ::testing::Test {
  protected:
    static LocalHttpsTestServer m_server;
    static bool m_setup_ok;

    static void SetUpTestSuite() { m_setup_ok = m_server.start(); }
    static void TearDownTestSuite() { m_server.stop(); }

    void SetUp() override {
        ASSERT_TRUE(m_setup_ok) << "HTTPS test server not available";
    }

    CorimStore make_store() const {
        HttpOptions options;
        options.set_tls_ca_cert(m_server.cert_path("tls_ca_cert.pem"));
        options.set_max_retry_count(0);
        CorimStore store(options);
        Error err = store.add_allowed_url_prefix(m_server.url());
        EXPECT_EQ(err, Error::Ok);
        return store;
    }

    std::string server_url() const { return m_server.url(); }
};

LocalHttpsTestServer CorimStoreHttpsTest::m_server;
bool CorimStoreHttpsTest::m_setup_ok = false;

TEST_F(CorimStoreHttpsTest, JsonRimServiceResponseIsUnwrapped) {
    CorimStore store = make_store();
    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(server_url() + "rim-service", body), Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), "CORIM-BYTES-FROM-SERVICE");
}

TEST_F(CorimStoreHttpsTest, CorimCborContentTypePassesThroughRawBytes) {
    CorimStore store = make_store();
    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(server_url() + "corim-cbor", body), Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), "CORIM-BYTES-CBOR");
}

TEST_F(CorimStoreHttpsTest, CorimCoseContentTypePassesThroughRawBytes) {
    CorimStore store = make_store();
    std::vector<uint8_t> body;
    ASSERT_EQ(store.fetch(server_url() + "corim-cose", body), Error::Ok);
    EXPECT_EQ(std::string(body.begin(), body.end()), "CORIM-BYTES-COSE");
}

TEST_F(CorimStoreHttpsTest, UnexpectedContentTypeRejected) {
    CorimStore store = make_store();
    std::vector<uint8_t> body;
    EXPECT_EQ(store.fetch(server_url() + "unexpected-content-type", body),
              Error::RimInvalidSchema);
}

// === fetch_with_coev ===

TEST_F(CorimStoreHttpsTest, FetchWithCoevExtractsBothPayloads) {
    CorimStore store = make_store();
    std::vector<uint8_t> corim_bytes, coev_bytes;
    bool coev_present = false;
    std::string coev_sha256;
    Error err = store.fetch_with_coev(server_url() + "rim-service-with-coev",
                                       corim_bytes, coev_bytes, coev_present,
                                       coev_sha256);

    EXPECT_EQ(err, Error::Ok);
    EXPECT_EQ(corim_bytes, (std::vector<uint8_t>{0x01, 0x02, 0x03}));
    EXPECT_TRUE(coev_present);
    EXPECT_EQ(coev_bytes, (std::vector<uint8_t>{0xAA, 0xBB}));
    EXPECT_EQ(coev_sha256, "unused");
}

TEST_F(CorimStoreHttpsTest, FetchWithCoevAbsentIsNotAnError) {
    CorimStore store = make_store();
    std::vector<uint8_t> corim_bytes, coev_bytes;
    bool coev_present = true; // must be reset to false by fetch_with_coev
    std::string coev_sha256 = "not-yet-set";
    Error err = store.fetch_with_coev(server_url() + "rim-service-no-coev",
                                       corim_bytes, coev_bytes, coev_present,
                                       coev_sha256);

    EXPECT_EQ(err, Error::Ok);
    EXPECT_FALSE(coev_present);
    EXPECT_TRUE(coev_bytes.empty());
    EXPECT_TRUE(coev_sha256.empty());
}

TEST_F(CorimStoreHttpsTest, FetchWithCoevRejectsInvalidCoevBase64) {
    CorimStore store = make_store();
    std::vector<uint8_t> corim_bytes, coev_bytes;
    bool coev_present = false;
    std::string coev_sha256;
    Error err = store.fetch_with_coev(
        server_url() + "rim-service-with-invalid-coev-base64", corim_bytes,
        coev_bytes, coev_present, coev_sha256);

    EXPECT_EQ(err, Error::RimInternalError);
}

// === ends_with utility ===

TEST(EndsWithTest, BasicSuffix) {
    EXPECT_TRUE(ends_with("nvidia.com", ".com"));
    EXPECT_TRUE(ends_with(".nvidia.com", ".nvidia.com"));
    EXPECT_TRUE(ends_with("rim.attestation.nvidia.com", ".nvidia.com"));
    EXPECT_FALSE(ends_with("notnvidia.com", ".nvidia.com"));
    EXPECT_FALSE(ends_with("nvidia.com.evil", ".nvidia.com"));
    EXPECT_TRUE(ends_with("", ""));
    EXPECT_FALSE(ends_with("", ".nvidia.com"));
}

// === Service-key domain + scheme scoping (indirect, via CorimStore) ===
// The credential must only be forwarded to https://*.nvidia.com targets.

// === Service-key domain scoping ===

TEST_F(CorimStoreHttpsTest, ServiceKeyNotSentToNonNvidiaDomain) {
    HttpOptions options;
    options.set_tls_ca_cert(m_server.cert_path("tls_ca_cert.pem"));
    options.set_max_retry_count(0);

    NvHttpClient client;
    ASSERT_EQ(NvHttpClient::create(client, "super-secret-key", options), Error::Ok);

    NvRequest req(server_url() + "echo-headers", NvHttpMethod::HTTP_METHOD_GET);
    long status = 0;
    std::string body;
    ASSERT_EQ(client.do_request_as_string(req, status, body), Error::Ok);
    ASSERT_EQ(status, 200);

    auto j = nlohmann::json::parse(body);
    // Headers are lowercased by Python's http.server; check both casings to be safe.
    const auto& headers = j.at("headers");
    EXPECT_FALSE(headers.contains("authorization"))
        << "Service key was leaked to a non-NVIDIA domain";
    EXPECT_FALSE(headers.contains("Authorization"))
        << "Service key was leaked to a non-NVIDIA domain";
}

} // namespace
} // namespace nvattestation

// Wrap the real cache to observe writes and simulate backend failures.
class RecordingNegativeCache : public nvattestation::INvCache {
  public:
    nvattestation::NvCache cache{
        std::make_shared<nvattestation::NvCacheOptions>(1048576, 600)};
    int puts = 0;
    uint64_t charge = 0;
    bool fail_put = false;
    bool fail_get = false;
    bool nonnull = false;

    nvattestation::Error put(const std::string &key,
                             std::shared_ptr<void> value,
                             uint64_t size_bytes) override {
        ++puts;
        charge = size_bytes;
        nonnull = value != nullptr;
        return fail_put ? nvattestation::Error::InternalError
                        : cache.put(key, std::move(value), size_bytes);
    }
    nvattestation::Error get(const std::string &key,
                             std::shared_ptr<void> &value) override {
        if (fail_get) {
            return nvattestation::Error::InternalError;
        }
        return cache.get(key, value);
    }
    void remove(const std::string &key) override {
        cache.remove(key);
    }
    void clear() override { cache.clear(); }
};

// Use real HTTPS requests: each /rim fixture returns 404 once, then fixture bytes.
// A request counter reveals whether a fetch reached the server or used the cache.
class CorimNegativeCacheTest : public ::testing::Test {
  protected:
    static LocalHttpsTestServer server;
    static bool ready;
    static void SetUpTestSuite() { ready = server.start(); }
    static void TearDownTestSuite() { server.stop(); }
    void SetUp() override { ASSERT_TRUE(ready); }

    nvattestation::HttpOptions options() const {
        nvattestation::HttpOptions result;
        result.set_tls_ca_cert(server.cert_path("tls_ca_cert.pem"));
        // Keep request counts independent of retries and fail connection errors quickly.
        result.set_max_retry_count(0);
        result.set_connection_timeout_ms(500);
        result.set_request_timeout_ms(1000);
        return result;
    }
    nvattestation::CorimStore store() const {
        nvattestation::CorimStore result(options());
        EXPECT_EQ(result.add_allowed_url_prefix(server.url()),
                  nvattestation::Error::Ok);
        return result;
    }
    std::string fixture(const std::string &suffix = "") const {
        // Isolate counters by test name while sharing one server across the suite.
        return server.url() + "negative-cache/" +
               ::testing::UnitTest::GetInstance()->current_test_info()->name() +
               suffix;
    }
    int count(const std::string &url) const {
        // The /count endpoint reports fixture requests without incrementing the count.
        nvattestation::NvHttpClient client;
        EXPECT_EQ(nvattestation::NvHttpClient::create(client, "", options()),
                  nvattestation::Error::Ok);
        nvattestation::NvRequest request(
            url + "/count", nvattestation::NvHttpMethod::HTTP_METHOD_GET);
        long status = 0;
        std::string body;
        EXPECT_EQ(client.do_request_as_string(request, status, body),
                  nvattestation::Error::Ok);
        EXPECT_EQ(status, 200);
        return nlohmann::json::parse(body).at("count").get<int>();
    }
};

LocalHttpsTestServer CorimNegativeCacheTest::server;
bool CorimNegativeCacheTest::ready = false;

TEST_F(CorimNegativeCacheTest, NegativeCacheSuppressesRepeated404) {
    // Two not-found results must come from one HTTP request; a second would return 200.
    auto subject = store();
    subject.enable_negative_cache(1048576, 600);
    std::vector<uint8_t> bytes{42};
    std::string effective;
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes, &effective),
              nvattestation::Error::RimNotFound);
    EXPECT_TRUE(bytes.empty());
    bytes = {42};
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes, &effective),
              nvattestation::Error::RimNotFound);
    EXPECT_TRUE(bytes.empty());
    EXPECT_EQ(effective, fixture() + "/rim");
    EXPECT_EQ(count(fixture()), 1);
}

TEST_F(CorimNegativeCacheTest, NegativeCacheDisabledByDefault) {
    // Without opting in, the second fetch reaches the server and sees the available RIM.
    auto subject = store();
    std::vector<uint8_t> bytes;
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::RimNotFound);
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::Ok);
    EXPECT_EQ(count(fixture()), 2);
}

TEST_F(CorimNegativeCacheTest, NegativeHitClearsAllOutputs) {
    auto subject = store();
    subject.enable_negative_cache(1048576, 600);
    // Seed stale outputs before both the live 404 and the cached result.
    for (int i = 0; i < 2; ++i) {
        std::vector<uint8_t> bytes{1}, coev{2};
        bool present = true;
        std::string digest = "stale", effective;
        EXPECT_EQ(subject.fetch_with_coev(fixture() + "/rim", bytes, coev,
                                          present, digest, &effective),
                  nvattestation::Error::RimNotFound);
        EXPECT_TRUE(bytes.empty());
        EXPECT_TRUE(coev.empty());
        EXPECT_FALSE(present);
        EXPECT_TRUE(digest.empty());
        EXPECT_EQ(effective, fixture() + "/rim");
    }
    EXPECT_EQ(count(fixture()), 1);
}

TEST_F(CorimNegativeCacheTest, NegativeMarkerIsNotReinsertedOnHit) {
    // Observe cache writes directly: a hit must reuse the marker without reinserting it.
    auto subject = store();
    auto cache = std::make_shared<RecordingNegativeCache>();
    subject.set_negative_cache(cache);
    std::vector<uint8_t> bytes;
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::RimNotFound);
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::RimNotFound);
    EXPECT_EQ(cache->puts, 1);
    EXPECT_TRUE(cache->nonnull);
    EXPECT_GT(cache->charge, (fixture() + "/rim").size());
    // Removing the marker must let the next fetch discover the server's 200 response.
    cache->clear();
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::Ok);
    EXPECT_EQ(count(fixture()), 2);
}

TEST_F(CorimNegativeCacheTest, NegativeCacheDoesNotSlideExpiry) {
    auto subject = store();
    subject.enable_negative_cache(1048576, 4);
    std::vector<uint8_t> bytes;
    ASSERT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::RimNotFound);
    const auto inserted = std::chrono::steady_clock::now();
    // NvCache uses whole-second timestamps; leave room on both sides of expiry.
    std::this_thread::sleep_until(inserted + std::chrono::milliseconds(2100));
    ASSERT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::RimNotFound);
    ASSERT_EQ(count(fixture()), 1);
    // Cross the original expiry; extending the TTL on the earlier hit would hide the RIM.
    std::this_thread::sleep_until(inserted + std::chrono::milliseconds(4100));
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::Ok);
    EXPECT_EQ(std::string(bytes.begin(), bytes.end()), "CORIM-BYTES-CBOR");
    EXPECT_EQ(count(fixture()), 2);
}

TEST_F(CorimNegativeCacheTest, NegativeCacheExpiryAllowsPublishedRim) {
    // After a short TTL, fetch again and verify the returned bytes as well as request count.
    auto subject = store();
    subject.enable_negative_cache(1048576, 1);
    std::vector<uint8_t> bytes;
    ASSERT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::RimNotFound);
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::Ok);
    EXPECT_EQ(std::string(bytes.begin(), bytes.end()), "CORIM-BYTES-CBOR");
    EXPECT_EQ(count(fixture()), 2);
}

TEST_F(CorimNegativeCacheTest,
       NegativeCacheUsesEffectiveUrlAndAuthorizesRawUrl) {
    // Two allowed locators share one destination; an untrusted locator must still fail.
    auto subject = store();
    subject.enable_negative_cache(1048576, 600);
    ASSERT_EQ(subject.add_url_rewrite("https://rim.attestation.nvidia.com/a",
                                      fixture() + "/rim"),
              nvattestation::Error::Ok);
    ASSERT_EQ(subject.add_url_rewrite("https://rim.attestation.nvidia.com/b",
                                      fixture() + "/rim"),
              nvattestation::Error::Ok);
    ASSERT_EQ(subject.add_url_rewrite("https://untrusted.example/a",
                                      fixture() + "/rim"),
              nvattestation::Error::Ok);
    std::vector<uint8_t> bytes;
    EXPECT_EQ(subject.fetch("https://rim.attestation.nvidia.com/a", bytes),
              nvattestation::Error::RimNotFound);
    EXPECT_EQ(subject.fetch("https://rim.attestation.nvidia.com/b", bytes),
              nvattestation::Error::RimNotFound);
    EXPECT_EQ(subject.fetch("https://untrusted.example/a", bytes),
              nvattestation::Error::BadArgument);
    EXPECT_EQ(count(fixture()), 1);
}

TEST_F(CorimNegativeCacheTest, OtherHttpErrorsRemainUncached) {
    // Each status is requested twice; neither response may suppress the next request.
    auto subject = store();
    subject.enable_negative_cache(1048576, 600);
    for (int status : {401, 403, 408, 429, 500, 502, 503, 504}) {
        const auto base = fixture(std::to_string(status));
        std::vector<uint8_t> bytes;
        for (int i = 0; i < 2; ++i) {
            EXPECT_NE(subject.fetch(base + "/status/" + std::to_string(status),
                                    bytes),
                      nvattestation::Error::Ok);
        }
        EXPECT_EQ(count(base), 2);
    }
}

TEST_F(CorimNegativeCacheTest, Non404FailuresDoNotInsertNegativeEntries) {
    // Invalid JSON, a missing file and a failed connection must produce no cache writes.
    // The missing file also returns RimNotFound, so the error code alone is insufficient.
    auto subject = store();
    auto cache = std::make_shared<RecordingNegativeCache>();
    subject.set_negative_cache(cache);
    std::vector<uint8_t> bytes;
    EXPECT_NE(subject.fetch(fixture() + "/malformed", bytes),
              nvattestation::Error::Ok);
    ASSERT_EQ(
        subject.add_url_rewrite("https://rim.attestation.nvidia.com/local",
                                "file:///nonexistent/rim.cbor"),
        nvattestation::Error::Ok);
    EXPECT_EQ(subject.fetch("https://rim.attestation.nvidia.com/local", bytes),
              nvattestation::Error::RimNotFound);
    ASSERT_EQ(
        subject.add_url_rewrite("https://rim.attestation.nvidia.com/network",
                                "http://127.0.0.1:9/rim"),
        nvattestation::Error::Ok);
    EXPECT_NE(
        subject.fetch("https://rim.attestation.nvidia.com/network", bytes),
        nvattestation::Error::Ok);
    EXPECT_EQ(cache->puts, 0);
}

TEST_F(CorimNegativeCacheTest, NegativeCapacityEvictsMarkers) {
    auto subject = store();
    std::vector<uint8_t> bytes;
    const auto a = fixture("a") + "/rim", b = fixture("b") + "/rim";
    // Fit exactly one marker: A must hit initially, then be evicted when B is inserted.
    subject.enable_negative_cache(a.size() + sizeof(bool), 600);
    EXPECT_EQ(subject.fetch(a, bytes), nvattestation::Error::RimNotFound);
    EXPECT_EQ(subject.fetch(a, bytes), nvattestation::Error::RimNotFound);
    EXPECT_EQ(count(fixture("a")), 1);
    EXPECT_EQ(subject.fetch(b, bytes), nvattestation::Error::RimNotFound);
    EXPECT_EQ(subject.fetch(a, bytes), nvattestation::Error::Ok);
    EXPECT_EQ(count(fixture("a")), 2);
}

TEST_F(CorimNegativeCacheTest, OversizedNegativeEntryIsNotCached) {
    // A one-byte budget cannot hold the URL and marker; the second fetch must reach the server.
    auto subject = store();
    subject.enable_negative_cache(1, 600);
    std::vector<uint8_t> bytes;
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::RimNotFound);
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::Ok);
    EXPECT_EQ(count(fixture()), 2);
}

TEST_F(CorimNegativeCacheTest, NegativeCacheReconfigureClearsEntries) {
    // Disabling the cache and replacing it must both discard old not-found markers.
    auto subject = store();
    subject.enable_negative_cache(1048576, 600);
    std::vector<uint8_t> bytes;
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::RimNotFound);
    subject.enable_negative_cache(1048576, 0);
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::Ok);
    EXPECT_EQ(count(fixture()), 2);
    subject.enable_negative_cache(1048576, 600);
    EXPECT_EQ(subject.fetch(fixture("again") + "/rim", bytes),
              nvattestation::Error::RimNotFound);
    subject.enable_negative_cache(1048576, 600);
    EXPECT_EQ(subject.fetch(fixture("again") + "/rim", bytes),
              nvattestation::Error::Ok);
}

TEST_F(CorimNegativeCacheTest, NegativeBackendFailuresPreserveFetchResults) {
    // Failed cache reads/writes must leave the live 404 and subsequent 200 unchanged.
    auto subject = store();
    auto cache = std::make_shared<RecordingNegativeCache>();
    cache->fail_put = true;
    cache->fail_get = true;
    subject.set_negative_cache(cache);
    std::vector<uint8_t> bytes;
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::RimNotFound);
    EXPECT_EQ(subject.fetch(fixture() + "/rim", bytes),
              nvattestation::Error::Ok);
    EXPECT_EQ(count(fixture()), 2);
}

TEST_F(CorimNegativeCacheTest, PositiveCacheIndependentOfNegativeCache) {
    // Try both setup orders, then make the caches disagree about a previously fetched RIM.
    for (bool negative_first : {false, true}) {
        auto subject = store();
        auto negative = std::make_shared<RecordingNegativeCache>();
        if (negative_first) {
            subject.set_negative_cache(negative);
        }
        subject.enable_in_memory_cache(1048576, 3600);
        if (!negative_first) {
            subject.set_negative_cache(negative);
        }
        const auto url = server.url() + "rim-service-with-coev";
        std::vector<uint8_t> bytes, coev;
        bool present = false;
        std::string digest;
        ASSERT_EQ(subject.fetch_with_coev(url, bytes, coev, present, digest),
                  nvattestation::Error::Ok);
        ASSERT_TRUE(present);
        // The positive entry must win over this injected 404 and retain its CoEV data.
        negative->put(url, std::make_shared<bool>(true), 512);
        EXPECT_EQ(subject.fetch_with_coev(url, bytes, coev, present, digest),
                  nvattestation::Error::Ok);
        EXPECT_EQ(bytes, (std::vector<uint8_t>{1, 2, 3}));
        EXPECT_EQ(coev, (std::vector<uint8_t>{0xaa, 0xbb}));
        EXPECT_TRUE(present);
    }
}
