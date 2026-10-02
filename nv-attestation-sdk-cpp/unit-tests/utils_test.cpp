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

//third party
#include "gtest/gtest.h"
#include "gmock/gmock.h"

//this sdk
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"
#include "nvat.h"

using namespace nvattestation;
using ::testing::Return;
using ::testing::_;

class UtilsTest : public ::testing::Test {
    protected:
        void SetUp() override {
        }
};

TEST_F(UtilsTest, ToHexStringUppercase) {
    EXPECT_EQ(to_hex_string(std::vector<uint8_t>{0x00, 0xFF, 0x0A}, /*uppercase=*/true), "00FF0A");
    EXPECT_EQ(to_hex_string(std::vector<uint8_t>{0x00, 0xFF, 0x0A}), "00ff0a");
    EXPECT_EQ(to_hex_string(std::vector<uint8_t>{}, /*uppercase=*/true), "");
}

TEST_F(UtilsTest, GenerateValidNonceLengths) {
    std::vector<size_t> lengths = {32, 64, 128};
    for (const auto length : lengths) {
        std::vector<uint8_t> buf(length, 0);
        Error err = generate_nonce(buf);
        ASSERT_EQ(err, Error::Ok) << "checking nonce length " << length;
        bool allZero = true;
        for (const auto x : buf) {
            if (x != 0) {
                allZero = false;
                break;
            }
        }
        ASSERT_FALSE(allZero) << "generated nonce cannot be all zeros";
    }
}


TEST_F(UtilsTest, GenerateInvalidNonceLengths) {
    std::vector<size_t> lengths = {0, 31};
    for (const auto length : lengths) {
        std::vector<uint8_t> buf(length, 0);
        Error err = generate_nonce(buf);
        ASSERT_EQ(err, Error::BadArgument) << "checking nonce length " << length;
        for (const auto x : buf) {
            ASSERT_EQ(x, 0) << "buffer was not modified";
        }
    }
}

class ParseUriTest : public ::testing::Test {
protected:
    void SetUp() override {}
    
    void TestValidUrl(const std::string& url, 
                     const std::string& expected_scheme,
                     const std::string& expected_host,
                     const std::string& expected_port,
                     const std::string& expected_path) {
        std::string scheme, host, port, path;
        Error err = parse_uri(url, scheme, host, port, path);
        
        ASSERT_EQ(err, Error::Ok) << "testing URL " << url;
        ASSERT_EQ(scheme, expected_scheme) << "testing URL scheme" << url;
        ASSERT_EQ(host, expected_host) << "testing URL host" << url;
        ASSERT_EQ(port, expected_port) << "testing URL port" << url;
        ASSERT_EQ(path, expected_path) << "testing URL path" << url;
    }
    
    void TestInvalidUrl(const std::string& url) {
        std::string scheme, host, port, path;
        Error err = parse_uri(url, scheme, host, port, path);
        ASSERT_NE(err, Error::Ok) << "testing URL " << url;
    }
};

TEST_F(ParseUriTest, HttpUrls) {
    TestValidUrl("http://example.com", "http", "example.com", "80", "/");
    TestValidUrl("http://example.com:80", "http", "example.com", "80", "/");
    TestValidUrl("http://example.com:80/", "http", "example.com", "80", "/");
}

TEST_F(ParseUriTest, HttpsUrls) {
    TestValidUrl("https://example.com", "https", "example.com", "443", "/");
    TestValidUrl("https://example.com:443", "https", "example.com", "443", "/");
    TestValidUrl("https://example.com:443/", "https", "example.com", "443", "/");
}

TEST_F(ParseUriTest, InvalidUrls) {
    TestInvalidUrl("bad://example.com");
    TestInvalidUrl("https://@:443");
    TestInvalidUrl("https://example.com:a/");
}

class CustomLoggerTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

class TestUserData {
public:
    bool called_log;
    bool called_flush;
    bool called_should_log;
};


bool test_should_log(nvat_log_level_t level, const char* filename, const char* function, int line, void* user_data) {
    auto data = static_cast<TestUserData*>(user_data);
    data->called_should_log = true;
    return true;
};

void test_log(nvat_log_level_t level, const char* message, const char* filename, const char* function, int line, void* user_data) {
    ASSERT_NE(user_data, nullptr);
    auto data = static_cast<TestUserData*>(user_data);
    data->called_log = true;
}

void test_flush(void* user_data) {
    ASSERT_NE(user_data, nullptr);
    auto data = static_cast<TestUserData*>(user_data);
    data->called_flush = true;
}

TEST_F(CustomLoggerTest, SimpleCustomLoggerTest) {
    auto data = new TestUserData();
    auto logger = CallbackLogger(
        test_should_log,
        test_log,
        test_flush,
        data
    );
    ASSERT_TRUE(logger.should_log(LogLevel::INFO, __FILE__, __FUNCTION__, __LINE__));
    logger.log(LogLevel::INFO, "test message!", __FILE__, __FUNCTION__, __LINE__);
    logger.flush();

    ASSERT_TRUE(data->called_should_log) << "should_log was called";
    ASSERT_TRUE(data->called_log) << "log was called";
    ASSERT_TRUE(data->called_flush) << "flush was called";
    delete data;
}

TEST_F(CustomLoggerTest, NullLoggerTest) {
    auto logger = CallbackLogger(nullptr, nullptr, nullptr, nullptr);
    // invoke methods. should be safe despite null functions
    ASSERT_TRUE(logger.should_log(LogLevel::INFO, __FILE__, __FUNCTION__, __LINE__));
    logger.log(LogLevel::INFO, "test message!", __FILE__, __FUNCTION__, __LINE__);
    logger.flush();
}

TEST(Base64UrlTest, RoundTripAllTailLengths) {
    // Cover each residue of len % 3 (0, 1, 2) to exercise both tail branches.
    for (std::size_t len = 0; len <= 8; ++len) {
        std::vector<uint8_t> input(len);
        for (std::size_t i = 0; i < len; ++i) {
            input[i] = static_cast<uint8_t>(i * 37 + 11);
        }
        std::string encoded;
        ASSERT_EQ(encode_base64url(input, encoded), Error::Ok) << "len=" << len;
        EXPECT_EQ(encoded.find('='), std::string::npos) << "len=" << len;
        std::vector<uint8_t> decoded;
        ASSERT_EQ(decode_base64url(encoded, decoded), Error::Ok) << "len=" << len;
        EXPECT_EQ(decoded, input) << "len=" << len;
    }
}

TEST(Base64UrlTest, EncodesUrlSafeAlphabet) {
    // 0xFB 0xFF 0xFE encodes to the two chars that differ from standard base64
    // ('-' and '_'), proving the URL-safe alphabet is used.
    std::vector<uint8_t> input = {0xFB, 0xFF, 0xFE};
    std::string encoded;
    ASSERT_EQ(encode_base64url(input, encoded), Error::Ok);
    EXPECT_EQ(encoded, "-__-");
}

TEST(Base64UrlTest, RejectsPadding) {
    std::vector<uint8_t> out;
    EXPECT_EQ(decode_base64url("QQ==", out), Error::BadArgument);
}

TEST(Base64UrlTest, RejectsInvalidCharacter) {
    std::vector<uint8_t> out;
    EXPECT_EQ(decode_base64url("AB*D", out), Error::BadArgument);
}

TEST(Base64UrlTest, RejectsImpossibleLength) {
    std::vector<uint8_t> out;
    // 5 chars == 1 (mod 4): no byte string base64url-encodes to this length.
    EXPECT_EQ(decode_base64url("QUJDQ", out), Error::BadArgument);
}

TEST(Base64UrlTest, EmptyRoundTrips) {
    std::string encoded = "stale";
    ASSERT_EQ(encode_base64url({}, encoded), Error::Ok);
    EXPECT_EQ(encoded, "");
    std::vector<uint8_t> out = {1, 2, 3};
    ASSERT_EQ(decode_base64url("", out), Error::Ok);
    EXPECT_TRUE(out.empty());
}

TEST_F(UtilsTest, RequireHttpsAndNormalizeAcceptsHttpsUrl) {
    std::string normalized;
    ASSERT_EQ(require_https_and_normalize("https://nras.example.com", normalized), Error::Ok);
    EXPECT_EQ(normalized, "https://nras.example.com");
}

TEST_F(UtilsTest, RequireHttpsAndNormalizeTrimsTrailingSlashes) {
    std::string normalized;
    ASSERT_EQ(require_https_and_normalize("https://nras.example.com///", normalized), Error::Ok);
    EXPECT_EQ(normalized, "https://nras.example.com");
}

TEST_F(UtilsTest, RequireHttpsAndNormalizeRejectsNonHttpsScheme) {
    std::string normalized;
    EXPECT_EQ(require_https_and_normalize("http://nras.example.com", normalized), Error::BadArgument);
    EXPECT_EQ(require_https_and_normalize("ftp://nras.example.com", normalized), Error::BadArgument);
    // A bare host with no scheme is also rejected.
    EXPECT_EQ(require_https_and_normalize("nras.example.com", normalized), Error::BadArgument);
}
// IANA Named Information registry IDs used by CoRIM/CoEV digest records.
TEST(HashAlgorithmTest, NiAlgorithmIds) {
    EXPECT_EQ(to_ni_algorithm_id(HashAlgorithm::Sha256), 1);
    EXPECT_EQ(to_ni_algorithm_id(HashAlgorithm::Sha384), 7);
    EXPECT_EQ(to_ni_algorithm_id(HashAlgorithm::Sha512), 8);
}

TEST(HashAlgorithmTest, EvpDigests) {
    const EVP_MD* digest = nullptr;

    ASSERT_EQ(evp_md_for_hash_algorithm(HashAlgorithm::Sha256, digest),
              Error::Ok);
    EXPECT_EQ(EVP_MD_get_type(digest), NID_sha256);

    ASSERT_EQ(evp_md_for_hash_algorithm(HashAlgorithm::Sha384, digest),
              Error::Ok);
    EXPECT_EQ(EVP_MD_get_type(digest), NID_sha384);

    ASSERT_EQ(evp_md_for_hash_algorithm(HashAlgorithm::Sha512, digest),
              Error::Ok);
    EXPECT_EQ(EVP_MD_get_type(digest), NID_sha512);

    EXPECT_EQ(evp_md_for_hash_algorithm(static_cast<HashAlgorithm>(99), digest),
              Error::BadArgument);
    EXPECT_EQ(digest, nullptr);
}

constexpr std::size_t kSha256DigestBytes = 32;
constexpr std::size_t kSha384DigestBytes = 48;
constexpr std::size_t kSha512DigestBytes = 64;
constexpr std::size_t kSha1DigestBytes = 20;

TEST(HashAlgorithmTest, FromDigestSizeMapsKnownLengths) {
    HashAlgorithm alg = HashAlgorithm::Sha256;
    ASSERT_EQ(hash_algorithm_from_digest_size(kSha256DigestBytes, alg), Error::Ok);
    EXPECT_EQ(alg, HashAlgorithm::Sha256);
    ASSERT_EQ(hash_algorithm_from_digest_size(kSha384DigestBytes, alg), Error::Ok);
    EXPECT_EQ(alg, HashAlgorithm::Sha384);
    ASSERT_EQ(hash_algorithm_from_digest_size(kSha512DigestBytes, alg), Error::Ok);
    EXPECT_EQ(alg, HashAlgorithm::Sha512);
}

TEST(HashAlgorithmTest, FromDigestSizeRejectsUnknownLengths) {
    HashAlgorithm alg = HashAlgorithm::Sha384;
    EXPECT_EQ(hash_algorithm_from_digest_size(0, alg), Error::BadArgument);
    // SHA-1 length, and one byte short of SHA-384.
    EXPECT_EQ(hash_algorithm_from_digest_size(kSha1DigestBytes, alg),
              Error::BadArgument);
    EXPECT_EQ(hash_algorithm_from_digest_size(kSha384DigestBytes - 1, alg),
              Error::BadArgument);
    // Left untouched on failure.
    EXPECT_EQ(alg, HashAlgorithm::Sha384);
}
