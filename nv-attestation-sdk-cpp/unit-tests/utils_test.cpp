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