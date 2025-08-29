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

using namespace nvattestation;

TEST(NvHttpClient, DISABLED_GetAsString) {
    NvHttpClient client;
    Error error = NvHttpClient::create(client);
    NvRequest request("https://httpbin.org/get", NvHttpMethod::HTTP_METHOD_GET);
    long status;
    std::string response;
    error = client.do_request_as_string(request, status, response);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_EQ(status, NvHttpStatus::HTTP_STATUS_OK);
    ASSERT_FALSE(response.empty());
}

TEST(NvHttpClient, DISABLED_GetAsStruct) {
    NvHttpClient client;
    Error error = NvHttpClient::create(client);
    NvRequest request("https://httpbin.org/get", NvHttpMethod::HTTP_METHOD_GET);
    long status;
    nlohmann::json json_response;
    error = client.do_request_as_json_struct(request, status, json_response);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_EQ(status, NvHttpStatus::HTTP_STATUS_OK);
    ASSERT_FALSE(json_response.empty());
    ASSERT_EQ(json_response["url"], "https://httpbin.org/get");
    ASSERT_EQ(json_response["headers"]["Host"], "httpbin.org");
}

TEST(NvHttpClient, DISABLED_PostAsString) {
    NvHttpClient client;
    Error error = NvHttpClient::create(client);
    NvRequest request("https://httpbin.org/post", NvHttpMethod::HTTP_METHOD_POST, {}, "{\"test\": \"test\"}");
    long status;
    std::string response;
    error = client.do_request_as_string(request, status, response);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_EQ(status, NvHttpStatus::HTTP_STATUS_OK);
    LOG_DEBUG("response: " << response);
}

TEST(NvHttpClient, DISABLED_PostAsStruct) {
    NvHttpClient client;
    Error error = NvHttpClient::create(client);
    NvRequest request("https://httpbin.org/post", NvHttpMethod::HTTP_METHOD_POST, {}, "{\"test\": \"test\"}");
    long status;
    nlohmann::json json_response;
    error = client.do_request_as_json_struct(request, status, json_response);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_EQ(status, NvHttpStatus::HTTP_STATUS_OK);
    ASSERT_EQ(json_response["url"], "https://httpbin.org/post");
    ASSERT_EQ(json_response["headers"]["Host"], "httpbin.org");
}
