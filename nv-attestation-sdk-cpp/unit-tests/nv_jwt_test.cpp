/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
 */

#include <array>
#include <chrono>
#include <string>
#include <utility>

#include <jwt-cpp/jwt.h>
#include "jwt-cpp/traits/nlohmann-json/traits.h"
#include "gtest/gtest.h"

#include "nv_attestation/nv_jwt.h"
#include "nv_attestation/utils.h"

using nvattestation::Error;
using nvattestation::Jwk;
using nvattestation::JwtValidationOptions;
using nvattestation::NvJwt;

class NvJwtValidationTest : public ::testing::Test {
  protected:
    static constexpr const char* kIssuer = "https://verifier.example";
    static constexpr const char* kKid = "test-kid";
    std::string m_private_key;
    std::string m_public_key;

    void SetUp() override {
        ASSERT_EQ(nvattestation::readFileIntoString(
                      "testdata/x509_cert_chain/ec_p384_private.pem",
                      m_private_key),
                  Error::Ok);
        ASSERT_EQ(nvattestation::readFileIntoString(
                      "testdata/x509_cert_chain/ec_p384_public.pem",
                      m_public_key),
                  Error::Ok);
    }

    std::string sign(
        std::chrono::system_clock::time_point issued_at,
        std::chrono::system_clock::time_point not_before,
        std::chrono::system_clock::time_point expires_at) const {
        return jwt::create<jwt::traits::nlohmann_json>()
            .set_issuer(kIssuer)
            .set_issued_at(issued_at)
            .set_not_before(not_before)
            .set_expires_at(expires_at)
            .set_header_claim(
                "kid", jwt::basic_claim<jwt::traits::nlohmann_json>(
                           std::string(kKid)))
            .set_payload_claim(
                "value", jwt::basic_claim<jwt::traits::nlohmann_json>(42))
            .sign(jwt::algorithm::es384("", m_private_key, "", ""));
    }

    Jwk jwk() const {
        return Jwk{kKid, m_public_key};
    }

    Error validate(const std::string& token,
                   const JwtValidationOptions& options,
                   std::string& payload,
                   bool require_nonempty_kid = true,
                   std::chrono::system_clock::time_point now =
                       std::chrono::system_clock::time_point(
                           std::chrono::seconds(1700000000))) const {
        return NvJwt::validate_and_decode(
            token, jwk(), options, kIssuer, Error::NrasTokenInvalid,
            require_nonempty_kid, now, payload);
    }
};

constexpr const char* NvJwtValidationTest::kIssuer;
constexpr const char* NvJwtValidationTest::kKid;

TEST_F(NvJwtValidationTest, DirectKeyVerificationReturnsPayload) {
    JwtValidationOptions options;

    std::string payload;
    const auto now = std::chrono::system_clock::time_point(
        std::chrono::seconds(1700000000));
    ASSERT_EQ(validate(sign(now, now, now + std::chrono::minutes(5)),
                       options, payload),
              Error::Ok);

    const auto json = nlohmann::json::parse(payload);
    EXPECT_EQ(json.at("iss"), kIssuer);
    EXPECT_EQ(json.at("value"), 42);
}

TEST_F(NvJwtValidationTest, InvalidSignatureUsesCallerErrorAndClearsOutput) {
    JwtValidationOptions options;
    const auto now = std::chrono::system_clock::time_point(
        std::chrono::seconds(1700000000));
    std::string token = sign(now, now, now + std::chrono::minutes(5));
    token.back() = token.back() == 'A' ? 'B' : 'A';
    std::string payload = "stale";

    EXPECT_EQ(validate(token, options, payload),
              Error::NrasTokenInvalid);
    EXPECT_TRUE(payload.empty());
}

TEST_F(NvJwtValidationTest, EmptyKidIsRejectedWhenRequired) {
    const std::string token =
        jwt::create<jwt::traits::nlohmann_json>()
            .set_issuer(kIssuer)
            .set_issued_at(std::chrono::system_clock::time_point(
                std::chrono::seconds(1700000000)))
            .set_not_before(std::chrono::system_clock::time_point(
                std::chrono::seconds(1700000000)))
            .set_expires_at(std::chrono::system_clock::time_point(
                std::chrono::seconds(1700000300)))
            .set_header_claim(
                "kid", jwt::basic_claim<jwt::traits::nlohmann_json>(
                           std::string()))
            .sign(jwt::algorithm::es384("", m_private_key, "", ""));
    JwtValidationOptions options;

    std::string payload;
    EXPECT_EQ(NvJwt::validate_and_decode(
                  token, jwk(), options, kIssuer, Error::NrasTokenInvalid, true,
                  std::chrono::system_clock::time_point(
                      std::chrono::seconds(1700000000)), payload),
              Error::NrasTokenInvalid);
}

TEST_F(NvJwtValidationTest, DefaultLeewayAccepts59SecondsAndRejects61Seconds) {
    const auto now = std::chrono::system_clock::time_point(
        std::chrono::seconds(1700000000));
    JwtValidationOptions options;
    std::string payload;

    EXPECT_EQ(validate(sign(now + std::chrono::seconds(59), now,
                            now + std::chrono::minutes(5)), options, payload),
              Error::Ok);
    EXPECT_EQ(validate(sign(now + std::chrono::seconds(61), now,
                            now + std::chrono::minutes(5)), options, payload),
              Error::NrasTokenInvalid);
    EXPECT_EQ(validate(sign(now, now + std::chrono::seconds(59),
                            now + std::chrono::minutes(5)), options, payload),
              Error::Ok);
    EXPECT_EQ(validate(sign(now, now + std::chrono::seconds(61),
                            now + std::chrono::minutes(5)), options, payload),
              Error::NrasTokenInvalid);
    EXPECT_EQ(validate(sign(now - std::chrono::minutes(5), now,
                            now - std::chrono::seconds(59)), options, payload),
              Error::Ok);
    EXPECT_EQ(validate(sign(now - std::chrono::minutes(5), now,
                            now - std::chrono::seconds(61)), options, payload),
              Error::NrasTokenInvalid);
}

TEST_F(NvJwtValidationTest, ZeroAndCustomLeewayApplyToAllTimeClaims) {
    const auto now = std::chrono::system_clock::time_point(
        std::chrono::seconds(1700000000));
    JwtValidationOptions zero_leeway;
    zero_leeway.clock_skew_leeway_seconds = 0;
    JwtValidationOptions custom_leeway;
    custom_leeway.clock_skew_leeway_seconds = 120;
    std::string payload;

    EXPECT_EQ(validate(sign(now + std::chrono::seconds(59), now,
                            now + std::chrono::minutes(5)), zero_leeway, payload),
              Error::NrasTokenInvalid);
    EXPECT_EQ(validate(sign(now, now + std::chrono::seconds(59),
                            now + std::chrono::minutes(5)), zero_leeway, payload),
              Error::NrasTokenInvalid);
    EXPECT_EQ(validate(sign(now - std::chrono::minutes(5), now,
                            now - std::chrono::seconds(59)), zero_leeway, payload),
              Error::NrasTokenInvalid);
    EXPECT_EQ(validate(sign(now + std::chrono::seconds(61), now,
                            now + std::chrono::minutes(5)), custom_leeway, payload),
              Error::Ok);
    EXPECT_EQ(validate(sign(now, now + std::chrono::seconds(61),
                            now + std::chrono::minutes(5)), custom_leeway, payload),
              Error::Ok);
    EXPECT_EQ(validate(sign(now - std::chrono::minutes(5), now,
                            now - std::chrono::seconds(61)), custom_leeway, payload),
              Error::Ok);
}

TEST_F(NvJwtValidationTest, TimeFailuresUseDistinctFixedDiagnostics) {
    const auto now = std::chrono::system_clock::time_point(
        std::chrono::seconds(1700000000));
    JwtValidationOptions options;
    const std::array<std::pair<std::string, const char*>, 3> cases = {{
        {sign(now - std::chrono::minutes(5), now,
              now - std::chrono::seconds(61)), "JWT expired"},
        {sign(now, now + std::chrono::seconds(61),
              now + std::chrono::minutes(5)), "JWT not yet valid (nbf)"},
        {sign(now + std::chrono::seconds(61), now,
              now + std::chrono::minutes(5)), "JWT issued in the future (iat)"},
    }};
    for (const auto& test_case : cases) {
        std::string payload;
        testing::internal::CaptureStderr();
        EXPECT_EQ(validate(test_case.first, options, payload),
                  Error::NrasTokenInvalid);
        const std::string logs = testing::internal::GetCapturedStderr();
        EXPECT_NE(logs.find(test_case.second), std::string::npos) << logs;
    }
}
