/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
 */

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <string>
#include <vector>

#include <unistd.h>

#include "gtest/gtest.h"
#include <jwt-cpp/jwt.h>
#include "jwt-cpp/traits/nlohmann-json/traits.h"
#include <nlohmann/json.hpp>
#include <openssl/pem.h>

#include "local_https_test_server.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/ear_mapper.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/verify.h"
#include "nvat.h"

using nvattestation::DetachedEATOptions;
using nvattestation::Error;
using nvattestation::HttpOptions;

constexpr const char* kProfile =
    "tag:nvidia.com,2026:ear/profiles/composite/generic/1.0.0";

static std::string pem_cert_to_x5c_b64(const std::string& pem) {
    static const std::string kBegin = "-----BEGIN CERTIFICATE-----";
    static const std::string kEnd = "-----END CERTIFICATE-----";
    const auto start = pem.find(kBegin);
    const auto end = pem.find(kEnd);
    if (start == std::string::npos || end == std::string::npos) {
        return "";
    }
    const auto body_start = start + kBegin.size();
    const std::string body = pem.substr(body_start, end - body_start);
    std::string out;
    for (char ch : body) {
        if (ch != '\n' && ch != '\r' && ch != ' ' && ch != '\t') {
            out.push_back(ch);
        }
    }
    return out;
}

static std::string expire_certificate(const std::string& certificate_pem,
                                      const std::string& private_key_pem) {
    auto certificate = nvattestation::x509_from_cert_string(certificate_pem);
    nvattestation::nv_unique_ptr<BIO> key_bio(BIO_new_mem_buf(
        private_key_pem.data(), static_cast<int>(private_key_pem.size())));
    nvattestation::nv_unique_ptr<EVP_PKEY> private_key(
        key_bio == nullptr
            ? nullptr
            : PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
    if (certificate == nullptr || private_key == nullptr ||
        X509_gmtime_adj(X509_getm_notAfter(certificate.get()), -3600) == nullptr ||
        X509_sign(certificate.get(), private_key.get(), EVP_sha384()) <= 0) {
        return "";
    }
    nvattestation::nv_unique_ptr<BIO> output(BIO_new(BIO_s_mem()));
    if (output == nullptr || PEM_write_bio_X509(output.get(), certificate.get()) != 1) {
        return "";
    }
    BUF_MEM* contents = nullptr;
    BIO_get_mem_ptr(output.get(), &contents);
    if (contents == nullptr || contents->data == nullptr) {
        return "";
    }
    return std::string(contents->data, contents->length);
}

static std::string replace_payload(const std::string& token,
                            const nlohmann::json& payload) {
    const auto first_dot = token.find('.');
    const auto last_dot = token.rfind('.');
    if (first_dot == std::string::npos || last_dot == first_dot) {
        return token;
    }
    const std::string serialized = payload.dump();
    std::vector<uint8_t> bytes(serialized.begin(), serialized.end());
    std::string encoded;
    if (nvattestation::encode_base64url(bytes, encoded) != Error::Ok) {
        return token;
    }
    return token.substr(0, first_dot + 1) + encoded + token.substr(last_dot);
}

static std::string base64url_encode(const std::string& value) {
    std::vector<uint8_t> bytes(value.begin(), value.end());
    std::string encoded;
    if (nvattestation::encode_base64url(bytes, encoded) != Error::Ok) {
        return "";
    }
    return encoded;
}

class VerifyEarServerTest : public ::testing::Test {
  protected:
    static constexpr const char* KID = "nvat-test-kid";
    static LocalHttpsTestServer m_server;
    static LocalHttpsTestServer m_malformed_jwks_server;
    static LocalHttpsTestServer m_missing_keys_server;
    static LocalHttpsTestServer m_invalid_keys_server;
    static LocalHttpsTestServer m_invalid_key_material_server;
    static LocalHttpsTestServer m_expired_leaf_server;
    static LocalHttpsTestServer m_valid_chain_server;
    static LocalHttpsTestServer m_wrong_issuer_server;
    static LocalHttpsTestServer m_redirect_server;
    static LocalHttpsTestServer m_redirect_target_server;
    static bool m_setup_ok;
    static std::string m_temp_dir;
    static std::vector<std::string> m_temp_files;
    static std::string m_base_url;
    static std::string m_malformed_jwks_url;
    static std::string m_missing_keys_url;
    static std::string m_invalid_keys_url;
    static std::string m_invalid_key_material_url;
    static std::string m_expired_leaf_url;
    static std::string m_valid_chain_url;
    static std::string m_wrong_issuer_url;
    static std::string m_redirect_url;
    static std::string m_base_headers_path;
    static std::string m_redirect_headers_path;
    static std::string m_redirect_target_headers_path;
    static std::string m_private_key;
    static std::string m_chain_leaf_private_key;
    static std::string m_ca_cert_path;

    static std::string temp_path(const std::string& filename) {
        const std::string path = m_temp_dir + "/" + filename;
        m_temp_files.push_back(path);
        return path;
    }

    static bool start_jwks_server(LocalHttpsTestServer& server,
                                  const std::string& path,
                                  const std::string& contents,
                                  std::string& out_url,
                                  const std::string& capture_headers_path = "",
                                  const std::string& redirect_url = "") {
        {
            std::ofstream out(path);
            if (!out) {
                return false;
            }
            out << contents;
            if (!out) {
                return false;
            }
        }
        if (!server.start(path, capture_headers_path, redirect_url)) {
            return false;
        }
        out_url = server.url();
        while (!out_url.empty() && out_url.back() == '/') {
            out_url.pop_back();
        }
        return true;
    }

    static void SetUpTestSuite() {
        m_setup_ok = false;
        const std::string tls_dir = "testdata/tls_test";
        const std::string x509_dir = "testdata/x509_cert_chain";
        m_ca_cert_path = tls_dir + "/tls_ca_cert.pem";

        char temp_dir_template[] = "/tmp/nvat_verify_ear_XXXXXX";
        const char* created_temp_dir = ::mkdtemp(temp_dir_template);
        if (created_temp_dir == nullptr) {
            return;
        }
        m_temp_dir = created_temp_dir;

        std::string leaf_pem;
        if (nvattestation::readFileIntoString(
                x509_dir + "/eat_jwks_leaf", leaf_pem) != Error::Ok ||
            nvattestation::readFileIntoString(
                x509_dir + "/eat_jwks_leaf_key.pem", m_private_key) != Error::Ok) {
            return;
        }
        const std::string x5c = pem_cert_to_x5c_b64(leaf_pem);
        if (x5c.empty()) {
            return;
        }
        nlohmann::json jwks = {
            {"keys", nlohmann::json::array({
                {{"kty", "EC"}, {"crv", "P-384"}, {"kid", KID},
                 {"x5c", nlohmann::json::array({x5c})}}
            })}
        };
        m_base_headers_path = temp_path("base_headers.json");
        if (!start_jwks_server(
                m_server, temp_path("valid_jwks.json"), jwks.dump(),
                m_base_url, m_base_headers_path)) {
            return;
        }
        const std::string expired_leaf_pem =
            expire_certificate(leaf_pem, m_private_key);
        if (expired_leaf_pem.empty()) {
            return;
        }
        nlohmann::json expired_jwks = jwks;
        expired_jwks["keys"][0]["x5c"][0] =
            pem_cert_to_x5c_b64(expired_leaf_pem);
        if (!start_jwks_server(
                m_expired_leaf_server,
                temp_path("expired_leaf_jwks.json"),
                expired_jwks.dump(), m_expired_leaf_url)) {
            return;
        }
        std::string chain_leaf_pem;
        std::string chain_issuer_pem;
        if (nvattestation::readFileIntoString(
                x509_dir + "/eat_jwks_chain_leaf", chain_leaf_pem) != Error::Ok ||
            nvattestation::readFileIntoString(
                x509_dir + "/eat_jwks_ca", chain_issuer_pem) != Error::Ok ||
            nvattestation::readFileIntoString(
                x509_dir + "/eat_jwks_chain_leaf_key.pem",
                m_chain_leaf_private_key) != Error::Ok) {
            return;
        }
        const std::string chain_leaf_x5c = pem_cert_to_x5c_b64(chain_leaf_pem);
        const std::string chain_issuer_x5c = pem_cert_to_x5c_b64(chain_issuer_pem);
        if (chain_leaf_x5c.empty() || chain_issuer_x5c.empty()) {
            return;
        }
        nlohmann::json valid_chain_jwks = {
            {"keys", nlohmann::json::array({
                {{"kty", "EC"}, {"crv", "P-384"}, {"kid", KID},
                 {"x5c", nlohmann::json::array(
                     {chain_leaf_x5c, chain_issuer_x5c})}}
            })}
        };
        if (!start_jwks_server(
                m_valid_chain_server, temp_path("valid_chain_jwks.json"),
                valid_chain_jwks.dump(), m_valid_chain_url)) {
            return;
        }
        nlohmann::json wrong_issuer_jwks = valid_chain_jwks;
        wrong_issuer_jwks["keys"][0]["x5c"][1] = x5c;
        if (!start_jwks_server(
                m_wrong_issuer_server, temp_path("wrong_issuer_jwks.json"),
                wrong_issuer_jwks.dump(), m_wrong_issuer_url)) {
            return;
        }
        if (!start_jwks_server(
                m_malformed_jwks_server,
                temp_path("malformed_jwks.json"),
                "MALFORMED_JWKS_RESPONSE_BODY::{not-json",
                m_malformed_jwks_url)) {
            return;
        }
        if (!start_jwks_server(
                m_missing_keys_server,
                temp_path("missing_keys_jwks.json"),
                R"({"not_keys":[]})", m_missing_keys_url)) {
            return;
        }
        if (!start_jwks_server(
                m_invalid_keys_server,
                temp_path("invalid_keys_jwks.json"),
                R"({"keys":{"not":"an array"}})", m_invalid_keys_url)) {
            return;
        }
        if (!start_jwks_server(
                m_invalid_key_material_server,
                temp_path("invalid_material_jwks.json"),
                R"({"keys":[{"kty":"EC","crv":"P-384","kid":"nvat-test-kid","x5c":["MALICIOUS_JWKS_KEY_MATERIAL"]}]})",
                m_invalid_key_material_url)) {
            return;
        }

        std::string redirect_target_url;
        m_redirect_target_headers_path = temp_path("redirect_target_headers.json");
        if (!start_jwks_server(
                m_redirect_target_server, temp_path("redirect_target_jwks.json"),
                jwks.dump(), redirect_target_url,
                m_redirect_target_headers_path)) {
            return;
        }
        m_redirect_headers_path = temp_path("redirect_headers.json");
        if (!start_jwks_server(
                m_redirect_server, temp_path("redirect_jwks.json"), jwks.dump(),
                m_redirect_url, m_redirect_headers_path,
                redirect_target_url + "/.well-known/jwks.json")) {
            return;
        }
        m_setup_ok = true;
    }

    static void TearDownTestSuite() {
        m_server.stop();
        m_malformed_jwks_server.stop();
        m_missing_keys_server.stop();
        m_invalid_keys_server.stop();
        m_invalid_key_material_server.stop();
        m_expired_leaf_server.stop();
        m_valid_chain_server.stop();
        m_wrong_issuer_server.stop();
        m_redirect_server.stop();
        m_redirect_target_server.stop();
        for (const auto& path : m_temp_files) {
            if (std::remove(path.c_str()) != 0 && errno != ENOENT) {
                ADD_FAILURE() << "Failed to remove temporary EAR fixture: "
                              << path;
            }
        }
        m_temp_files.clear();
        if (!m_temp_dir.empty()) {
            if (::rmdir(m_temp_dir.c_str()) != 0) {
                ADD_FAILURE() << "Failed to remove temporary EAR directory: "
                              << m_temp_dir;
            }
            m_temp_dir.clear();
        }
    }

    void SetUp() override {
        ASSERT_TRUE(m_setup_ok) << "JWKS test fixture setup failed";
    }

    nlohmann::json make_valid_ear(
        const std::string& issuer,
        const std::string& status = "affirming") {
        const auto now = static_cast<std::int64_t>(std::time(nullptr));
        return {
            {"iss", issuer},
            {"iat", now},
            {"nbf", now},
            {"exp", now + 3600},
            {"eat_profile", kProfile},
            {"ear_status", status},
            {"eat_nonce", "3q2-7w"},
            {"submods", {
                {"gpu-0", {
                    {"eat_profile", kProfile},
                    {"ear_status", status},
                    {"x-nvidia-submod-extension", "preserved"}
                }}
            }},
            {"x-nvidia-root-extension", {
                {"nested", true}, {"value", 42}
            }}
        };
    }

    std::string sign_test_ear(
        const nlohmann::json& ear,
        const std::string& kid = "nvat-test-kid",
        const std::string& private_key = "") {
        DetachedEATOptions options;
        options.m_private_key_pem =
            private_key.empty() ? m_private_key : private_key;
        options.m_kid = kid;
        std::string token;
        EXPECT_EQ(nvattestation::sign_ear(ear, options, token), Error::Ok);
        return token;
    }

    std::string sign_none(const nlohmann::json& ear) {
        DetachedEATOptions options;
        options.m_kid = KID;
        std::string token;
        EXPECT_EQ(nvattestation::sign_ear(ear, options, token), Error::Ok);
        return token;
    }

    std::string sign_hs256(const nlohmann::json& ear) {
        auto token = jwt::create<jwt::traits::nlohmann_json>();
        for (auto it = ear.begin(); it != ear.end(); ++it) {
            token.set_payload_claim(
                it.key(), jwt::basic_claim<jwt::traits::nlohmann_json>(it.value()));
        }
        token.set_header_claim(
            "kid", jwt::basic_claim<jwt::traits::nlohmann_json>(std::string(KID)));
        return token.sign(jwt::algorithm::hs256("test-secret"));
    }

    HttpOptions http_options() const {
        HttpOptions options;
        options.set_tls_ca_cert(m_ca_cert_path);
        return options;
    }

    nvat_http_options_t c_http_options() const {
        nvat_http_options_t options = nullptr;
        EXPECT_EQ(nvat_http_options_create_default(&options), NVAT_RC_OK);
        if (options != nullptr) {
            nvat_http_options_set_tls_ca_cert(options, m_ca_cert_path.c_str());
        }
        return options;
    }

    nvat_rc_t verify_c(
        const std::string& token, nvat_jwt_validation_options_t jwt_options,
        nvat_str_t* out) const {
        nvat_http_options_t options = c_http_options();
        if (options == nullptr) {
            return NVAT_RC_UNKNOWN;
        }
        const nvat_rc_t rc = nvat_verify_ear(
            token.c_str(), m_base_url.c_str(), nullptr, nullptr, options,
            jwt_options, out);
        nvat_http_options_free(&options);
        return rc;
    }

    Error verify(const std::string& token, std::string& out_ear_json,
                 const std::vector<uint8_t>& nonce = {},
                 const std::string& url = "",
                 const std::string& service_key = "",
                 std::size_t clock_skew_leeway_seconds = 60) const {
        nvattestation::JwtValidationOptions jwt_options;
        jwt_options.clock_skew_leeway_seconds = clock_skew_leeway_seconds;
        return nvattestation::verify_ear(
            token, url.empty() ? m_base_url : url, service_key,
            http_options(), jwt_options, nonce, out_ear_json);
    }

    static std::string captured_authorization(const std::string& path) {
        std::string contents;
        if (nvattestation::readFileIntoString(path, contents) != Error::Ok) {
            return "";
        }
        const auto headers = nlohmann::json::parse(contents, nullptr, false);
        if (!headers.is_object() || !headers.contains("Authorization") ||
            !headers.at("Authorization").is_string()) {
            return "";
        }
        return headers.at("Authorization").get<std::string>();
    }

    void expect_invalid(const std::string& token,
                        Error expected = Error::NrasTokenInvalid,
                        const std::vector<uint8_t>& nonce = {},
                        const std::string& url = "") const {
        std::string out = "must be cleared";
        EXPECT_EQ(verify(token, out, nonce, url), expected);
        EXPECT_TRUE(out.empty());
    }
};

LocalHttpsTestServer VerifyEarServerTest::m_server;
LocalHttpsTestServer VerifyEarServerTest::m_malformed_jwks_server;
LocalHttpsTestServer VerifyEarServerTest::m_missing_keys_server;
LocalHttpsTestServer VerifyEarServerTest::m_invalid_keys_server;
LocalHttpsTestServer VerifyEarServerTest::m_invalid_key_material_server;
LocalHttpsTestServer VerifyEarServerTest::m_expired_leaf_server;
LocalHttpsTestServer VerifyEarServerTest::m_valid_chain_server;
LocalHttpsTestServer VerifyEarServerTest::m_wrong_issuer_server;
LocalHttpsTestServer VerifyEarServerTest::m_redirect_server;
LocalHttpsTestServer VerifyEarServerTest::m_redirect_target_server;
constexpr const char* VerifyEarServerTest::KID;
bool VerifyEarServerTest::m_setup_ok = false;
std::string VerifyEarServerTest::m_temp_dir;
std::vector<std::string> VerifyEarServerTest::m_temp_files;
std::string VerifyEarServerTest::m_base_url;
std::string VerifyEarServerTest::m_malformed_jwks_url;
std::string VerifyEarServerTest::m_missing_keys_url;
std::string VerifyEarServerTest::m_invalid_keys_url;
std::string VerifyEarServerTest::m_invalid_key_material_url;
std::string VerifyEarServerTest::m_expired_leaf_url;
std::string VerifyEarServerTest::m_valid_chain_url;
std::string VerifyEarServerTest::m_wrong_issuer_url;
std::string VerifyEarServerTest::m_redirect_url;
std::string VerifyEarServerTest::m_base_headers_path;
std::string VerifyEarServerTest::m_redirect_headers_path;
std::string VerifyEarServerTest::m_redirect_target_headers_path;
std::string VerifyEarServerTest::m_private_key;
std::string VerifyEarServerTest::m_chain_leaf_private_key;
std::string VerifyEarServerTest::m_ca_cert_path;

class VerifyEarCapi : public VerifyEarServerTest {};

TEST_F(VerifyEarCapi, NullOptionsUseDefaultLeeway) {
    auto ear = make_valid_ear(m_base_url);
    ear["iat"] = static_cast<std::int64_t>(std::time(nullptr)) + 30;
    nvat_str_t out = nullptr;

    EXPECT_EQ(verify_c(sign_test_ear(ear), nullptr, &out), NVAT_RC_OK);
    ASSERT_NE(out, nullptr);
    nvat_str_free(&out);
}

TEST_F(VerifyEarCapi, CustomLeewayIsApplied) {
    auto ear = make_valid_ear(m_base_url);
    ear["iat"] = static_cast<std::int64_t>(std::time(nullptr)) + 90;
    nvat_jwt_validation_options_t options = nullptr;
    ASSERT_EQ(nvat_jwt_validation_options_create_default(&options), NVAT_RC_OK);
    ASSERT_NE(options, nullptr);
    nvat_jwt_validation_options_set_clock_skew_leeway_seconds(options, 120);
    nvat_str_t out = nullptr;

    EXPECT_EQ(verify_c(sign_test_ear(ear), options, &out), NVAT_RC_OK);
    ASSERT_NE(out, nullptr);
    nvat_str_free(&out);
    nvat_jwt_validation_options_free(&options);
}

TEST_F(VerifyEarCapi, ZeroLeewayIsStrict) {
    auto ear = make_valid_ear(m_base_url);
    ear["iat"] = static_cast<std::int64_t>(std::time(nullptr)) + 30;
    nvat_jwt_validation_options_t options = nullptr;
    ASSERT_EQ(nvat_jwt_validation_options_create_default(&options), NVAT_RC_OK);
    ASSERT_NE(options, nullptr);
    nvat_jwt_validation_options_set_clock_skew_leeway_seconds(options, 0);
    nvat_str_t out = reinterpret_cast<nvat_str_t>(std::uintptr_t{1});

    EXPECT_EQ(verify_c(sign_test_ear(ear), options, &out),
              NVAT_RC_NRAS_TOKEN_INVALID);
    EXPECT_EQ(out, nullptr);
    nvat_jwt_validation_options_free(&options);
}

TEST_F(VerifyEarCapi, OptionsLifecycleHandlesNullSafely) {
    EXPECT_EQ(nvat_jwt_validation_options_create_default(nullptr),
              NVAT_RC_BAD_ARGUMENT);
    nvat_jwt_validation_options_set_clock_skew_leeway_seconds(nullptr, 60);
    nvat_jwt_validation_options_free(nullptr);

    nvat_jwt_validation_options_t options = nullptr;
    ASSERT_EQ(nvat_jwt_validation_options_create_default(&options), NVAT_RC_OK);
    ASSERT_NE(options, nullptr);
    nvat_jwt_validation_options_free(&options);
    EXPECT_EQ(options, nullptr);
    nvat_jwt_validation_options_free(&options);
}

TEST_F(VerifyEarCapi, OutputRemainsNullOnFailure) {
    nvat_str_t out = reinterpret_cast<nvat_str_t>(std::uintptr_t{1});

    EXPECT_EQ(verify_c("not.a.compact.jwt", nullptr, &out),
              NVAT_RC_NRAS_TOKEN_INVALID);
    EXPECT_EQ(out, nullptr);
}

TEST_F(VerifyEarServerTest, ValidAffirmingEarReturnsExactPayload) {
    const auto ear = make_valid_ear(m_base_url);
    const std::string token = sign_test_ear(ear);
    std::string out;
    ASSERT_EQ(verify(token, out), Error::Ok);
    EXPECT_EQ(out, jwt::decode<jwt::traits::nlohmann_json>(token).get_payload());
    EXPECT_EQ(nlohmann::json::parse(out), ear);
}

TEST_F(VerifyEarServerTest, NonNvidiaJwksGetsNoServiceKey) {
    static const std::string kServiceKey =
        "EAR_TEST_SERVICE_KEY_MUST_NOT_REACH_LOGS";
    std::remove(m_base_headers_path.c_str());
    const std::string token = sign_test_ear(make_valid_ear(m_base_url));
    std::string out;

    testing::internal::CaptureStderr();
    const Error err = verify(token, out, {}, m_base_url, kServiceKey);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::Ok);
    EXPECT_TRUE(captured_authorization(m_base_headers_path).empty());
    EXPECT_EQ(logs.find(kServiceKey), std::string::npos);
}

TEST_F(VerifyEarServerTest, JwksRedirectIsRejected) {
    static const std::string kServiceKey =
        "EAR_REDIRECT_SERVICE_KEY_MUST_NOT_REACH_LOGS";
    std::remove(m_redirect_headers_path.c_str());
    std::remove(m_redirect_target_headers_path.c_str());
    const std::string token = sign_test_ear(make_valid_ear(m_redirect_url));
    std::string out = "must be cleared";

    testing::internal::CaptureStderr();
    const Error err = verify(token, out, {}, m_redirect_url, kServiceKey);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::VerifierJwksError);
    EXPECT_TRUE(out.empty());
    EXPECT_TRUE(captured_authorization(m_redirect_headers_path).empty());
    EXPECT_NE(::access(m_redirect_target_headers_path.c_str(), F_OK), 0);
    EXPECT_EQ(logs.find(kServiceKey), std::string::npos);
}

TEST_F(VerifyEarServerTest, InternalValidContraindicatedEarReturnsOk) {
    const auto ear = make_valid_ear(m_base_url, "contraindicated");
    std::string out;
    EXPECT_EQ(verify(sign_test_ear(ear), out), Error::Ok);
    EXPECT_EQ(nlohmann::json::parse(out), ear);
}

TEST_F(VerifyEarServerTest, UnknownExtensionClaimsAreRetained) {
    const auto ear = make_valid_ear(m_base_url);
    std::string out;
    ASSERT_EQ(verify(sign_test_ear(ear), out), Error::Ok);
    const auto verified = nlohmann::json::parse(out);
    EXPECT_EQ(verified.at("x-nvidia-root-extension"),
              ear.at("x-nvidia-root-extension"));
    EXPECT_EQ(verified.at("submods").at("gpu-0").at("x-nvidia-submod-extension"),
              "preserved");
}

TEST_F(VerifyEarServerTest, InternalMatchingExpectedNonceAccepted) {
    std::string out;
    EXPECT_EQ(verify(sign_test_ear(make_valid_ear(m_base_url)), out,
                     {0xde, 0xad, 0xbe, 0xef}), Error::Ok);
}

TEST_F(VerifyEarServerTest, MismatchingExpectedNonceReturnsNonceMismatch) {
    expect_invalid(sign_test_ear(make_valid_ear(m_base_url)),
                   Error::NonceMismatch, {0xde, 0xad, 0xbe, 0x00});
}

TEST_F(VerifyEarServerTest,
       ExpectedNonceComparesDecodedNonceInsteadOfItsEncoding) {
    const std::vector<uint8_t> expected_nonce = {0xff};
    auto ear = make_valid_ear(m_base_url);
    // "_x" decodes to the same byte as canonical "_w".
    ear["eat_nonce"] = "_x";
    std::string out;
    EXPECT_EQ(verify(sign_test_ear(ear), out, expected_nonce), Error::Ok);
}

TEST_F(VerifyEarServerTest, OmittedExpectedNonceDoesNotValidateNonceClaim) {
    const auto expect_valid = [this](const nlohmann::json& ear) {
        std::string out;
        ASSERT_EQ(verify(sign_test_ear(ear), out), Error::Ok);
        EXPECT_EQ(nlohmann::json::parse(out), ear);
    };

    auto ear = make_valid_ear(m_base_url);
    ear.erase("eat_nonce");
    expect_valid(ear);
    for (const auto& nonce : {nlohmann::json(123), nlohmann::json("")}) {
        ear["eat_nonce"] = nonce;
        expect_valid(ear);
    }
}

TEST_F(VerifyEarServerTest, MalformedCompactJwtRejected) {
    expect_invalid("not.a.compact.jwt");
}

TEST_F(VerifyEarServerTest, DoesNotLogTokenOrPayload) {
    const std::string malformed_header_marker =
        "MALICIOUS_MALFORMED_HEADER_MUST_NOT_REACH_LOGS";
    const std::string malformed_payload_marker =
        "MALICIOUS_MALFORMED_PAYLOAD_MUST_NOT_REACH_LOGS";
    const std::array<std::string, 2> tokens = {{
        base64url_encode("{\"alg\":\"ES384\",\"kid\":\"" +
                         malformed_header_marker + "\"") +
            "." + base64url_encode("{}") + ".ignored",
        base64url_encode("{\"alg\":\"ES384\",\"kid\":\"" +
                         std::string(KID) + "\"}") +
            "." + base64url_encode("{\"claim\":\"" +
                                    malformed_payload_marker + "\"") +
            ".ignored",
    }};

    for (const std::string& token : tokens) {
        std::string out = "must be cleared";
        testing::internal::CaptureStderr();
        const Error err = verify(token, out);
        const std::string logs = testing::internal::GetCapturedStderr();

        EXPECT_EQ(err, Error::NrasTokenInvalid);
        EXPECT_TRUE(out.empty());
        EXPECT_EQ(logs.find(malformed_header_marker), std::string::npos)
            << logs;
        EXPECT_EQ(logs.find(malformed_payload_marker), std::string::npos)
            << logs;
        EXPECT_NE(logs.find("JWT validation error"), std::string::npos)
            << logs;
    }
}

TEST_F(VerifyEarServerTest, AlgNoneRejected) {
    expect_invalid(sign_none(make_valid_ear(m_base_url)));
}

TEST_F(VerifyEarServerTest, WrongAlgorithmRejected) {
    expect_invalid(sign_hs256(make_valid_ear(m_base_url)));
}

TEST_F(VerifyEarServerTest, MissingKidRejected) {
    expect_invalid(sign_test_ear(make_valid_ear(m_base_url), ""));
}

TEST_F(VerifyEarServerTest, EmptyKidRejected) {
    auto token = jwt::create<jwt::traits::nlohmann_json>();
    const auto ear = make_valid_ear(m_base_url);
    for (auto it = ear.begin(); it != ear.end(); ++it) {
        token.set_payload_claim(
            it.key(), jwt::basic_claim<jwt::traits::nlohmann_json>(it.value()));
    }
    token.set_header_claim(
        "kid", jwt::basic_claim<jwt::traits::nlohmann_json>(std::string()));
    expect_invalid(token.sign(jwt::algorithm::es384("", m_private_key, "", "")));
}

TEST_F(VerifyEarServerTest, UnknownKidReturnsCertNotFound) {
    expect_invalid(sign_test_ear(make_valid_ear(m_base_url), "unknown-kid"),
                   Error::CertNotFound);
}

TEST_F(VerifyEarServerTest, MalformedJwksDoesNotLeak) {
    static const std::string kMaliciousKid =
        "MALICIOUS_TOKEN_KID_MUST_NOT_REACH_LOGS";
    const std::string token = sign_test_ear(
        make_valid_ear(m_malformed_jwks_url), kMaliciousKid);
    std::string out = "must be cleared";

    testing::internal::CaptureStderr();
    const Error err = verify(token, out, {}, m_malformed_jwks_url);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::JsonSerializationError);
    EXPECT_TRUE(out.empty());
    EXPECT_EQ(logs.find(kMaliciousKid), std::string::npos) << logs;
    EXPECT_EQ(logs.find("MALFORMED_JWKS_RESPONSE_BODY"), std::string::npos) << logs;
    EXPECT_EQ(logs.find("json.exception"), std::string::npos) << logs;
    EXPECT_EQ(logs.find("parse error"), std::string::npos) << logs;
}

TEST_F(VerifyEarServerTest, MissingJwksKeysReturnsJwksError) {
    expect_invalid(sign_test_ear(make_valid_ear(m_missing_keys_url)),
                   Error::VerifierJwksError, {}, m_missing_keys_url);
}

TEST_F(VerifyEarServerTest, InvalidJwksShapeReturnsJwksError) {
    expect_invalid(sign_test_ear(make_valid_ear(m_invalid_keys_url)),
                   Error::VerifierJwksError, {}, m_invalid_keys_url);
}

TEST_F(VerifyEarServerTest, SingleCertificateUsesEatPathBehavior) {
    std::string out;
    EXPECT_EQ(verify(sign_test_ear(make_valid_ear(m_expired_leaf_url)), out,
                     {}, m_expired_leaf_url), Error::Ok);
}

TEST_F(VerifyEarServerTest, ValidTwoCertificateX5cChainAccepted) {
    std::string out;
    EXPECT_EQ(verify(sign_test_ear(make_valid_ear(m_valid_chain_url), KID,
                                   m_chain_leaf_private_key),
                     out, {}, m_valid_chain_url), Error::Ok);
}

TEST_F(VerifyEarServerTest, WrongIssuerTwoCertificateX5cChainRejected) {
    expect_invalid(sign_test_ear(make_valid_ear(m_wrong_issuer_url), KID,
                                 m_chain_leaf_private_key),
                   Error::CertNotFound, {}, m_wrong_issuer_url);
}

TEST_F(VerifyEarServerTest, InvalidJwksKeyDoesNotLeak) {
    const std::string token = sign_test_ear(
        make_valid_ear(m_invalid_key_material_url));
    std::string out = "must be cleared";

    testing::internal::CaptureStderr();
    const Error err = verify(token, out, {}, m_invalid_key_material_url);
    const std::string logs = testing::internal::GetCapturedStderr();

    EXPECT_EQ(err, Error::NrasTokenInvalid);
    EXPECT_TRUE(out.empty());
    EXPECT_EQ(logs.find("MALICIOUS_JWKS_KEY_MATERIAL"), std::string::npos) << logs;
    EXPECT_EQ(logs.find(KID), std::string::npos) << logs;
}

TEST_F(VerifyEarServerTest, BadSignatureRejected) {
    std::string token = sign_test_ear(make_valid_ear(m_base_url));
    const auto last_dot = token.rfind('.');
    ASSERT_NE(last_dot, std::string::npos);
    ASSERT_LT(last_dot + 1, token.size());
    token[last_dot + 1] = token[last_dot + 1] == 'A' ? 'B' : 'A';
    expect_invalid(token);
}

TEST_F(VerifyEarServerTest, PayloadTamperingRejected) {
    const std::string token = sign_test_ear(make_valid_ear(m_base_url));
    auto tampered = make_valid_ear(m_base_url);
    tampered["x-nvidia-root-extension"]["value"] = 43;
    expect_invalid(replace_payload(token, tampered));
}

TEST_F(VerifyEarServerTest, IssuerMismatchRejected) {
    expect_invalid(sign_test_ear(make_valid_ear("https://other.example")));
}

TEST_F(VerifyEarServerTest, NonHttpsVerifierUrlRejected) {
    expect_invalid(sign_test_ear(make_valid_ear(m_base_url)), Error::BadArgument,
                   {}, "http://verifier.example");
}

TEST_F(VerifyEarServerTest, TrailingSlashVerifierUrlNormalized) {
    std::string out;
    EXPECT_EQ(verify(sign_test_ear(make_valid_ear(m_base_url)), out, {},
                     m_base_url + "///"), Error::Ok);
}

TEST_F(VerifyEarServerTest, SchemaClaimsDoNotAffectVerification) {
    const auto expect_valid = [this](const char* description,
                                     const nlohmann::json& ear) {
        SCOPED_TRACE(description);
        std::string out;
        ASSERT_EQ(verify(sign_test_ear(ear), out), Error::Ok);
        EXPECT_EQ(nlohmann::json::parse(out), ear);
    };

    auto ear = make_valid_ear(m_base_url);
    ear.erase("eat_profile");
    expect_valid("missing profile", ear);
    ear = make_valid_ear(m_base_url);
    ear["eat_profile"] = "tag:example.com,2026:unsupported";
    expect_valid("different profile", ear);
    ear = make_valid_ear(m_base_url);
    ear["eat_profile"] = 7;
    expect_valid("non-string profile", ear);

    ear = make_valid_ear(m_base_url);
    ear["submods"]["gpu-0"].erase("eat_profile");
    expect_valid("missing submod profile", ear);
    ear = make_valid_ear(m_base_url);
    ear["submods"]["gpu-0"]["eat_profile"] =
        "tag:example.com,2026:unsupported";
    expect_valid("different submod profile", ear);
    ear = make_valid_ear(m_base_url);
    ear["submods"]["gpu-0"]["eat_profile"] = 7;
    expect_valid("non-string submod profile", ear);

    ear = make_valid_ear(m_base_url);
    ear.erase("ear_status");
    ear.erase("submods");
    expect_valid("missing status and submods", ear);

    ear = make_valid_ear(m_base_url);
    ear["ear_status"] = 1;
    ear["submods"] = nlohmann::json::array({"opaque", 7});
    expect_valid("non-schema status and submods", ear);

    ear = make_valid_ear(m_base_url);
    ear["ear_status"] = "unknown";
    ear["submods"]["gpu-0"] = "opaque";
    expect_valid("opaque submod", ear);
}

TEST_F(VerifyEarServerTest, MissingTimeClaimsAccepted) {
    for (const std::string claim : {"iat", "nbf", "exp"}) {
        auto ear = make_valid_ear(m_base_url);
        ear.erase(claim);
        std::string out;
        ASSERT_EQ(verify(sign_test_ear(ear), out), Error::Ok);
        EXPECT_EQ(nlohmann::json::parse(out), ear);
    }
}

TEST_F(VerifyEarServerTest, NonNumericTimeClaimsRejected) {
    for (const std::string claim : {"iat", "nbf", "exp"}) {
        auto ear = make_valid_ear(m_base_url);
        ear[claim] = "123";
        expect_invalid(sign_test_ear(ear));
    }
}

TEST_F(VerifyEarServerTest, DefaultLeewayAcceptsSmallFutureIat) {
    auto ear = make_valid_ear(m_base_url);
    ear["iat"] = static_cast<std::int64_t>(std::time(nullptr)) + 30;
    std::string out;
    EXPECT_EQ(verify(sign_test_ear(ear), out), Error::Ok);
}

TEST_F(VerifyEarServerTest, DefaultLeewayAcceptsSmallFutureNbf) {
    auto ear = make_valid_ear(m_base_url);
    ear["nbf"] = static_cast<std::int64_t>(std::time(nullptr)) + 30;
    std::string out;
    EXPECT_EQ(verify(sign_test_ear(ear), out), Error::Ok);
}

TEST_F(VerifyEarServerTest, ZeroLeewayRejectsFutureIat) {
    auto ear = make_valid_ear(m_base_url);
    ear["iat"] = static_cast<std::int64_t>(std::time(nullptr)) + 30;
    std::string out = "must be cleared";
    EXPECT_EQ(verify(sign_test_ear(ear), out, {}, "", "", 0),
              Error::NrasTokenInvalid);
    EXPECT_TRUE(out.empty());
}

TEST_F(VerifyEarServerTest, DefaultLeewayAcceptsRecentlyExpiredToken) {
    auto ear = make_valid_ear(m_base_url);
    ear["iat"] = static_cast<std::int64_t>(std::time(nullptr)) - 3600;
    ear["nbf"] = ear["iat"];
    ear["exp"] = static_cast<std::int64_t>(std::time(nullptr)) - 30;
    std::string out;
    EXPECT_EQ(verify(sign_test_ear(ear), out), Error::Ok);
}

TEST_F(VerifyEarServerTest, ExpectedNonceRequiresDecodableNonceClaim) {
    const std::vector<uint8_t> expected_nonce = {0xde, 0xad, 0xbe, 0xef};
    auto ear = make_valid_ear(m_base_url);
    ear.erase("eat_nonce");
    expect_invalid(sign_test_ear(ear), Error::NrasTokenInvalid, expected_nonce);
    for (const auto& nonce : {"", "3q2-7w==", "3q2+7w", "A"}) {
        ear = make_valid_ear(m_base_url);
        ear["eat_nonce"] = nonce;
        expect_invalid(sign_test_ear(ear), Error::NrasTokenInvalid,
                       expected_nonce);
    }
    ear = make_valid_ear(m_base_url);
    ear["eat_nonce"] = 123;
    expect_invalid(sign_test_ear(ear), Error::NrasTokenInvalid, expected_nonce);
}
