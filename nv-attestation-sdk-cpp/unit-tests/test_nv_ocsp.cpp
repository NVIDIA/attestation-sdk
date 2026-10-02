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

#include <string>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

#include "gtest/gtest.h"

#include "nv_attestation/error.h"
#include "nv_attestation/nv_ocsp.h"
#include "test_utils.h"

using namespace nvattestation;
using Rules = std::vector<std::pair<std::string, std::string>>;

// Build a minimal self-signed cert, optionally with an OCSP AIA entry.
// When out_pkey is non-null, the signing key is returned there instead of
// being freed, so the caller can reuse it (e.g. to sign an OCSP_BASICRESP).
static nv_unique_ptr<X509> make_test_cert(const std::string& ocsp_url = "",
                                           nv_unique_ptr<EVP_PKEY>* out_pkey = nullptr) {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);

    nv_unique_ptr<X509> cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 3600);
    X509_set_pubkey(cert.get(), pkey);

    if (!ocsp_url.empty()) {
        std::string aia_val = "OCSP;URI:" + ocsp_url;
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(
            nullptr, &ctx, NID_info_access, aia_val.c_str());
        if (ext) {
            X509_add_ext(cert.get(), ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    X509_sign(cert.get(), pkey, EVP_sha256());
    if (out_pkey != nullptr) {
        out_pkey->reset(pkey);
    } else {
        EVP_PKEY_free(pkey);
    }
    return cert;
}

namespace nvattestation {

namespace {

void expect_cert_id_algorithm(OCSP_CERTID* id, int expected_nid,
                              int expected_hash_length) {
    ASN1_OCTET_STRING* name_hash = nullptr;
    ASN1_OBJECT* digest = nullptr;
    ASN1_OCTET_STRING* key_hash = nullptr;
    ASSERT_EQ(OCSP_id_get0_info(&name_hash, &digest, &key_hash, nullptr, id), 1);
    EXPECT_EQ(OBJ_obj2nid(digest), expected_nid);
    EXPECT_EQ(ASN1_STRING_length(name_hash), expected_hash_length);
    EXPECT_EQ(ASN1_STRING_length(key_hash), expected_hash_length);
}

void expect_request_cert_id_algorithm(OCSP_REQUEST* request,
                                      OCSP_CERTID* response_lookup_id,
                                      int expected_nid,
                                      int expected_hash_length) {
    ASSERT_NE(request, nullptr);
    ASSERT_EQ(OCSP_request_onereq_count(request), 1);
    OCSP_ONEREQ* one_request = OCSP_request_onereq_get0(request, 0);
    ASSERT_NE(one_request, nullptr);
    OCSP_CERTID* request_id = OCSP_onereq_get0_id(one_request);
    expect_cert_id_algorithm(request_id, expected_nid, expected_hash_length);
    ASSERT_NE(response_lookup_id, nullptr);
    EXPECT_EQ(OCSP_id_cmp(request_id, response_lookup_id), 0);
}

}  // namespace

TEST(NvHttpOcspClientHashTest, ConfiguredAlgorithmsBuildExpectedCertIds) {
    OcspClientOptions default_options;
    EXPECT_EQ(default_options.cert_id_hash_algorithm,
              OcspCertIdHashAlgorithm::Sha256);

    auto issuer = make_test_cert();
    auto subject = make_test_cert();
    struct TestCase {
        OcspCertIdHashAlgorithm algorithm;
        int nid;
        int hash_length;
    };
    for (const TestCase& test_case : {
             TestCase{OcspCertIdHashAlgorithm::Sha1, NID_sha1, 20},
             TestCase{OcspCertIdHashAlgorithm::Sha256, NID_sha256, 32},
             TestCase{OcspCertIdHashAlgorithm::Sha384, NID_sha384, 48},
         }) {
        OcspClientOptions options;
        options.cert_id_hash_algorithm = test_case.algorithm;
        NvHttpOcspClient client;
        ASSERT_EQ(NvHttpOcspClient::create(
                      client, "http://ocsp.example.com", "", HttpOptions(),
                      options),
                  Error::Ok);

        nv_unique_ptr<OCSP_REQUEST> request;
        nv_unique_ptr<OCSP_CERTID> response_lookup_id;
        ASSERT_EQ(client.build_request(subject.get(), issuer.get(), request,
                                       response_lookup_id),
                  Error::Ok);
        expect_request_cert_id_algorithm(
            request.get(), response_lookup_id.get(), test_case.nid,
            test_case.hash_length);
    }
}

TEST(NvHttpOcspClientHashTest, InvalidAlgorithmIsRejected) {
    OcspClientOptions options;
    options.cert_id_hash_algorithm = static_cast<OcspCertIdHashAlgorithm>(99);
    NvHttpOcspClient client;
    EXPECT_EQ(NvHttpOcspClient::create(client, "http://ocsp.example.com", "",
                                       HttpOptions(), options),
              Error::BadArgument);
}

TEST(NvHttpOcspClientHashTest, ParsesNamesCaseInsensitively) {
    struct TestCase {
        const char* name;
        OcspCertIdHashAlgorithm expected;
    };
    const TestCase cases[] = {
        {"sha-1", OcspCertIdHashAlgorithm::Sha1},
        {"SHA1", OcspCertIdHashAlgorithm::Sha1},
        {"sHa-256", OcspCertIdHashAlgorithm::Sha256},
        {"SHA256", OcspCertIdHashAlgorithm::Sha256},
        {"Sha-384", OcspCertIdHashAlgorithm::Sha384},
        {"sha384", OcspCertIdHashAlgorithm::Sha384},
    };

    for (const auto& test_case : cases) {
        OcspCertIdHashAlgorithm algorithm = OcspCertIdHashAlgorithm::Sha1;
        ASSERT_EQ(ocsp_cert_id_hash_algorithm_from_name(test_case.name, algorithm),
                  Error::Ok)
            << test_case.name;
        EXPECT_EQ(algorithm, test_case.expected) << test_case.name;
    }
}

TEST(NvHttpOcspClientHashTest, InvalidNameIsRejected) {
    OcspCertIdHashAlgorithm algorithm = OcspCertIdHashAlgorithm::Sha1;
    EXPECT_EQ(ocsp_cert_id_hash_algorithm_from_name("sha-512", algorithm),
              Error::BadArgument);
}

TEST(NvHttpOcspClientHashTest, EnvironmentDefaultsUnsetAndEmptyToSha256) {
    ScopedEnvironmentVariable environment("NVAT_OCSP_CERT_ID_HASH_ALGORITHM");
    for (const char* value : {static_cast<const char*>(nullptr), ""}) {
        if (value == nullptr) {
            environment.unset();
        } else {
            environment.set(value);
        }

        NvHttpOcspClient client;
        ASSERT_EQ(NvHttpOcspClient::init_from_env(
                      client, "http://ocsp.example.com", "", HttpOptions()),
                  Error::Ok);
        EXPECT_EQ(client.cert_id_hash_algorithm(),
                  OcspCertIdHashAlgorithm::Sha256);
    }
}

TEST(NvHttpOcspClientHashTest, EnvironmentUsesAliasesAndRejectsInvalidValues) {
    ScopedEnvironmentVariable environment("NVAT_OCSP_CERT_ID_HASH_ALGORITHM");
    environment.set("sHa384");
    NvHttpOcspClient client;
    ASSERT_EQ(NvHttpOcspClient::init_from_env(
                  client, "http://ocsp.example.com", "", HttpOptions()),
              Error::Ok);
    EXPECT_EQ(client.cert_id_hash_algorithm(), OcspCertIdHashAlgorithm::Sha384);

    environment.set("sha-512");
    EXPECT_EQ(NvHttpOcspClient::init_from_env(
                  client, "http://ocsp.example.com", "", HttpOptions()),
              Error::BadArgument);
}

TEST(NvHttpOcspClientHashTest, ExplicitOptionsIgnoreHashEnvironmentVariable) {
    ScopedEnvironmentVariable environment("NVAT_OCSP_CERT_ID_HASH_ALGORITHM");
    environment.set("invalid");
    OcspClientOptions options;
    options.cert_id_hash_algorithm = OcspCertIdHashAlgorithm::Sha1;
    NvHttpOcspClient client;
    ASSERT_EQ(NvHttpOcspClient::init_from_env(
                  client, "http://ocsp.example.com", "", HttpOptions(), options),
              Error::Ok);
    EXPECT_EQ(client.cert_id_hash_algorithm(), OcspCertIdHashAlgorithm::Sha1);
}

TEST(NvHttpOcspCacheClientTest, CacheKeyUsesFixedSha256) {
    auto subject = make_test_cert();
    auto issuer = make_test_cert();
    std::string cache_key;
    ASSERT_EQ(NvHttpOcspCacheClient::get_cache_key(subject, issuer, cache_key),
              Error::Ok);

    const unsigned char* encoded =
        reinterpret_cast<const unsigned char*>(cache_key.data());
    nv_unique_ptr<OCSP_CERTID> decoded(
        d2i_OCSP_CERTID(nullptr, &encoded, static_cast<long>(cache_key.size())));
    ASSERT_TRUE(decoded);
    EXPECT_EQ(encoded, reinterpret_cast<const unsigned char*>(cache_key.data()) +
                           cache_key.size());
    expect_cert_id_algorithm(decoded.get(), NID_sha256, 32);
}

}  // namespace nvattestation

// ---- apply_url_rewrites ----

TEST(OcspUrlRewrite, NoRules) {
    EXPECT_EQ(NvHttpOcspClient::apply_url_rewrites({}, "http://example.com/path"),
              "http://example.com/path");
}

TEST(OcspUrlRewrite, SchemeUpgrade) {
    Rules rules = {{"http://", "https://"}};
    EXPECT_EQ(NvHttpOcspClient::apply_url_rewrites(rules, "http://ocsp.example.com/path"),
              "https://ocsp.example.com/path");
}

TEST(OcspUrlRewrite, HostRewrite) {
    Rules rules = {{"http://ocsp.example.com", "https://ocsp.example.com"}};
    EXPECT_EQ(NvHttpOcspClient::apply_url_rewrites(rules, "http://ocsp.example.com/cert"),
              "https://ocsp.example.com/cert");
}

TEST(OcspUrlRewrite, FirstMatchWins) {
    Rules rules = {
        {"http://", "https://"},
        {"http://ocsp.example.com", "http://alt.example.com"},
    };
    EXPECT_EQ(NvHttpOcspClient::apply_url_rewrites(rules, "http://ocsp.example.com/path"),
              "https://ocsp.example.com/path");
}

TEST(OcspUrlRewrite, NoMatch) {
    Rules rules = {{"http://", "https://"}};
    EXPECT_EQ(NvHttpOcspClient::apply_url_rewrites(rules, "https://ocsp.example.com/path"),
              "https://ocsp.example.com/path");
}

TEST(OcspUrlRewrite, EmptyUrl) {
    Rules rules = {{"http://", "https://"}};
    EXPECT_EQ(NvHttpOcspClient::apply_url_rewrites(rules, ""), "");
}

// ---- add_url_rewrite ----

TEST(OcspAddUrlRewrite, EmptyPatternRejected) {
    NvHttpOcspClient client;
    EXPECT_EQ(client.add_url_rewrite("", "https://ocsp.example.com"), Error::BadArgument);
}

TEST(OcspAddUrlRewrite, EmptyReplacementPatternRejected) {
    NvHttpOcspClient client;
    EXPECT_EQ(client.add_url_rewrite("https://ocsp.example.com", ""), Error::BadArgument);
}

TEST(OcspAddUrlRewrite, ValidRuleAccepted) {
    NvHttpOcspClient client;
    EXPECT_EQ(client.add_url_rewrite("http://", "https://"), Error::Ok);
}

// ---- first_ocsp_responder_url ----

TEST(OcspAia, NullCert) {
    EXPECT_EQ(NvHttpOcspClient::first_ocsp_responder_url(nullptr), "");
}

TEST(OcspAia, CertWithoutAia) {
    auto cert = make_test_cert();
    EXPECT_EQ(NvHttpOcspClient::first_ocsp_responder_url(cert.get()), "");
}

TEST(OcspAia, CertWithAia) {
    const std::string expected = "http://ocsp.example.com";
    auto cert = make_test_cert(expected);
    EXPECT_EQ(NvHttpOcspClient::first_ocsp_responder_url(cert.get()), expected);
}

// ---- select_request_url (set_use_cert_aia_responder integration) ----

static NvHttpOcspClient make_client(const std::string& base_url) {
    NvHttpOcspClient client;
    Error err = NvHttpOcspClient::create(client, base_url, "", HttpOptions());
    EXPECT_EQ(err, Error::Ok);
    return client;
}

TEST(OcspSelectRequestUrl, AiaDisabledUsesBaseUrl) {
    NvHttpOcspClient client = make_client("http://base.example.com");
    auto cert = make_test_cert("http://ocsp.example.com");
    // set_use_cert_aia_responder() left at its default (disabled).
    EXPECT_EQ(client.select_request_url(cert.get()), "http://base.example.com");
}

TEST(OcspSelectRequestUrl, AiaEnabledUsesCertAiaUrl) {
    NvHttpOcspClient client = make_client("http://base.example.com");
    client.set_use_cert_aia_responder(true);
    auto cert = make_test_cert("http://ocsp.example.com");
    EXPECT_EQ(client.select_request_url(cert.get()), "http://ocsp.example.com");
}

TEST(OcspSelectRequestUrl, AiaEnabledSkipsWhenCertHasNoAia) {
    NvHttpOcspClient client = make_client("http://base.example.com");
    client.set_use_cert_aia_responder(true);
    auto cert = make_test_cert();
    // No AIA responder: no fallback to the base URL — the empty result signals
    // the OCSP request should be skipped.
    EXPECT_EQ(client.select_request_url(cert.get()), "");
}

TEST(OcspSelectRequestUrl, AiaEnabledAppliesRewritesToAiaUrl) {
    NvHttpOcspClient client = make_client("http://base.example.com");
    client.set_use_cert_aia_responder(true);
    ASSERT_EQ(client.add_url_rewrite("http://", "https://"), Error::Ok);
    auto cert = make_test_cert("http://ocsp.example.com");
    EXPECT_EQ(client.select_request_url(cert.get()), "https://ocsp.example.com");
}

TEST(OcspSelectRequestUrl, AiaDisabledIgnoresRewrites) {
    NvHttpOcspClient client = make_client("http://base.example.com");
    ASSERT_EQ(client.add_url_rewrite("http://", "https://"), Error::Ok);
    auto cert = make_test_cert("http://ocsp.example.com");
    // Rewrites only apply to the AIA URL path; disabled AIA means the base
    // URL is returned as-is, unrewritten.
    EXPECT_EQ(client.select_request_url(cert.get()), "http://base.example.com");
}

// ---- get_ocsp_response skip ----

TEST(OcspGetResponse, AiaEnabledSkipsCertWithoutAia) {
    NvHttpOcspClient client = make_client("http://base.example.com");
    client.set_use_cert_aia_responder(true);

    nv_unique_ptr<X509> subject = make_test_cert();
    nv_unique_ptr<X509> issuer;
    nv_unique_ptr<stack_st_X509> intermediates(sk_X509_new_null());
    nv_unique_ptr<X509_STORE> trust_store(X509_STORE_new());

    NvOcspResponse resp;
    resp.skipped = false;
    EXPECT_EQ(client.get_ocsp_response(subject, issuer, intermediates,
                                       trust_store, resp),
              Error::Ok);
    EXPECT_TRUE(resp.skipped);
}

// ---- get_ocsp_status ----
// Exercises the real timestamp-parsing logic with a hand-built, signed
// OCSP_BASICRESP, rather than mocking IOcspHttpClient above it.
// These TEST() bodies must live in the nvattestation namespace: the
// FRIEND_TEST-style declarations in nv_ocsp.h are unqualified, so they only
// grant access to a same-named class in NvHttpOcspClient's own namespace.
namespace nvattestation {

namespace {

using Asn1TimePtr = std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)>;

Asn1TimePtr make_asn1_time(time_t t) {
    return Asn1TimePtr(ASN1_TIME_set(nullptr, t), ASN1_TIME_free);
}

// Builds a signed OCSP_BASICRESP reporting subject_id's status.
// OCSP_basic_sign populates producedAt with the current time.
nv_unique_ptr<OCSP_BASICRESP> build_signed_basic_resp(
    OCSP_CERTID* subject_id, X509* signer_cert, EVP_PKEY* signer_key,
    int status, int reason, ASN1_TIME* revtime, ASN1_TIME* thisupd, ASN1_TIME* nextupd) {
    nv_unique_ptr<OCSP_BASICRESP> bs(OCSP_BASICRESP_new());
    OCSP_basic_add1_status(bs.get(), subject_id, status, reason, revtime, thisupd, nextupd);
    OCSP_basic_sign(bs.get(), signer_cert, signer_key, EVP_sha256(), nullptr, 0);
    return bs;
}

}  // namespace

TEST(NvHttpOcspClientStatusTest, GoodStatusAllFieldsPresent) {
    nv_unique_ptr<EVP_PKEY> signer_key;
    nv_unique_ptr<X509> signer_cert = make_test_cert("", &signer_key);
    nv_unique_ptr<X509> subject_cert = make_test_cert();

    nv_unique_ptr<OCSP_CERTID> id_for_resp(OCSP_cert_to_id(EVP_sha1(), subject_cert.get(), signer_cert.get()));
    ASSERT_TRUE(id_for_resp);

    const time_t this_update = 1700000000;
    const time_t next_update = 1700003600;
    Asn1TimePtr thisupd = make_asn1_time(this_update);
    Asn1TimePtr nextupd = make_asn1_time(next_update);
    ASSERT_TRUE(thisupd);
    ASSERT_TRUE(nextupd);

    nv_unique_ptr<OCSP_BASICRESP> bs = build_signed_basic_resp(
        id_for_resp.get(), signer_cert.get(), signer_key.get(),
        V_OCSP_CERTSTATUS_GOOD, 0, nullptr, thisupd.get(), nextupd.get());
    ASSERT_TRUE(bs);

    nv_unique_ptr<OCSP_CERTID> id_for_lookup(OCSP_cert_to_id(EVP_sha1(), subject_cert.get(), signer_cert.get()));
    ASSERT_TRUE(id_for_lookup);

    NvOcspResponse out;
    const time_t before = time(nullptr);
    Error err = NvHttpOcspClient::get_ocsp_status(bs, id_for_lookup, out);
    const time_t after = time(nullptr);

    ASSERT_EQ(err, Error::Ok);
    EXPECT_EQ(out.status, V_OCSP_CERTSTATUS_GOOD);
    EXPECT_EQ(out.thisupd, this_update);
    EXPECT_EQ(out.nextupd, next_update);
    EXPECT_EQ(out.revtime, 0);
    EXPECT_GE(out.producedat, before);
    EXPECT_LE(out.producedat, after);
}

TEST(NvHttpOcspClientStatusTest, RevokedStatusIncludesRevocationTime) {
    nv_unique_ptr<EVP_PKEY> signer_key;
    nv_unique_ptr<X509> signer_cert = make_test_cert("", &signer_key);
    nv_unique_ptr<X509> subject_cert = make_test_cert();

    nv_unique_ptr<OCSP_CERTID> id_for_resp(OCSP_cert_to_id(EVP_sha1(), subject_cert.get(), signer_cert.get()));
    ASSERT_TRUE(id_for_resp);

    const time_t this_update = 1700000000;
    const time_t next_update = 1700003600;
    const time_t revoked_at = 1699996400;
    Asn1TimePtr thisupd = make_asn1_time(this_update);
    Asn1TimePtr nextupd = make_asn1_time(next_update);
    Asn1TimePtr revtime = make_asn1_time(revoked_at);
    ASSERT_TRUE(thisupd);
    ASSERT_TRUE(nextupd);
    ASSERT_TRUE(revtime);

    nv_unique_ptr<OCSP_BASICRESP> bs = build_signed_basic_resp(
        id_for_resp.get(), signer_cert.get(), signer_key.get(),
        V_OCSP_CERTSTATUS_REVOKED, OCSP_REVOKED_STATUS_KEYCOMPROMISE, revtime.get(), thisupd.get(), nextupd.get());
    ASSERT_TRUE(bs);

    nv_unique_ptr<OCSP_CERTID> id_for_lookup(OCSP_cert_to_id(EVP_sha1(), subject_cert.get(), signer_cert.get()));
    ASSERT_TRUE(id_for_lookup);

    NvOcspResponse out;
    Error err = NvHttpOcspClient::get_ocsp_status(bs, id_for_lookup, out);

    ASSERT_EQ(err, Error::Ok);
    EXPECT_EQ(out.status, V_OCSP_CERTSTATUS_REVOKED);
    EXPECT_EQ(out.reason, OCSP_REVOKED_STATUS_KEYCOMPROMISE);
    EXPECT_EQ(out.revtime, revoked_at);
}

TEST(NvHttpOcspClientStatusTest, MissingNextUpdateUsesDefaultTtl) {
    nv_unique_ptr<EVP_PKEY> signer_key;
    nv_unique_ptr<X509> signer_cert = make_test_cert("", &signer_key);
    nv_unique_ptr<X509> subject_cert = make_test_cert();

    nv_unique_ptr<OCSP_CERTID> id_for_resp(OCSP_cert_to_id(EVP_sha1(), subject_cert.get(), signer_cert.get()));
    ASSERT_TRUE(id_for_resp);

    const time_t this_update = 1700000000;
    Asn1TimePtr thisupd = make_asn1_time(this_update);
    ASSERT_TRUE(thisupd);

    nv_unique_ptr<OCSP_BASICRESP> bs = build_signed_basic_resp(
        id_for_resp.get(), signer_cert.get(), signer_key.get(),
        V_OCSP_CERTSTATUS_GOOD, 0, nullptr, thisupd.get(), nullptr);
    ASSERT_TRUE(bs);

    nv_unique_ptr<OCSP_CERTID> id_for_lookup(OCSP_cert_to_id(EVP_sha1(), subject_cert.get(), signer_cert.get()));
    ASSERT_TRUE(id_for_lookup);

    NvOcspResponse out;
    Error err = NvHttpOcspClient::get_ocsp_status(bs, id_for_lookup, out);

    ASSERT_EQ(err, Error::Ok);
    EXPECT_EQ(out.thisupd, this_update);
    EXPECT_EQ(out.nextupd, this_update + NvHttpOcspClient::DEFAULT_NEXT_UPDATE_TTL_SECONDS);
}

}  // namespace nvattestation
