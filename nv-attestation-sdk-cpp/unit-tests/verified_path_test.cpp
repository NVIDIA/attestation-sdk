/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 sol pbc
 * SPDX-License-Identifier: Apache-2.0
 *
 * Revocation coverage follows the certificate path OpenSSL verified, and the
 * presented chain must be an ordered, byte-identical prefix of that path.
 * Fixture certificates come from testdata/x509_verified_path/generate_certs.py.
 */

#include "gtest/gtest.h"

#include <fstream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include <openssl/ocsp.h>
#include <openssl/x509.h>

#include "nv_attestation/error.h"
#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/nv_types.h"
#include "nv_attestation/nv_x509.h"

using namespace nvattestation;

namespace {

const std::string kDir = "testdata/x509_verified_path/";

std::string cert(const std::string& name) {
    std::ifstream file(kDir + name + ".pem", std::ios::binary);
    EXPECT_TRUE(file.good()) << name;
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

X509CertChain device_chain(const std::vector<std::string>& order) {
    X509CertChain chain;
    EXPECT_EQ(X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, cert("root"), chain), Error::Ok);
    for (const auto& name : order) {
        EXPECT_EQ(chain.push_back(cert(name)), Error::Ok) << name;
    }
    return chain;
}

const std::vector<std::string> kPresented = {"leaf", "l4", "l3", "l2", "root"};
const std::vector<std::string> kRootOmitted = {"leaf", "l4", "l3", "l2"};

// Answers GOOD for every lookup and records which subject/issuer pair it was
// asked about, so a test sees exactly what coverage the chain requested.
class RecordingOcspClient : public IOcspHttpClient {
public:
    Error get_ocsp_response(
        const nv_unique_ptr<X509>& subject,
        const nv_unique_ptr<X509>& issuer,
        const nv_unique_ptr<stack_st_X509>& /*intermediates*/,
        const nv_unique_ptr<X509_STORE>& /*trust_store*/,
        NvOcspResponse& out) override {
        X509_up_ref(subject.get());
        X509_up_ref(issuer.get());
        m_pairs.emplace_back(nv_unique_ptr<X509>(subject.get()), nv_unique_ptr<X509>(issuer.get()));
        out = NvOcspResponse{};
        out.status = V_OCSP_CERTSTATUS_GOOD;
        out.reason = -1;
        out.nonce_matches = true;
        out.response_valid = true;
        out.thisupd = 1790812800;
        out.nextupd = 1790812800 + 86400;
        return Error::Ok;
    }
    std::vector<std::pair<nv_unique_ptr<X509>, nv_unique_ptr<X509>>> m_pairs;
};

void expect_path(const std::vector<nv_unique_ptr<X509>>& path, const std::vector<std::string>& names) {
    ASSERT_EQ(path.size(), names.size());
    for (size_t i = 0; i < names.size(); ++i) {
        nv_unique_ptr<X509> expected = x509_from_cert_string(cert(names[i]));
        EXPECT_EQ(X509_cmp(path[i].get(), expected.get()), 0) << i;
    }
}

// The GPU alias leaf and the root are not checked; each other certificate
// is checked against the certificate that actually issued it.
void expect_verified_pairs(const RecordingOcspClient& client) {
    const std::vector<std::pair<std::string, std::string>> expected = {
        {"l2", "root"}, {"l3", "l2"}, {"l4", "l3"}};
    ASSERT_EQ(client.m_pairs.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        nv_unique_ptr<X509> subject = x509_from_cert_string(cert(expected[i].first));
        nv_unique_ptr<X509> issuer = x509_from_cert_string(cert(expected[i].second));
        EXPECT_EQ(X509_cmp(client.m_pairs[i].first.get(), subject.get()), 0) << i;
        EXPECT_EQ(X509_cmp(client.m_pairs[i].second.get(), issuer.get()), 0) << i;
        EXPECT_EQ(X509_check_issued(client.m_pairs[i].second.get(), client.m_pairs[i].first.get()), X509_V_OK) << i;
    }
}

}  // namespace

TEST(VerifiedPathTest, ExactPresentedChainVerifiesAndIsReturnedInOrder) {
    X509CertChain chain = device_chain(kPresented);
    std::vector<nv_unique_ptr<X509>> path;
    ASSERT_EQ(chain.verify(path), Error::Ok);
    expect_path(path, kPresented);
}

TEST(VerifiedPathTest, ChainWithoutItsRootVerifiesAgainstTheTrustStoreRoot) {
    X509CertChain chain = device_chain(kRootOmitted);
    EXPECT_EQ(chain.verify(), Error::Ok);
    std::vector<nv_unique_ptr<X509>> path;
    ASSERT_EQ(chain.verify(path), Error::Ok);
    expect_path(path, kPresented);
}

TEST(VerifiedPathTest, ReorderedExtraAndDuplicateChainsReject) {
    const std::vector<std::vector<std::string>> shapes = {
        {"leaf", "l3", "l4", "l2", "root"},               // reordered
        {"leaf", "l4", "unrelated", "l3", "l2", "root"},  // a non-issuer inserted to shift the pairs
        {"leaf", "l4", "unrelated", "l3", "l2"},          // the same, root omitted
        {"leaf", "l4", "l3", "l2", "root", "unrelated"},  // extra at the end
        {"leaf", "l4", "l3", "l2", "unrelated"},          // extra in place of the root
        {"leaf", "l4", "l4", "l3", "l2", "root"},         // duplicate
        {"leaf", "l4", "l3", "l2", "root", "root"},       // duplicate root
        {"leaf", "l4", "l3", "l2", "stranger_root"},      // a different root
    };
    for (size_t s = 0; s < shapes.size(); ++s) {
        X509CertChain chain = device_chain(shapes[s]);
        std::vector<nv_unique_ptr<X509>> path;
        EXPECT_EQ(chain.verify(path), Error::CertChainVerificationFailure) << s;
        EXPECT_TRUE(path.empty()) << s;

        RecordingOcspClient client;
        CertChainClaims claims;
        EXPECT_NE(chain.generate_cert_chain_claims(OcspVerifyOptions(), client, claims), Error::Ok) << s;
        OCSPClaims ocsp_claims;
        EXPECT_NE(chain.generate_ocsp_claims(OcspVerifyOptions(), client, ocsp_claims), Error::Ok) << s;
        std::vector<PerCertStatus> statuses;
        EXPECT_NE(chain.generate_per_cert_status(OcspVerifyOptions(), &client, statuses), Error::Ok) << s;
        EXPECT_FALSE(all_certs_trusted(statuses)) << s;
        EXPECT_TRUE(client.m_pairs.empty()) << s << ": a rejected path must request no status";
    }
}

TEST(VerifiedPathTest, StatusesAreRequestedForTheVerifiedSubjectIssuerPairs) {
    X509CertChain chain = device_chain(kPresented);
    RecordingOcspClient client;
    CertChainClaims claims;
    ASSERT_EQ(chain.generate_cert_chain_claims(OcspVerifyOptions(), client, claims), Error::Ok);
    expect_verified_pairs(client);
    EXPECT_EQ(claims.ocsp_claims.status, OCSPStatus::GOOD);
}

TEST(VerifiedPathTest, RootOmittedChainChecksItsLastCertificateAgainstTheTrustStoreRoot) {
    X509CertChain chain = device_chain(kRootOmitted);
    RecordingOcspClient client;
    CertChainClaims claims;
    ASSERT_EQ(chain.generate_cert_chain_claims(OcspVerifyOptions(), client, claims), Error::Ok);
    expect_verified_pairs(client);
    EXPECT_EQ(claims.ocsp_claims.status, OCSPStatus::GOOD);
}

TEST(VerifiedPathTest, PerCertStatusFollowsTheVerifiedPath) {
    // Output is root-first. The root and the GPU alias leaf are not checked.
    {
        X509CertChain chain = device_chain(kPresented);
        RecordingOcspClient client;
        std::vector<PerCertStatus> statuses;
        ASSERT_EQ(chain.generate_per_cert_status(OcspVerifyOptions(), &client, statuses), Error::Ok);
        expect_verified_pairs(client);
        ASSERT_EQ(statuses.size(), 5u);
        const std::vector<OCSPStatus> expected = {
            OCSPStatus::NOT_CHECKED, OCSPStatus::GOOD, OCSPStatus::GOOD, OCSPStatus::GOOD, OCSPStatus::NOT_CHECKED};
        for (size_t i = 0; i < expected.size(); ++i) {
            ASSERT_TRUE(statuses[i].ocsp) << i;
            EXPECT_EQ(statuses[i].ocsp->crl_status, expected[i]) << i;
        }
        EXPECT_TRUE(all_certs_trusted(statuses));
    }
    {
        // With the root omitted, l2 is checked against the trust store's root
        // rather than being treated as the root and skipped.
        X509CertChain chain = device_chain(kRootOmitted);
        RecordingOcspClient client;
        std::vector<PerCertStatus> statuses;
        ASSERT_EQ(chain.generate_per_cert_status(OcspVerifyOptions(), &client, statuses), Error::Ok);
        expect_verified_pairs(client);
        ASSERT_EQ(statuses.size(), 4u);
        const std::vector<OCSPStatus> expected = {
            OCSPStatus::GOOD, OCSPStatus::GOOD, OCSPStatus::GOOD, OCSPStatus::NOT_CHECKED};
        for (size_t i = 0; i < expected.size(); ++i) {
            ASSERT_TRUE(statuses[i].ocsp) << i;
            EXPECT_EQ(statuses[i].ocsp->crl_status, expected[i]) << i;
        }
        EXPECT_TRUE(all_certs_trusted(statuses));
    }
}

TEST(VerifiedPathTest, PartialChainAcceptsAPrefixEndingBelowAnIntermediateAnchor) {
    nv_unique_ptr<X509> anchor = x509_from_cert_string(cert("l3"));
    ASSERT_NE(anchor, nullptr);
    X509CertChain chain(CertificateChainType::GENERIC, create_trust_store(anchor.get()));
    ASSERT_EQ(chain.push_back(cert("leaf")), Error::Ok);
    ASSERT_EQ(chain.push_back(cert("l4")), Error::Ok);

    EXPECT_EQ(chain.verify(), Error::CertChainVerificationFailure);
    std::vector<nv_unique_ptr<X509>> path;
    ASSERT_EQ(chain.verify(path, /*allow_partial_chain=*/true), Error::Ok);
    expect_path(path, {"leaf", "l4", "l3"});

    X509CertChain shifted(CertificateChainType::GENERIC, create_trust_store(anchor.get()));
    ASSERT_EQ(shifted.push_back(cert("leaf")), Error::Ok);
    ASSERT_EQ(shifted.push_back(cert("unrelated")), Error::Ok);
    ASSERT_EQ(shifted.push_back(cert("l4")), Error::Ok);
    EXPECT_EQ(shifted.verify(/*allow_partial_chain=*/true), Error::CertChainVerificationFailure);
}
