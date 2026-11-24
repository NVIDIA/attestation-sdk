/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
 */

#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "nv_attestation/cmw.h"
#include "nv_attestation/corim_evidence/evidence_handler.h"
#include "nv_attestation/corim_evidence/evidence_handler_settings.h"
#include "nv_attestation/cose.h"
#include "nv_attestation/corim_verify.h"
#include "nv_attestation/corim_evidence/dice_tcb_info_to_ect.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/utils.h"
#include "internal/certs.h"

using namespace nvattestation;

namespace {

nv_unique_ptr<X509> issue_certificate(EVP_PKEY* subject_key, const char* name,
                                     EVP_PKEY* issuer_key, X509* issuer,
                                     bool is_ca, long serial,
                                     const char* leaf_eku = nullptr,
                                     const char* unknown_extension = nullptr,
                                     const char* basic_constraints = nullptr,
                                     const char* key_usage = nullptr,
                                     const char* extra_oid = "1.2.3.4.5.6") {
    nv_unique_ptr<X509> cert(X509_new());
    if (!cert || X509_set_version(cert.get(), 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial) != 1 ||
        !X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600) ||
        X509_set_pubkey(cert.get(), subject_key) != 1) {
        return nullptr;
    }
    X509_NAME* subject = X509_get_subject_name(cert.get());
    if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                  reinterpret_cast<const unsigned char*>(name),
                                  -1, -1, 0) != 1 ||
        X509_set_issuer_name(cert.get(), issuer ? X509_get_subject_name(issuer)
                                              : subject) != 1) {
        return nullptr;
    }
    const char* constraints_value = basic_constraints != nullptr
        ? basic_constraints : (is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    if (constraints_value[0] != '\0') {
        nv_unique_ptr<X509_EXTENSION> constraints(X509V3_EXT_conf_nid(
            nullptr, nullptr, NID_basic_constraints, constraints_value));
        if (!constraints || X509_add_ext(cert.get(), constraints.get(), -1) != 1) {
            return nullptr;
        }
    }
    const char* usage_value = key_usage != nullptr
        ? key_usage : (is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
    if (usage_value[0] != '\0') {
        nv_unique_ptr<X509_EXTENSION> usage(X509V3_EXT_conf_nid(
            nullptr, nullptr, NID_key_usage, usage_value));
        if (!usage || X509_add_ext(cert.get(), usage.get(), -1) != 1) {
            return nullptr;
        }
    }
    if (leaf_eku != nullptr) {
        nv_unique_ptr<X509_EXTENSION> eku(X509V3_EXT_conf_nid(
            nullptr, nullptr, NID_ext_key_usage, leaf_eku));
        if (!eku || X509_add_ext(cert.get(), eku.get(), -1) != 1) {
            return nullptr;
        }
    }
    if (unknown_extension != nullptr) {
        nv_unique_ptr<X509_EXTENSION> extension(X509V3_EXT_conf(
            nullptr, nullptr, extra_oid, unknown_extension));
        if (!extension || X509_add_ext(cert.get(), extension.get(), -1) != 1) {
            return nullptr;
        }
    }
    if (X509_sign(cert.get(), issuer_key, EVP_sha384()) <= 0) {
        return nullptr;
    }
    return cert;
}

std::string certificate_pem(X509* cert) {
    nv_unique_ptr<BIO> bio(BIO_new(BIO_s_mem()));
    if (!bio || PEM_write_bio_X509(bio.get(), cert) != 1) {
        return {};
    }
    BUF_MEM* contents = nullptr;
    BIO_get_mem_ptr(bio.get(), &contents);
    return std::string(contents->data, contents->length);
}

std::vector<uint8_t> sample_extension_der(const char* path, const char* oid_text) {
    std::ifstream input(path);
    if (!input.good()) {
        return {};
    }
    const std::string pem((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());
    nv_unique_ptr<X509> sample(x509_from_cert_string(pem));
    nv_unique_ptr<ASN1_OBJECT> oid(OBJ_txt2obj(oid_text, 1));
    if (!sample || !oid) {
        return {};
    }
    const int index = X509_get_ext_by_OBJ(sample.get(), oid.get(), -1);
    if (index < 0) {
        return {};
    }
    ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(X509_get_ext(sample.get(), index));
    if (!data || ASN1_STRING_length(data) <= 0) {
        return {};
    }
    const unsigned char* bytes = ASN1_STRING_get0_data(data);
    return {bytes, bytes + ASN1_STRING_length(data)};
}

bool add_der_extension(X509* cert, const char* oid_text,
                       const std::vector<uint8_t>& der, bool critical) {
    nv_unique_ptr<ASN1_OBJECT> oid(OBJ_txt2obj(oid_text, 1));
    std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> data(
        ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free);
    if (!oid || !data || der.empty() ||
        ASN1_OCTET_STRING_set(data.get(), der.data(), static_cast<int>(der.size())) != 1) {
        return false;
    }
    nv_unique_ptr<X509_EXTENSION> extension(X509_EXTENSION_create_by_OBJ(
        nullptr, oid.get(), critical ? 1 : 0, data.get()));
    return extension && X509_add_ext(cert, extension.get(), -1) == 1;
}

class P384SignerTest : public ::testing::TestWithParam<const char*> {
  protected:
    nv_unique_ptr<EVP_PKEY> m_key;
    X509CertChain m_chain;

    void SetUp() override {
        nv_unique_ptr<EVP_PKEY> root_key(
            EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-384"));
        nv_unique_ptr<EVP_PKEY> intermediate_key(
            EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-384"));
        ASSERT_NE(root_key, nullptr);
        ASSERT_NE(intermediate_key, nullptr);
        m_key.reset(std::string(GetParam()) == "RSA"
                        ? EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", 2048)
                        : EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", GetParam()));
        ASSERT_NE(m_key, nullptr);
        auto root = issue_certificate(root_key.get(), "Root", root_key.get(),
                                      nullptr, true, 1);
        ASSERT_NE(root, nullptr);
        auto intermediate = issue_certificate(
            intermediate_key.get(), "Intermediate", root_key.get(), root.get(),
            true, 2);
        ASSERT_NE(intermediate, nullptr);
        auto leaf = issue_certificate(m_key.get(), "Signer", intermediate_key.get(),
                                      intermediate.get(), false, 3);
        ASSERT_NE(leaf, nullptr);
        const std::string root_pem = certificate_pem(root.get());
        const std::string chain_pem = certificate_pem(leaf.get()) +
            certificate_pem(intermediate.get()) + root_pem;
        ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                      CertificateChainType::GENERIC, root_pem, chain_pem, m_chain),
                  Error::Ok);
        ASSERT_EQ(m_chain.verify(), Error::Ok);
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& data,
                              std::size_t component_size = 48) {
        nv_unique_ptr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
        if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha384(), nullptr,
                                       m_key.get()) != 1) {
            ADD_FAILURE() << "signature initialization failed";
            return {};
        }
        std::size_t size = 0;
        if (EVP_DigestSign(ctx.get(), nullptr, &size, data.data(), data.size()) != 1) {
            ADD_FAILURE() << "signature size query failed";
            return {};
        }
        std::vector<uint8_t> der(size);
        if (EVP_DigestSign(ctx.get(), der.data(), &size, data.data(), data.size()) != 1) {
            ADD_FAILURE() << "signing failed";
            return {};
        }
        der.resize(size);
        if (EVP_PKEY_is_a(m_key.get(), "RSA") == 1) {
            der.resize(component_size * 2);
            return der;
        }
        const unsigned char* ptr = der.data();
        nv_unique_ptr<ECDSA_SIG> sig(d2i_ECDSA_SIG(nullptr, &ptr, static_cast<long>(size)));
        if (!sig) {
            ADD_FAILURE() << "ECDSA signature decoding failed";
            return {};
        }
        const BIGNUM* r = nullptr;
        const BIGNUM* s = nullptr;
        ECDSA_SIG_get0(sig.get(), &r, &s);
        std::vector<uint8_t> raw(component_size * 2);
        const int width = static_cast<int>(component_size);
        if (BN_bn2binpad(r, raw.data(), width) != width ||
            BN_bn2binpad(s, raw.data() + component_size, width) != width) {
            ADD_FAILURE() << "ECDSA signature encoding failed";
            return {};
        }
        return raw;
    }

    bool is_p384() const { return std::string(GetParam()) == "P-384"; }
};

TEST_P(P384SignerTest, CoseRequiresP384KeyForEs384) {
    CoseSign1Components components;
    components.has_alg = true;
    components.alg = cose::ALG_ES384;
    components.protected_header_bytes = {0xA1, 0x01, 0x38, 0x22};
    components.payload = {0x01, 0x02, 0x03};
    // Hand-encoded COSE Sig_structure: ["Signature1", h'a1013822', h'', h'010203'].
    const std::vector<uint8_t> tbs = {
        0x84, 0x6A, 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1',
        0x44, 0xA1, 0x01, 0x38, 0x22, 0x40, 0x43, 0x01, 0x02, 0x03};
    components.signature = sign(tbs);
    ASSERT_FALSE(components.signature.empty());
    if (EVP_PKEY_is_a(m_key.get(), "EC") == 1) {
        ASSERT_EQ(m_chain.verify_signature_pkcs11(tbs, components.signature,
                                                  EVP_sha384()), Error::Ok);
    }
    EXPECT_EQ(verify_cose_sign1_signature(components, m_chain),
              is_p384() ? Error::Ok : Error::CoseInvalidSignature);
    if (is_p384()) {
        components.signature.back() ^= 0x01;
        EXPECT_EQ(verify_cose_sign1_signature(components, m_chain),
                  Error::CoseInvalidSignature);
        components.signature = sign(tbs, 50);
        EXPECT_EQ(verify_cose_sign1_signature(components, m_chain),
                  Error::CoseInvalidSignature);
    }
}

TEST_P(P384SignerTest, SpdmRequiresP384KeyForFixedSignatureFormat) {
    std::string hex;
    std::ifstream capture("testdata/hopperAttestationReport.txt");
    ASSERT_TRUE(static_cast<bool>(std::getline(capture, hex)));
    auto transcript = hex_string_to_bytes(hex);
    ASSERT_GT(transcript.size(), 96U);
    ASSERT_EQ(transcript[0], 0x11);
    transcript.resize(transcript.size() - 96);
    auto signature = sign(transcript);
    ASSERT_FALSE(signature.empty());
    if (EVP_PKEY_is_a(m_key.get(), "EC") == 1) {
        ASSERT_EQ(m_chain.verify_signature_pkcs11(transcript, signature,
                                                  EVP_sha384()), Error::Ok);
    }
    transcript.insert(transcript.end(), signature.begin(), signature.end());
    CmwEvidenceItem item;
    item.evidence = CmwRecord(kCmwMediaSpdmTranscript, std::move(transcript));
    const auto* handler = find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);
    EvidenceVerification verification;
    ASSERT_EQ(handler->verify_and_extract_ects(item, m_chain,
                                               EvidenceHandlerSettings{}, verification),
              Error::Ok);
    EXPECT_TRUE(verification.signature_checked);
    EXPECT_EQ(verification.signature_valid, is_p384());
    EXPECT_EQ(verification.parsed, is_p384());
    if (!is_p384()) {
        EXPECT_TRUE(verification.ects.empty());
    }
}

INSTANTIATE_TEST_SUITE_P(KeyTypes, P384SignerTest,
                        ::testing::Values("P-384", "P-256", "brainpoolP384r1", "RSA"));

struct KeySizeCase {
    const char* name;
    const char* root_curve;
    int root_rsa_bits;
    const char* intermediate_curve;
    int intermediate_rsa_bits;
    bool accepted;
    bool unused_weak_cert;
    bool weak_leaf = false;
    bool intermediate_rsa_pss = false;
    const char* leaf_eku = nullptr;
    bool reject_device_only = false;
    const char* unknown_extension = nullptr;
    const char* leaf_basic_constraints = nullptr;
    const char* leaf_key_usage = nullptr;
    bool critical_dice_extension = false;
};

const std::vector<KeySizeCase>& key_size_cases() {
    static const std::string dice_eku = "critical," + OID_TCG_DICE_KP_ATTEST_LOC;
    static const std::string corim_eku_critical =
        "critical," + OID_NVIDIA_CORIM_SIGNING;
    static const std::string combined_eku =
        OID_TCG_DICE_KP_ATTEST_LOC + "," + OID_NVIDIA_CORIM_SIGNING;
    static const std::vector<KeySizeCase> cases = {
        {"P384", "P-384", 0, "P-384", 0, true, false},
        {"Rsa2048Intermediate", "P-384", 0, nullptr, 2048, false, false},
        {"Rsa3071Intermediate", "P-384", 0, nullptr, 3071, false, false},
        {"Rsa3072Intermediate", "P-384", 0, nullptr, 3072, true, false},
        {"Rsa4096Intermediate", "P-384", 0, nullptr, 4096, true, false},
        {"P256Intermediate", "P-384", 0, "P-256", 0, false, false},
        {"P521Intermediate", "P-384", 0, "P-521", 0, true, false},
        {"Rsa2048Root", nullptr, 2048, "P-384", 0, false, false},
        {"P256Root", "P-256", 0, "P-384", 0, false, false},
        {"UnusedP256Certificate", "P-384", 0, "P-384", 0, true, true},
        {"P256Leaf", "P-384", 0, "P-384", 0, false, false, true},
        {"RsaPss2048Intermediate", "P-384", 0, nullptr, 2048, false, false, false, true},
        {"RsaPss3072Intermediate", "P-384", 0, nullptr, 3072, true, false, false, true},
        {"AkWithExpectedEku", "P-384", 0, "P-384", 0, true, false, false, false,
         dice_eku.c_str()},
        {"AkWithOtherEku", "P-384", 0, "P-384", 0, true, false, false, false,
         "critical,1.2.3.4", true},
        {"UnknownCriticalExtension", "P-384", 0, "P-384", 0, false, false,
         false, false, nullptr, false, "critical,ASN1:UTF8String:opaque"},
        {"UnknownNoncriticalExtension", "P-384", 0, "P-384", 0, true, false,
         false, false, nullptr, false, "ASN1:UTF8String:opaque"},
        {"CorimSigningEkuCritical", "P-384", 0, "P-384", 0, true, false,
         false, false, corim_eku_critical.c_str(), true},
        {"CorimSigningEkuNoncritical", "P-384", 0, "P-384", 0, true, false,
         false, false, OID_NVIDIA_CORIM_SIGNING.c_str(), true},
        {"LeafMissingKeyUsage", "P-384", 0, "P-384", 0, true, false,
         false, false, combined_eku.c_str(),
         true, nullptr, nullptr, ""},
        {"LeafWithoutDigitalSignature", "P-384", 0, "P-384", 0, true, false,
         false, false, combined_eku.c_str(),
         true, nullptr, nullptr, "critical,keyEncipherment"},
        {"LeafCaTrue", "P-384", 0, "P-384", 0, true, false,
         false, false, combined_eku.c_str(),
         true, nullptr, "critical,CA:TRUE"},
        {"CriticalDiceTcbInfoAlias", "P-384", 0, "P-384", 0, false, false,
         false, false, nullptr, false, nullptr, nullptr, nullptr, true},
    };
    return cases;
}

nv_unique_ptr<EVP_PKEY> key_for_size_test(const char* curve, int rsa_bits,
                                        bool rsa_pss = false) {
    if (rsa_pss) {
        nv_unique_ptr<EVP_PKEY_CTX> ctx(
            EVP_PKEY_CTX_new_from_name(nullptr, "RSA-PSS", nullptr));
        if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), rsa_bits) != 1) {
            return nullptr;
        }
        EVP_PKEY* key = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &key) != 1) {
            return nullptr;
        }
        return nv_unique_ptr<EVP_PKEY>(key);
    }
    return nv_unique_ptr<EVP_PKEY>(
        curve ? EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", curve)
              : EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", rsa_bits));
}

void append_certificate_bstr(std::vector<uint8_t>& out, X509* cert) {
    const int length = i2d_X509(cert, nullptr);
    ASSERT_GT(length, 0);
    ASSERT_LE(length, 0xFFFF);
    out.push_back(0x59);
    out.push_back(static_cast<uint8_t>(length >> 8));
    out.push_back(static_cast<uint8_t>(length));
    const std::size_t start = out.size();
    out.resize(start + static_cast<std::size_t>(length));
    unsigned char* ptr = out.data() + start;
    ASSERT_EQ(i2d_X509(cert, &ptr), length);
}

class CertificateKeySizeTest : public P384SignerTest {
  protected:
    const KeySizeCase* m_case = nullptr;
    std::string m_root_pem;
    std::string m_chain_pem;
    std::vector<uint8_t> m_cose_header;

    void SetUp() override {
        for (const auto& candidate : key_size_cases()) {
            if (std::string(candidate.name) == GetParam()) {
                m_case = &candidate;
                break;
            }
        }
        ASSERT_NE(m_case, nullptr);
        auto root_key = key_for_size_test(m_case->root_curve, m_case->root_rsa_bits);
        auto intermediate_key = key_for_size_test(
            m_case->intermediate_curve, m_case->intermediate_rsa_bits,
            m_case->intermediate_rsa_pss);
        m_key = key_for_size_test(m_case->weak_leaf ? "P-256" : "P-384", 0);
        ASSERT_NE(root_key, nullptr);
        ASSERT_NE(intermediate_key, nullptr);
        ASSERT_NE(m_key, nullptr);
        auto root = issue_certificate(root_key.get(), "Root", root_key.get(),
                                      nullptr, true, 1);
        ASSERT_NE(root, nullptr);
        auto intermediate = issue_certificate(
            intermediate_key.get(), "Intermediate", root_key.get(), root.get(), true, 2);
        ASSERT_NE(intermediate, nullptr);
        auto leaf = issue_certificate(m_key.get(), "Signer", intermediate_key.get(),
                                      intermediate.get(), false, 3, m_case->leaf_eku,
                                      m_case->unknown_extension,
                                      m_case->leaf_basic_constraints,
                                      m_case->leaf_key_usage);
        ASSERT_NE(leaf, nullptr);
        if (m_case->critical_dice_extension) {
            const auto der = sample_extension_der(
                "testdata/sample_attestation_data/gpu/blackwellCertChain.txt",
                "2.23.133.5.4.1.1");
            ASSERT_FALSE(der.empty());
            ASSERT_TRUE(add_der_extension(leaf.get(), "2.23.133.5.4.1.1",
                                          der, true));
            ASSERT_GT(X509_sign(leaf.get(), intermediate_key.get(), EVP_sha384()), 0);
        }
        m_root_pem = certificate_pem(root.get());
        m_chain_pem = certificate_pem(leaf.get()) + certificate_pem(intermediate.get());

        // COSE_Sign1: protected alg ES384, unprotected x5chain, root omitted.
        m_cose_header = {0xD2, 0x84, 0x44, 0xA1, 0x01, 0x38, 0x22,
                         0xA1, 0x18, 0x21,
                         static_cast<uint8_t>(m_case->unused_weak_cert ? 0x83 : 0x82)};
        append_certificate_bstr(m_cose_header, leaf.get());
        append_certificate_bstr(m_cose_header, intermediate.get());
        if (m_case->unused_weak_cert) {
            auto unused_key = key_for_size_test("P-256", 0);
            ASSERT_NE(unused_key, nullptr);
            auto unused = issue_certificate(unused_key.get(), "Unrelated", root_key.get(),
                                            root.get(), true, 4);
            ASSERT_NE(unused, nullptr);
            m_chain_pem += certificate_pem(unused.get());
            append_certificate_bstr(m_cose_header, unused.get());
        }
        ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                      CertificateChainType::GENERIC, m_root_pem, m_chain_pem, m_chain),
                  Error::Ok);
        ASSERT_EQ(m_chain.verify(),
                  (std::string(m_case->name) == "UnknownCriticalExtension" ||
                   m_case->critical_dice_extension)
                      ? Error::CertChainVerificationFailure : Error::Ok);
    }
};

TEST_P(CertificateKeySizeTest, CoseChecksKeySizesInValidatedPath) {
    const std::vector<uint8_t> tbs = {
        0x84, 0x6A, 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1',
        0x44, 0xA1, 0x01, 0x38, 0x22, 0x40, 0x43, 0x01, 0x02, 0x03};
    const auto signature = sign(tbs);
    ASSERT_EQ(signature.size(), 96u);
    auto cose = m_cose_header;
    cose.insert(cose.end(), {0x43, 0x01, 0x02, 0x03, 0x58, 0x60});
    cose.insert(cose.end(), signature.begin(), signature.end());
    CoseSign1VerifyOptions options;
    options.root_cert_pem = m_root_pem;
    options.verify_ocsp = false;
    NvHttpOcspClient unused_client;
    CoseSign1Result result;
    EXPECT_EQ(verify_cose_sign1(cose, options, unused_client, result),
              m_case->accepted ? Error::Ok : Error::CertChainVerificationFailure);
}

TEST_P(CertificateKeySizeTest, DeviceAppraisalChecksKeySizesInValidatedPath) {
    std::string hex;
    std::ifstream capture("testdata/hopperAttestationReport.txt");
    ASSERT_TRUE(static_cast<bool>(std::getline(capture, hex)));
    auto transcript = hex_string_to_bytes(hex);
    ASSERT_GT(transcript.size(), 96u);
    transcript.resize(transcript.size() - 96);
    const auto signature = sign(transcript);
    transcript.insert(transcript.end(), signature.begin(), signature.end());
    CmwEvidenceItem item;
    item.evidence = CmwRecord(kCmwMediaSpdmTranscript, std::move(transcript));
    item.certificate.reset(new CmwRecord(
        kCmwMediaPemCertChain, std::vector<uint8_t>(m_chain_pem.begin(), m_chain_pem.end())));
    CmwCollection collection;
    collection.add_evidence_item("device", std::move(item));
    std::vector<uint8_t> cmw;
    ASSERT_EQ(collection.serialize(CmwFormat::kJson, cmw), Error::Ok);
    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    ASSERT_EQ(verifier.add_device_identity_trust_root_pem(m_root_pem), Error::Ok);
    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(cmw.data(), cmw.size(), CmwFormat::kJson, result), Error::Ok);
    ASSERT_EQ(result.items.size(), 1u);
    const bool accepted = (m_case->accepted && !m_case->reject_device_only) ||
                          m_case->critical_dice_extension;
    EXPECT_EQ(result.items[0].evidence.signature_verified, accepted);
    EXPECT_EQ(result.items[0].stage_error.code,
              accepted ? Error::RimLocatorUnavailable : Error::CertChainVerificationFailure);
}

TEST_P(CertificateKeySizeTest, InternalMinimumsCanBeAdjusted) {
    if (std::string(m_case->name) == "UnknownCriticalExtension" ||
        m_case->critical_dice_extension) {
        return;
    }
    CertificateKeySizeMinimums minimums;
    minimums.rsa_bits = 2048;
    minimums.ec_bits = 256;
    EXPECT_EQ(m_chain.verify(false, &minimums), Error::Ok);
    minimums.ec_bits = 521;
    EXPECT_EQ(m_chain.verify(false, &minimums), Error::CertChainVerificationFailure);
}

TEST_P(CertificateKeySizeTest, CorimSignerRequiresPurposeEkuWhenRequested) {
    const std::string name = m_case->name;
    if (name != "P384" && name != "AkWithOtherEku" &&
        name != "CorimSigningEkuCritical" &&
        name != "CorimSigningEkuNoncritical" &&
        name != "LeafMissingKeyUsage" &&
        name != "LeafWithoutDigitalSignature" && name != "LeafCaTrue") {
        return;
    }
    const std::vector<uint8_t> tbs = {
        0x84, 0x6A, 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1',
        0x44, 0xA1, 0x01, 0x38, 0x22, 0x40, 0x43, 0x01, 0x02, 0x03};
    const auto signature = sign(tbs);
    ASSERT_EQ(signature.size(), 96u);
    auto cose = m_cose_header;
    cose.insert(cose.end(), {0x43, 0x01, 0x02, 0x03, 0x58, 0x60});
    cose.insert(cose.end(), signature.begin(), signature.end());
    CoseSign1VerifyOptions options;
    options.root_cert_pem = m_root_pem;
    options.verify_ocsp = false;
    options.require_corim_signing_eku = true;
    NvHttpOcspClient unused_client;
    CoseSign1Result result;
    const bool accepted = name == "CorimSigningEkuCritical" ||
                          name == "CorimSigningEkuNoncritical";
    EXPECT_EQ(verify_cose_sign1(cose, options, unused_client, result),
              accepted ? Error::Ok : Error::CertChainVerificationFailure);
}

TEST(CertificateKeySizeMinimumsTest, RejectsNonPositiveMinimums) {
    X509CertChain chain;
    CertificateKeySizeMinimums minimums;
    minimums.rsa_bits = 0;
    EXPECT_EQ(chain.verify(false, &minimums), Error::BadArgument);
    minimums.rsa_bits = 3072;
    minimums.ec_bits = -1;
    EXPECT_EQ(chain.verify(false, &minimums), Error::BadArgument);
}

TEST(RealAkCertificateExtensionsTest, ExistingDeviceChainsRemainValid) {
    const char* paths[] = {
        "testdata/sample_attestation_data/gpu/hopperCertChain.txt",
        "testdata/sample_attestation_data/gpu/blackwellCertChain.txt",
        "testdata/sample_attestation_data/gpu/blackwellFspCertChain.txt",
        "testdata/sample_attestation_data/gpu/gb20xFspCertChain.txt",
        "testdata/sample_attestation_data/gpu/rubinCertChain.txt",
        "testdata/sample_attestation_data/switch/switchCertChain.txt",
    };
    for (const char* path : paths) {
        SCOPED_TRACE(path);
        std::ifstream input(path);
        ASSERT_TRUE(input.good());
        const std::string pem((std::istreambuf_iterator<char>(input)),
                              std::istreambuf_iterator<char>());
        const std::string marker = "-----BEGIN CERTIFICATE-----";
        const std::size_t root_offset = pem.rfind(marker);
        ASSERT_NE(root_offset, std::string::npos);
        ASSERT_GT(root_offset, 0u);
        X509CertChain chain;
        ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                      CertificateChainType::GENERIC, pem.substr(root_offset),
                      pem.substr(0, root_offset), chain), Error::Ok);
        const CertificateKeySizeMinimums minimums;
        ASSERT_EQ(chain.verify(false, &minimums, true), Error::Ok);
        EXPECT_EQ(chain.verify_end_entity_eku(OID_TCG_DICE_KP_ATTEST_LOC, false),
                  Error::Ok);
    }
}

TEST(RealCorimSigningCertificateTest, Gb100VbiosSigningChainHasRequiredEku) {
    std::ifstream input(
        "testdata/sample_attestation_data/gb100_vbios_corim_signing_chain.crt");
    ASSERT_TRUE(input.good());
    const std::string pem((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());
    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GENERIC, RIM_ROOT_CERT_CA001,
                  pem, chain), Error::Ok);
    const CertificateKeySizeMinimums minimums;
    ASSERT_EQ(chain.verify(false, &minimums, true), Error::Ok);
    EXPECT_EQ(chain.verify_end_entity_eku(OID_NVIDIA_CORIM_SIGNING, true),
              Error::Ok);
}

TEST(CertificateUsagePolicyTest, IntermediatesRequireCaBasicConstraints) {
    struct Case {
        const char* name;
        const char* constraints;
    };
    const Case cases[] = {
        {"missing", ""},
        {"cA false", "critical,CA:FALSE"},
    };
    for (const auto& test_case : cases) {
        SCOPED_TRACE(test_case.name);
        auto root_key = key_for_size_test("P-384", 0);
        auto intermediate_key = key_for_size_test("P-384", 0);
        auto leaf_key = key_for_size_test("P-384", 0);
        ASSERT_NE(root_key, nullptr);
        ASSERT_NE(intermediate_key, nullptr);
        ASSERT_NE(leaf_key, nullptr);
        auto root = issue_certificate(root_key.get(), "Root", root_key.get(),
                                      nullptr, true, 1);
        ASSERT_NE(root, nullptr);
        auto intermediate = issue_certificate(
            intermediate_key.get(), "Intermediate", root_key.get(), root.get(),
            true, 2, nullptr, nullptr, test_case.constraints);
        ASSERT_NE(intermediate, nullptr);
        auto leaf = issue_certificate(leaf_key.get(), "Signer", intermediate_key.get(),
                                      intermediate.get(), false, 3);
        ASSERT_NE(leaf, nullptr);
        X509CertChain chain;
        ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                      CertificateChainType::GENERIC, certificate_pem(root.get()),
                      certificate_pem(leaf.get()) + certificate_pem(intermediate.get()),
                      chain), Error::Ok);
        const CertificateKeySizeMinimums minimums;
        EXPECT_EQ(chain.verify(false, &minimums, true),
                  Error::CertChainVerificationFailure);
    }
}

TEST(CertificateUsagePolicyTest, EnforcesIntermediatePathLengthConstraint) {
    auto root_key = key_for_size_test("P-384", 0);
    auto restricted_ca_key = key_for_size_test("P-384", 0);
    auto subordinate_ca_key = key_for_size_test("P-384", 0);
    auto leaf_key = key_for_size_test("P-384", 0);
    ASSERT_NE(root_key, nullptr);
    ASSERT_NE(restricted_ca_key, nullptr);
    ASSERT_NE(subordinate_ca_key, nullptr);
    ASSERT_NE(leaf_key, nullptr);

    auto root = issue_certificate(root_key.get(), "Root", root_key.get(),
                                  nullptr, true, 1);
    ASSERT_NE(root, nullptr);
    auto restricted_ca = issue_certificate(
        restricted_ca_key.get(), "Restricted CA", root_key.get(), root.get(),
        true, 2, nullptr, nullptr, "critical,CA:TRUE,pathlen:0");
    ASSERT_NE(restricted_ca, nullptr);
    auto subordinate_ca = issue_certificate(
        subordinate_ca_key.get(), "Subordinate CA", restricted_ca_key.get(),
        restricted_ca.get(), true, 3);
    ASSERT_NE(subordinate_ca, nullptr);

    auto direct_leaf = issue_certificate(
        leaf_key.get(), "Direct Leaf", restricted_ca_key.get(),
        restricted_ca.get(), false, 4);
    ASSERT_NE(direct_leaf, nullptr);
    X509CertChain direct_chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GENERIC, certificate_pem(root.get()),
                  certificate_pem(direct_leaf.get()) +
                      certificate_pem(restricted_ca.get()), direct_chain),
              Error::Ok);
    EXPECT_EQ(direct_chain.verify(false, nullptr, true), Error::Ok);

    auto nested_leaf = issue_certificate(
        leaf_key.get(), "Nested Leaf", subordinate_ca_key.get(),
        subordinate_ca.get(), false, 5);
    ASSERT_NE(nested_leaf, nullptr);
    X509CertChain nested_chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GENERIC, certificate_pem(root.get()),
                  certificate_pem(nested_leaf.get()) +
                      certificate_pem(subordinate_ca.get()) +
                      certificate_pem(restricted_ca.get()), nested_chain),
              Error::Ok);
    EXPECT_EQ(nested_chain.verify(false, nullptr, true),
              Error::CertChainVerificationFailure);
}

TEST(CertificateExtensionsTest, UnknownCriticalExtensionFailsAtEveryPathDepth) {
    for (int depth = 0; depth < 3; ++depth) {
        SCOPED_TRACE(depth);
        auto root_key = key_for_size_test("P-384", 0);
        auto intermediate_key = key_for_size_test("P-384", 0);
        auto leaf_key = key_for_size_test("P-384", 0);
        ASSERT_NE(root_key, nullptr);
        ASSERT_NE(intermediate_key, nullptr);
        ASSERT_NE(leaf_key, nullptr);
        const char* ext = "critical,ASN1:UTF8String:opaque";
        auto root = issue_certificate(root_key.get(), "Root", root_key.get(),
                                      nullptr, true, 1, nullptr,
                                      depth == 2 ? ext : nullptr);
        ASSERT_NE(root, nullptr);
        auto intermediate = issue_certificate(
            intermediate_key.get(), "Intermediate", root_key.get(), root.get(),
            true, 2, nullptr, depth == 1 ? ext : nullptr);
        ASSERT_NE(intermediate, nullptr);
        auto leaf = issue_certificate(leaf_key.get(), "Signer", intermediate_key.get(),
                                      intermediate.get(), false, 3, nullptr,
                                      depth == 0 ? ext : nullptr);
        ASSERT_NE(leaf, nullptr);
        X509CertChain chain;
        ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                      CertificateChainType::GENERIC, certificate_pem(root.get()),
                      certificate_pem(leaf.get()) + certificate_pem(intermediate.get()),
                      chain), Error::Ok);
        EXPECT_EQ(chain.verify(), Error::CertChainVerificationFailure);
    }
}

TEST(CertificateExtensionsTest, MalformedRecognizedDiceExtensionsFailConversion) {
    const auto alias = sample_extension_der(
        "testdata/sample_attestation_data/gpu/blackwellCertChain.txt",
        "2.23.133.5.4.1.1");
    const auto composite = sample_extension_der(
        "testdata/sample_attestation_data/gpu/hopperCertChain.txt",
        "2.23.133.5.4.1");
    ASSERT_GT(alias.size(), 127u);
    ASSERT_LT(alias.size(), 256u);
    ASSERT_FALSE(composite.empty());
    std::vector<uint8_t> valid_multi = {
        0x30, 0x81, static_cast<uint8_t>(alias.size())};
    valid_multi.insert(valid_multi.end(), alias.begin(), alias.end());
    const std::vector<uint8_t> malformed = {0x01, 0x01, 0x00};
    auto alias_trailing = alias;
    alias_trailing.push_back(0x00);
    auto composite_trailing = composite;
    composite_trailing.push_back(0x00);
    auto multi_trailing = valid_multi;
    multi_trailing.push_back(0x00);
    struct Case {
        const char* oid;
        const std::vector<uint8_t>* der;
        bool add_valid_multi;
    };
    const Case cases[] = {
        {"2.23.133.5.4.1.1", &malformed, false},
        {"2.23.133.5.4.1", &malformed, false},
        {"2.23.133.5.4.5", &malformed, false},
        {"2.23.133.5.4.4", &malformed, false},
        {"2.23.133.5.4.1.1", &malformed, true},
        {"2.23.133.5.4.1.1", &alias_trailing, false},
        {"2.23.133.5.4.1", &composite_trailing, false},
        {"2.23.133.5.4.5", &multi_trailing, false},
    };
    for (const auto& test_case : cases) {
        SCOPED_TRACE(test_case.oid);
        SCOPED_TRACE(test_case.add_valid_multi);
        auto root_key = key_for_size_test("P-384", 0);
        auto leaf_key = key_for_size_test("P-384", 0);
        ASSERT_NE(root_key, nullptr);
        ASSERT_NE(leaf_key, nullptr);
        auto root = issue_certificate(root_key.get(), "Root", root_key.get(),
                                      nullptr, true, 1);
        ASSERT_NE(root, nullptr);
        auto leaf = issue_certificate(leaf_key.get(), "Signer", root_key.get(),
                                      root.get(), false, 2);
        ASSERT_NE(leaf, nullptr);
        if (test_case.add_valid_multi) {
            ASSERT_TRUE(add_der_extension(leaf.get(), "2.23.133.5.4.5",
                                          valid_multi, false));
        }
        ASSERT_TRUE(add_der_extension(leaf.get(), test_case.oid, *test_case.der, false));
        ASSERT_GT(X509_sign(leaf.get(), root_key.get(), EVP_sha384()), 0);
        X509CertChain chain;
        ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                      CertificateChainType::GENERIC, certificate_pem(root.get()),
                      certificate_pem(leaf.get()), chain), Error::Ok);
        EXPECT_EQ(chain.verify(), Error::Ok);
        std::vector<Ect> ects;
        EXPECT_EQ(x509_chain_to_evidence_ects(chain, nullptr, ects),
                  Error::InternalError);
    }
}

TEST(CertificateExtensionsTest, CriticalDiceExtensionsRequireKnownOidAndValidDer) {
    const auto alias = sample_extension_der(
        "testdata/sample_attestation_data/gpu/blackwellCertChain.txt",
        "2.23.133.5.4.1.1");
    const auto composite = sample_extension_der(
        "testdata/sample_attestation_data/gpu/hopperCertChain.txt",
        "2.23.133.5.4.1");
    ASSERT_GT(alias.size(), 127u);
    ASSERT_LT(alias.size(), 256u);
    ASSERT_FALSE(composite.empty());
    std::vector<uint8_t> multi = {0x30, 0x81, static_cast<uint8_t>(alias.size())};
    multi.insert(multi.end(), alias.begin(), alias.end());
    const std::vector<uint8_t> ueid = {0x30, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03};
    const std::vector<uint8_t> malformed = {0x01, 0x01, 0x00};
    const std::vector<uint8_t> unsupported_dti_tag = {0x30, 0x03, 0x9E, 0x01, 0x00};
    const std::vector<uint8_t> duplicate_dti_tag = {
        0x30, 0x06, 0x80, 0x01, 'a', 0x80, 0x01, 'b'};
    auto composite_trailing_data = composite;
    composite_trailing_data.push_back(0x00);
    const std::vector<uint8_t> ueid_trailing_data = {
        0x30, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03, 0x00};
    struct Case {
        const char* name;
        const char* oid;
        const std::vector<uint8_t>* der;
        bool on_intermediate;
        bool add_unknown;
        bool accepted;
    };
    const Case cases[] = {
        {"DiceTcbInfoAlias", "2.23.133.5.4.1.1", &alias, false, false, true},
        {"CompositeDeviceId", "2.23.133.5.4.1", &composite, false, false, true},
        {"MultiDiceTcbInfo", "2.23.133.5.4.5", &multi, false, false, true},
        {"DiceUeid", "2.23.133.5.4.4", &ueid, false, false, true},
        {"IntermediateDiceTcbInfoAlias", "2.23.133.5.4.1.1", &alias, true, false, true},
        {"MalformedAlias", "2.23.133.5.4.1.1", &malformed, false, false, false},
        {"MalformedPrimary", "2.23.133.5.4.1", &malformed, false, false, false},
        {"MalformedMulti", "2.23.133.5.4.5", &malformed, false, false, false},
        {"MalformedUeid", "2.23.133.5.4.4", &malformed, false, false, false},
        {"UnsupportedCriticalDtiTag", "2.23.133.5.4.1.1",
         &unsupported_dti_tag, false, false, false},
        {"DuplicateCriticalDtiTag", "2.23.133.5.4.1.1",
         &duplicate_dti_tag, false, false, false},
        {"CompositeTrailingData", "2.23.133.5.4.1",
         &composite_trailing_data, false, false, false},
        {"UeidTrailingData", "2.23.133.5.4.4",
         &ueid_trailing_data, false, false, false},
        {"KnownAndUnknown", "2.23.133.5.4.1.1", &alias, false, true, false},
    };
    for (const auto& test_case : cases) {
        SCOPED_TRACE(test_case.name);
        auto root_key = key_for_size_test("P-384", 0);
        auto intermediate_key = key_for_size_test("P-384", 0);
        auto leaf_key = key_for_size_test("P-384", 0);
        ASSERT_NE(root_key, nullptr);
        ASSERT_NE(intermediate_key, nullptr);
        ASSERT_NE(leaf_key, nullptr);
        auto root = issue_certificate(root_key.get(), "Root", root_key.get(),
                                      nullptr, true, 1);
        ASSERT_NE(root, nullptr);
        auto intermediate = issue_certificate(intermediate_key.get(), "Intermediate",
                                              root_key.get(), root.get(), true, 2);
        ASSERT_NE(intermediate, nullptr);
        auto leaf = issue_certificate(leaf_key.get(), "Signer", intermediate_key.get(),
                                      intermediate.get(), false, 3);
        ASSERT_NE(leaf, nullptr);
        X509* target = test_case.on_intermediate ? intermediate.get() : leaf.get();
        ASSERT_TRUE(add_der_extension(target, test_case.oid, *test_case.der, true));
        if (test_case.add_unknown) {
            nv_unique_ptr<X509_EXTENSION> unknown(X509V3_EXT_conf(
                nullptr, nullptr, "1.2.3.4.5.6", "critical,ASN1:UTF8String:opaque"));
            ASSERT_NE(unknown, nullptr);
            ASSERT_EQ(X509_add_ext(target, unknown.get(), -1), 1);
        }
        ASSERT_GT(X509_sign(target, test_case.on_intermediate ? root_key.get()
                                                               : intermediate_key.get(),
                            EVP_sha384()), 0);
        X509CertChain chain;
        ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                      CertificateChainType::GENERIC, certificate_pem(root.get()),
                      certificate_pem(leaf.get()) + certificate_pem(intermediate.get()),
                      chain), Error::Ok);
        const CertificateKeySizeMinimums minimums;
        EXPECT_EQ(chain.verify(false, &minimums, true, true),
                  test_case.accepted ? Error::Ok : Error::CertChainVerificationFailure);
        if (test_case.accepted) {
            std::vector<Ect> ects;
            EXPECT_EQ(x509_chain_to_evidence_ects(chain, nullptr, ects), Error::Ok);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    KeySizes, CertificateKeySizeTest,
    ::testing::Values("P384", "Rsa2048Intermediate", "Rsa3071Intermediate",
                      "Rsa3072Intermediate", "Rsa4096Intermediate", "P256Intermediate",
                      "P521Intermediate", "Rsa2048Root", "P256Root", "UnusedP256Certificate",
                      "P256Leaf", "RsaPss2048Intermediate", "RsaPss3072Intermediate",
                      "AkWithExpectedEku", "AkWithOtherEku",
                      "UnknownCriticalExtension", "UnknownNoncriticalExtension",
                      "CorimSigningEkuCritical", "CorimSigningEkuNoncritical",
                      "LeafMissingKeyUsage", "LeafWithoutDigitalSignature",
                      "LeafCaTrue", "CriticalDiceTcbInfoAlias"));

} // namespace
