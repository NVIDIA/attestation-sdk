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

#include "gtest/gtest.h"

#include <vector>
#include <string>

#include "nv_attestation/nv_x509.h"
#include "nv_attestation/nv_types.h"
#include "nv_attestation/error.h"
#include "nv_attestation/utils.h"

using namespace nvattestation;

class X509CertChainSignatureTest : public ::testing::Test {
protected:
    std::string m_root_cert_pem_str;
    std::string m_leaf_cert_pem_str;
    X509CertChain m_cert_chain;
    std::vector<uint8_t> m_data_to_sign;
    std::vector<uint8_t> m_valid_signature;
    const EVP_MD* m_hash_algo = EVP_sha256();

    std::string kTestX509CertChainDir = "testdata/x509_cert_chain/";
    std::string kTestRootCertPath = kTestX509CertChainDir + "root_cert";
    std::string kTestLeafCertPath = kTestX509CertChainDir + "leaf_cert_with_fwid";
    std::string kTestSignatureFilePath = kTestX509CertChainDir + "valid_signature.sig";
    std::string kTestDataFilePath = kTestX509CertChainDir + "signed_data.txt";

    void SetUp() override {

        Error error = readFileIntoString(kTestRootCertPath, m_root_cert_pem_str);
        ASSERT_EQ(error, Error::Ok);

        error = readFileIntoString(kTestLeafCertPath, m_leaf_cert_pem_str);
        ASSERT_EQ(error, Error::Ok);

        X509CertChain out_cert_chain;
        error = X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, m_root_cert_pem_str, out_cert_chain);
        ASSERT_EQ(error, Error::Ok) << "X509CertChain::create failed. SDK error: " << to_string(error);
        
        error = out_cert_chain.push_back(m_leaf_cert_pem_str);
        ASSERT_EQ(error, Error::Ok) << "push_back failed for leaf cert: " << to_string(error);
        
        m_cert_chain = std::move(out_cert_chain);

        ASSERT_EQ(m_cert_chain.size(), 1) << "Certificate chain size should be 1 after push_back.";

        // Read pre-generated signature and data files
        std::string data_str;
        error = readFileIntoString(kTestDataFilePath, data_str);
        ASSERT_EQ(error, Error::Ok);
        m_data_to_sign.assign(data_str.begin(), data_str.end());

        std::string signature_str;
        error = readFileIntoString(kTestSignatureFilePath, signature_str);
        ASSERT_EQ(error, Error::Ok);
        m_valid_signature.assign(signature_str.begin(), signature_str.end());
        ASSERT_FALSE(m_valid_signature.empty()) << "Signature file is empty: " << kTestSignatureFilePath;
    }

    void TearDown() override {
    }
};


TEST_F(X509CertChainSignatureTest, ValidSignature) {
    Error error = m_cert_chain.verify_signature(m_data_to_sign, m_valid_signature, m_hash_algo);
    EXPECT_EQ(error, Error::Ok) << "Signature verification failed for a valid signature.";
}

TEST_F(X509CertChainSignatureTest, InvalidSignatureTamperedData) {
    std::vector<uint8_t> tampered_data = m_data_to_sign;
    ASSERT_FALSE(tampered_data.empty()) << "Original data to sign is empty, cannot tamper.";
    tampered_data[0]++;

    Error error = m_cert_chain.verify_signature(tampered_data, m_valid_signature, m_hash_algo);
    EXPECT_EQ(error, Error::InternalError) << "Signature verification succeeded for tampered data.";
}

TEST_F(X509CertChainSignatureTest, InvalidSignatureIncorrectSignature) {
    std::vector<uint8_t> incorrect_signature = m_valid_signature;
    ASSERT_FALSE(incorrect_signature.empty()) << "Original valid signature is empty, cannot make incorrect.";
    incorrect_signature[0]++;

    Error error = m_cert_chain.verify_signature(m_data_to_sign, incorrect_signature, m_hash_algo);
    EXPECT_EQ(error, Error::InternalError) << "Signature verification succeeded for an incorrect signature.";
}

TEST_F(X509CertChainSignatureTest, NullHashAlgorithmRejected) {
    Error error = m_cert_chain.verify_signature(m_data_to_sign, m_valid_signature, nullptr);
    EXPECT_EQ(error, Error::InternalError) << "A null digest must not be accepted.";
}

TEST(X509CertChainSignatureEmptyChainTest, EmptyChainHasNoKeyToVerifyWith) {
    X509CertChain chain;
    const std::vector<uint8_t> data{0x01, 0x02};
    const std::vector<uint8_t> signature{0x03, 0x04};
    EXPECT_NE(chain.verify_signature(data, signature, EVP_sha256()), Error::Ok);
}

class X509CertChainFwidTest : public ::testing::Test {
protected:
    std::string m_root_cert_pem_str;
    std::string m_leaf_cert_with_fwid_pem_str;
    std::string m_leaf_cert_without_fwid_pem_str;
    std::vector<uint8_t> m_expected_fwid_bytes;

    std::string kTestX509CertChainDir = "testdata/x509_cert_chain/";
    std::string kTestFwidRootCertPath = kTestX509CertChainDir + "root_cert";
    std::string kTestFwidLeafCertWithFwidPath = kTestX509CertChainDir + "leaf_cert_with_fwid";
    std::string kTestFwidLeafCertWithoutFwidPath = kTestX509CertChainDir + "leaf_cert_without_fwid";

    void SetUp() override {

        m_expected_fwid_bytes.clear();
        m_expected_fwid_bytes.reserve(48);
        for (uint8_t i = 1; i <= 48; ++i) {
            m_expected_fwid_bytes.push_back(i);
        }

        Error error = readFileIntoString(kTestFwidRootCertPath, m_root_cert_pem_str);
        ASSERT_EQ(error, Error::Ok);

        error = readFileIntoString(kTestFwidLeafCertWithFwidPath, m_leaf_cert_with_fwid_pem_str);
        ASSERT_EQ(error, Error::Ok);

        error = readFileIntoString(kTestFwidLeafCertWithoutFwidPath, m_leaf_cert_without_fwid_pem_str);
        ASSERT_EQ(error, Error::Ok);

        ASSERT_FALSE(m_root_cert_pem_str.empty()) << "Root certificate PEM is empty. File: " << kTestFwidRootCertPath;
        ASSERT_FALSE(m_leaf_cert_with_fwid_pem_str.empty()) << "Leaf certificate with FWID PEM is empty. File: " << kTestFwidLeafCertWithFwidPath;
        ASSERT_FALSE(m_leaf_cert_without_fwid_pem_str.empty()) << "Leaf certificate without FWID PEM is empty. File: " << kTestFwidLeafCertWithoutFwidPath;
    }

    void TearDown() override {
    }
};


TEST_F(X509CertChainFwidTest, FwidFoundInCert) {
    X509CertChain out_cert_chain;
    Error error = X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, m_root_cert_pem_str, out_cert_chain);
    ASSERT_EQ(error, Error::Ok) << "X509CertChain::create failed: " << to_string(error);
    
    error = out_cert_chain.push_back(m_leaf_cert_with_fwid_pem_str);
    ASSERT_EQ(error, Error::Ok) << "push_back failed for leaf cert with FWID: " << to_string(error);
    ASSERT_EQ(out_cert_chain.size(), 1);

    std::vector<uint8_t> out_fwid;
    error = out_cert_chain.get_fwid(0, X509CertChain::FWIDType::FWID_2_23_133_5_4_1, out_fwid);
    EXPECT_EQ(error, Error::Ok) << "get_fwid failed for cert with FWID: " << to_string(error);
    ASSERT_FALSE(out_fwid.empty()) << "out_fwid should not be empty when FWID is found.";
    EXPECT_EQ(out_fwid.size(), m_expected_fwid_bytes.size()) << "FWID size mismatch.";
    EXPECT_EQ(out_fwid, m_expected_fwid_bytes) << "Extracted FWID does not match expected FWID.";
}

TEST_F(X509CertChainFwidTest, FwidNotFoundInCert) {
    X509CertChain out_cert_chain;
    Error error = X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, m_root_cert_pem_str, out_cert_chain);
    ASSERT_EQ(error, Error::Ok) << "X509CertChain::create failed: " << to_string(error);
    
    error = out_cert_chain.push_back(m_leaf_cert_without_fwid_pem_str);
    ASSERT_EQ(error, Error::Ok) << "push_back failed for leaf cert without FWID: " << to_string(error);
    ASSERT_EQ(out_cert_chain.size(), 1);

    std::vector<uint8_t> out_fwid;
    error = out_cert_chain.get_fwid(0, X509CertChain::FWIDType::FWID_2_23_133_5_4_1, out_fwid);
    EXPECT_EQ(error, Error::CertFwidNotFound) << "get_fwid should return CertFwidNotFound for cert without FWID, but returned: " << to_string(error);
    EXPECT_TRUE(out_fwid.empty()) << "out_fwid should be empty when FWID is not found.";
}

TEST_F(X509CertChainFwidTest, IndexOutOfBoundsTooHigh) {
    X509CertChain cert_chain_obj;
    Error error = X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, m_root_cert_pem_str, cert_chain_obj);
    ASSERT_EQ(error, Error::Ok) << "X509CertChain::create failed: " << to_string(error);

    error = cert_chain_obj.push_back(m_leaf_cert_with_fwid_pem_str);
    ASSERT_EQ(error, Error::Ok) << "push_back failed: " << to_string(error);
    ASSERT_EQ(cert_chain_obj.size(), 1);

    std::vector<uint8_t> out_fwid;
    error = cert_chain_obj.get_fwid(1, X509CertChain::FWIDType::FWID_2_23_133_5_4_1, out_fwid);
    EXPECT_EQ(error, Error::CertNotFound) << "get_fwid should return CertNotFound for out-of-bounds index, but returned: " << to_string(error);
}

TEST_F(X509CertChainFwidTest, IndexOutOfBoundsEmptyChain) {
    X509CertChain cert_chain_obj;
    Error error = X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, m_root_cert_pem_str, cert_chain_obj);
    ASSERT_EQ(error, Error::Ok) << "X509CertChain::create failed: " << to_string(error);
    
    ASSERT_EQ(cert_chain_obj.size(), 0) << "Certificate chain should be empty.";

    std::vector<uint8_t> out_fwid;
    error = cert_chain_obj.get_fwid(0, X509CertChain::FWIDType::FWID_2_23_133_5_4_1, out_fwid);
    EXPECT_EQ(error, Error::CertNotFound) << "get_fwid should return CertNotFound for empty chain, but returned: " << to_string(error);
}


class X509CertChainVerifyTest : public ::testing::Test {
protected:
    std::string m_root_cert_pem_str;
    std::string m_leaf_cert_expired_pem_str;
    std::string m_leaf_cert_wrong_signature_pem_str;

    std::string kTestX509CertChainDir = "testdata/x509_cert_chain/";
    std::string kTestRootCertPath = kTestX509CertChainDir + "root_cert";
    std::string kTestLeafCertExpiredPath = kTestX509CertChainDir + "leaf_cert_expired";
    std::string kTestLeafCertWrongSignaturePath = kTestX509CertChainDir + "leaf_cert_wrong_signature";

    void SetUp() override {

        Error error = readFileIntoString(kTestRootCertPath, m_root_cert_pem_str);
        ASSERT_EQ(error, Error::Ok);

        error = readFileIntoString(kTestLeafCertExpiredPath, m_leaf_cert_expired_pem_str);
        ASSERT_EQ(error, Error::Ok);

        error = readFileIntoString(kTestLeafCertWrongSignaturePath, m_leaf_cert_wrong_signature_pem_str);
        ASSERT_EQ(error, Error::Ok);

        ASSERT_FALSE(m_root_cert_pem_str.empty()) << "Root certificate PEM is empty. File: " << kTestRootCertPath;
        ASSERT_FALSE(m_leaf_cert_expired_pem_str.empty()) << "Expired leaf certificate PEM is empty. File: " << kTestLeafCertExpiredPath;
        ASSERT_FALSE(m_leaf_cert_wrong_signature_pem_str.empty()) << "Wrong signature leaf certificate PEM is empty. File: " << kTestLeafCertWrongSignaturePath;
    }

    void TearDown() override {
    }
};


TEST_F(X509CertChainVerifyTest, ExpiredCertificatePassesVerification) {
    
    X509CertChain cert_chain;
    Error error = X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, m_root_cert_pem_str, cert_chain);
    ASSERT_EQ(error, Error::Ok) << "X509CertChain::create failed: " << to_string(error);
    
    error = cert_chain.push_back(m_leaf_cert_expired_pem_str);
    ASSERT_EQ(error, Error::Ok) << "push_back failed for expired leaf cert: " << to_string(error);
    ASSERT_EQ(cert_chain.size(), 1);

    error = cert_chain.verify();
    EXPECT_EQ(error, Error::Ok) << "Expired certificate should pass verification when time checks are disabled.";
}

TEST_F(X509CertChainVerifyTest, MinExpirationTime) {
    
    X509CertChain cert_chain;
    Error error = X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, m_root_cert_pem_str, cert_chain);
    ASSERT_EQ(error, Error::Ok) << "X509CertChain::create failed: " << to_string(error);
    
    error = cert_chain.push_back(m_leaf_cert_expired_pem_str);
    ASSERT_EQ(error, Error::Ok) << "push_back failed for expired leaf cert: " << to_string(error);
    ASSERT_EQ(cert_chain.size(), 1);

    time_t min_expiration_time = 0;
    error = cert_chain.calculate_min_expiration_time(min_expiration_time);
    ASSERT_EQ(error, Error::Ok) << "calculate_min_expiration_time failed: " << to_string(error);
    EXPECT_LT(min_expiration_time, time(nullptr)) << "notAfter should be in the past";
}

TEST_F(X509CertChainVerifyTest, InvalidSignatureFailsVerification) {
    
    X509CertChain cert_chain;
    Error error = X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, m_root_cert_pem_str, cert_chain);
    ASSERT_EQ(error, Error::Ok) << "X509CertChain::create failed: " << to_string(error);
    
    error = cert_chain.push_back(m_leaf_cert_wrong_signature_pem_str);
    ASSERT_EQ(error, Error::Ok) << "push_back failed for wrong signature leaf cert: " << to_string(error);
    ASSERT_EQ(cert_chain.size(), 1);

    error = cert_chain.verify();
    EXPECT_EQ(error, Error::CertChainVerificationFailure) << "Certificate with invalid signature should fail verification.";
}

// DMTF SubjectAltName otherName (1.3.6.1.4.1.412.274.1) carries
// "<manufacturer>:<product>:<serial>"; the claim is the final field.
TEST(X509CertChainDmtfSerialTest, ExtractsSerialFromOtherName) {
    std::string pem;
    ASSERT_EQ(readFileIntoString(
                  "testdata/sample_attestation_data/gpu/rubinCertChain.txt", pem),
              Error::Ok);
    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GPU_DEVICE_IDENTITY, pem, pem, chain),
              Error::Ok);

    DmtfDeviceInfo info;
    ASSERT_EQ(chain.get_end_entity_dmtf_device_info(info), Error::Ok);
    EXPECT_EQ(info.serial, "48B02D1D45D71980");
    EXPECT_EQ(info.product, "GR100");
}

TEST(X509CertChainDmtfSerialTest, ExtractsSerialFromBlackwellChain) {
    std::string pem;
    ASSERT_EQ(readFileIntoString(
                  "testdata/sample_attestation_data/gpu/blackwellCertChain.txt", pem),
              Error::Ok);
    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GPU_DEVICE_IDENTITY, pem, pem, chain),
              Error::Ok);

    DmtfDeviceInfo info;
    ASSERT_EQ(chain.get_end_entity_dmtf_device_info(info), Error::Ok);
    EXPECT_EQ(info.serial, "48B02DD4C0CB1539");
    EXPECT_EQ(info.product, "GB100");
}

// Not every chain carries the extension; absence is reported, not fatal.
TEST(X509CertChainDmtfSerialTest, AbsentExtensionReportsCertNotFound) {
    std::string pem;
    ASSERT_EQ(readFileIntoString(
                  "testdata/sample_attestation_data/cpu/veraCertChain.txt", pem),
              Error::Ok);
    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GENERIC, pem, pem, chain),
              Error::Ok);

    DmtfDeviceInfo info;
    EXPECT_EQ(chain.get_end_entity_dmtf_device_info(info), Error::CertNotFound);
}


// An empty chain has no end-entity certificate to read the extension from.
TEST(X509CertChainDmtfSerialTest, EmptyChainReportsCertNotFound) {
    X509CertChain chain;
    DmtfDeviceInfo info;
    EXPECT_EQ(chain.get_end_entity_dmtf_device_info(info), Error::CertNotFound);
}

// The serial is read per index; the device cert is not always the leaf.
TEST(X509CertChainSerialTest, ReadsSerialAtIndex) {
    std::string pem;
    ASSERT_EQ(readFileIntoString(
                  "testdata/sample_attestation_data/gpu/blackwellCertChain.txt", pem),
              Error::Ok);
    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GPU_DEVICE_IDENTITY, pem, pem, chain),
              Error::Ok);
    ASSERT_GT(chain.size(), 0u);

    std::string leaf_serial;
    ASSERT_EQ(chain.get_cert_serial(0, leaf_serial), Error::Ok);
    EXPECT_FALSE(leaf_serial.empty());
    // Decimal, per BN_bn2dec.
    EXPECT_EQ(leaf_serial.find_first_not_of("0123456789"), std::string::npos);

    // get_end_entity_serial is index 0 by definition.
    std::string end_entity_serial;
    ASSERT_EQ(chain.get_end_entity_serial(end_entity_serial), Error::Ok);
    EXPECT_EQ(end_entity_serial, leaf_serial);
}

TEST(X509CertChainSerialTest, IndexOutOfBoundsReportsCertNotFound) {
    X509CertChain chain;
    std::string serial;
    EXPECT_EQ(chain.get_cert_serial(0, serial), Error::CertNotFound);
    EXPECT_EQ(chain.get_cert_serial(99, serial), Error::CertNotFound);
}

// akpub is exported from the end-entity key, so an empty chain has none.
TEST(X509CertChainPublicKeyTest, ExportsEndEntityKeyAsPem) {
    std::string pem;
    ASSERT_EQ(readFileIntoString(
                  "testdata/sample_attestation_data/gpu/blackwellCertChain.txt", pem),
              Error::Ok);
    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GPU_DEVICE_IDENTITY, pem, pem, chain),
              Error::Ok);

    std::string key_pem;
    ASSERT_EQ(chain.get_end_entity_public_key_pem(key_pem), Error::Ok);
    EXPECT_NE(key_pem.find("-----BEGIN PUBLIC KEY-----"), std::string::npos);
    EXPECT_NE(key_pem.find("-----END PUBLIC KEY-----"), std::string::npos);
}

TEST(X509CertChainPublicKeyTest, EmptyChainHasNoPublicKey) {
    X509CertChain chain;
    std::string key_pem;
    EXPECT_NE(chain.get_end_entity_public_key_pem(key_pem), Error::Ok);
    EXPECT_TRUE(key_pem.empty());
}

// DSP0274 §330 fixes the value at exactly "<manufacturer>:<product>:<serial>",
// with no colon permitted inside a field.
TEST(DmtfDeviceInfoSerialTest, SplitsAllThreeFields) {
    DmtfDeviceInfo info;
    ASSERT_EQ(parse_dmtf_device_info("NVIDIA:GB100:48B02DD4C0CB1539", info),
              Error::Ok);
    EXPECT_EQ(info.manufacturer, "NVIDIA");
    EXPECT_EQ(info.product, "GB100");
    EXPECT_EQ(info.serial, "48B02DD4C0CB1539");
    // The spec's own example.
    ASSERT_EQ(parse_dmtf_device_info("ACME:WIDGET:0123456789", info), Error::Ok);
    EXPECT_EQ(info.product, "WIDGET");
    EXPECT_EQ(info.serial, "0123456789");
}

TEST(DmtfDeviceInfoSerialTest, RejectsMalformedValues) {
    const char* const kMalformed[] = {
        "48B02DD4C0CB1539",               // no separators — was returned whole
        "NVIDIA:48B02DD4C0CB1539",        // two fields
        "NVIDIA:GB100:A:48B02DD4C0CB15",  // four fields
        "NVIDIA:GB100:",                  // empty serial
        "",                               // empty value
    };
    for (const char* value : kMalformed) {
        DmtfDeviceInfo info;
        info.serial = "stale";
        EXPECT_EQ(parse_dmtf_device_info(value, info), Error::BadArgument)
            << value;
        EXPECT_EQ(info.serial, "stale") << value;
    }
}

TEST(X509CertChainTest, GetSubjectCnReturnsLeafCn) {
    std::string root_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/root_cert", root_pem),
              Error::Ok);
    std::string leaf_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/leaf_cert_with_fwid", leaf_pem),
              Error::Ok);

    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, root_pem, chain),
              Error::Ok);
    ASSERT_EQ(chain.push_back(leaf_pem), Error::Ok);

    std::string cn;
    Error err = chain.get_subject_cn(0, cn);

    EXPECT_EQ(err, Error::Ok);
    EXPECT_FALSE(cn.empty());
}

TEST(X509CertChainTest, GetSubjectCnOutOfRangeIndexFails) {
    std::string root_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/root_cert", root_pem),
              Error::Ok);
    std::string leaf_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/leaf_cert_with_fwid", leaf_pem),
              Error::Ok);

    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, root_pem, chain),
              Error::Ok);
    ASSERT_EQ(chain.push_back(leaf_pem), Error::Ok);

    std::string cn;
    Error err = chain.get_subject_cn(999, cn);

    EXPECT_EQ(err, Error::CertNotFound);
}

namespace {
PerCertStatus good_cert_status() {
    PerCertStatus status;
    status.expired = false;
    status.ocsp = std::make_shared<PerCertStatus::OcspInfo>();
    status.ocsp->crl_status = OCSPStatus::GOOD;
    status.ocsp->nonce_matches = true;
    status.ocsp->response_valid = true;
    return status;
}

// chain[0] is always the root (self-signed trust anchor): generate_per_cert_status()
// returns root-first and never queries OCSP for it. These tests put the cert
// under test at index 1, with a root placeholder (no ocsp info) at index 0.
PerCertStatus root_placeholder_status() {
    PerCertStatus status;
    status.expired = false;
    return status;
}

// Represents a non-root cert whose OCSP check was skipped as not applicable
// (e.g. the device's attestation-key/"AK" leaf cert has no AIA responder
// URL, as on real NVIDIA GPU device-identity chains). Must not be required
// to show a GOOD OCSP status.
PerCertStatus ak_cert_status() {
    PerCertStatus status;
    status.expired = false;
    status.ocsp = std::make_shared<PerCertStatus::OcspInfo>();
    status.ocsp->crl_status = OCSPStatus::NOT_CHECKED;
    return status;
}
}  // namespace

TEST(AllCertsTrustedTest, AllGoodPasses) {
    std::vector<PerCertStatus> chain{root_placeholder_status(), good_cert_status(), good_cert_status()};
    EXPECT_TRUE(all_certs_trusted(chain));
}

TEST(AllCertsTrustedTest, NotApplicableOcspPasses) {
    std::vector<PerCertStatus> chain{
        root_placeholder_status(), good_cert_status(), good_cert_status(), ak_cert_status()};
    EXPECT_TRUE(all_certs_trusted(chain));
}

TEST(AllCertsTrustedTest, RootOcspNotRequired) {
    std::vector<PerCertStatus> chain{root_placeholder_status(), good_cert_status()};
    EXPECT_TRUE(all_certs_trusted(chain));
}

TEST(AllCertsTrustedTest, ExpiredCertFailsEvenWithoutOcsp) {
    PerCertStatus expired = good_cert_status();
    expired.expired = true;
    std::vector<PerCertStatus> chain{root_placeholder_status(), expired};
    EXPECT_FALSE(all_certs_trusted(chain));
}

TEST(AllCertsTrustedTest, ExpiredRootFails) {
    PerCertStatus expired_root = root_placeholder_status();
    expired_root.expired = true;
    std::vector<PerCertStatus> chain{expired_root, good_cert_status()};
    EXPECT_FALSE(all_certs_trusted(chain));
}

TEST(AllCertsTrustedTest, NonceMismatchFails) {
    PerCertStatus bad_nonce = good_cert_status();
    bad_nonce.ocsp->nonce_matches = false;
    std::vector<PerCertStatus> chain{root_placeholder_status(), bad_nonce};
    EXPECT_FALSE(all_certs_trusted(chain));
}

TEST(AllCertsTrustedTest, InvalidResponseFails) {
    PerCertStatus bad_response = good_cert_status();
    bad_response.ocsp->response_valid = false;
    std::vector<PerCertStatus> chain{root_placeholder_status(), bad_response};
    EXPECT_FALSE(all_certs_trusted(chain));
}

TEST(AllCertsTrustedTest, ErrorStatusFails) {
    PerCertStatus errored = good_cert_status();
    errored.ocsp->crl_status = OCSPStatus::ERROR;
    std::vector<PerCertStatus> chain{root_placeholder_status(), errored};
    EXPECT_FALSE(all_certs_trusted(chain));
}

TEST(AllCertsTrustedTest, MissingOcspInfoPasses) {
    PerCertStatus no_ocsp;
    no_ocsp.expired = false;
    std::vector<PerCertStatus> chain{root_placeholder_status(), no_ocsp};
    EXPECT_TRUE(all_certs_trusted(chain));
}
