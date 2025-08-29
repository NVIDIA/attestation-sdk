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

// System headers
#include <fstream>
#include <vector>
#include <string>
#include <memory>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h> 

// SDK headers
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/nv_types.h"
#include "nv_attestation/error.h"
#include "nv_attestation/utils.h"

using namespace nvattestation;

// Helper function to sign data using OpenSSL EVP functions
static std::vector<uint8_t> sign_data_with_key_str(
    const std::vector<uint8_t>& data_to_sign,
    const std::string& private_key_pem_str,
    const EVP_MD* md_algo) {

    nv_unique_ptr<BIO> key_bio(BIO_new_mem_buf(private_key_pem_str.data(), static_cast<int>(private_key_pem_str.length())));
    if (!key_bio) {
        ADD_FAILURE() << "BIO_new_mem_buf failed for private key: " << get_openssl_error();
        return {};
    }

    nv_unique_ptr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
    if (!pkey) {
        ADD_FAILURE() << "PEM_read_bio_PrivateKey failed: " << get_openssl_error();
        // ERR_print_errors_fp(stderr); // Useful for direct OpenSSL error debugging
        return {};
    }

    nv_unique_ptr<EVP_MD_CTX> md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        ADD_FAILURE() << "EVP_MD_CTX_new failed: " << get_openssl_error();
        return {};
    }

    if (EVP_DigestSignInit(md_ctx.get(), nullptr, md_algo, nullptr, pkey.get()) != 1) {
        ADD_FAILURE() << "EVP_DigestSignInit failed: " << get_openssl_error();
        return {};
    }

    if (EVP_DigestSignUpdate(md_ctx.get(), data_to_sign.data(), data_to_sign.size()) != 1) {
        ADD_FAILURE() << "EVP_DigestSignUpdate failed: " << get_openssl_error();
        return {};
    }

    size_t sig_len = 0;
    // First call to get the required buffer size
    if (EVP_DigestSignFinal(md_ctx.get(), nullptr, &sig_len) != 1) {
        ADD_FAILURE() << "EVP_DigestSignFinal (getting length) failed: " << get_openssl_error();
        return {};
    }

    std::vector<uint8_t> signature(sig_len);
    // Second call to actually get the signature
    if (EVP_DigestSignFinal(md_ctx.get(), signature.data(), &sig_len) != 1) {
        ADD_FAILURE() << "EVP_DigestSignFinal (signing) failed: " << get_openssl_error();
        return {};
    }
    // signature.resize(sig_len); // sig_len should be updated to the actual length, resize if needed.

    return signature;
}


class X509CertChainSignatureTest : public ::testing::Test {
protected:
    std::string m_root_cert_pem_str;
    std::string m_leaf_cert_pem_str;
    std::string m_leaf_key_pem_str;
    X509CertChain m_cert_chain;
    std::vector<uint8_t> m_data_to_sign;
    std::vector<uint8_t> m_valid_signature;
    const EVP_MD* m_hash_algo = EVP_sha256();

    // Paths to test data files from FWID certificate generation script
    static const std::string kTestX509CertChainDir;
    static const std::string kTestRootCertPath;
    static const std::string kTestLeafCertPath;
    static const std::string kTestLeafKeyPath;


    void SetUp() override {
        ErrorStack::clear(); // Clear any previous SDK errors

        Error error = readFileIntoString(kTestRootCertPath, m_root_cert_pem_str);
        if (error != Error::Ok) {
            FAIL() << "Failed to read root certificate file: " << kTestRootCertPath
                   << "\nPlease ensure you have run the 'unit-tests/testdata/generate_test_certs.sh' script"
                   << "\nto generate the required certificates in '" << kTestX509CertChainDir << "'.";
        }

        error = readFileIntoString(kTestLeafCertPath, m_leaf_cert_pem_str);
        if (error != Error::Ok) {
            FAIL() << "Failed to read leaf certificate file: " << kTestLeafCertPath
                   << "\nPlease ensure you have run the 'unit-tests/testdata/generate_test_certs.sh' script"
                   << "\nto generate the required certificates in '" << kTestX509CertChainDir << "'.";
        }

        error = readFileIntoString(kTestLeafKeyPath, m_leaf_key_pem_str);
        if (error != Error::Ok) {
            FAIL() << "Failed to read leaf key file: " << kTestLeafKeyPath
                   << "\nPlease ensure you have run the 'unit-tests/testdata/generate_test_certs.sh' script"
                   << "\nto generate the required certificates in '" << kTestX509CertChainDir << "'.";
        }

        // Create proper certificate chain with root CA and leaf certificate
        X509CertChain out_cert_chain;
        error = X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, m_root_cert_pem_str, out_cert_chain);
        ASSERT_EQ(error, Error::Ok) << "X509CertChain::create failed. SDK error: " << to_string(error);
        
        error = out_cert_chain.push_back(m_leaf_cert_pem_str);
        ASSERT_EQ(error, Error::Ok) << "push_back failed for leaf cert: " << to_string(error);
        
        m_cert_chain = std::move(out_cert_chain);

        ASSERT_EQ(m_cert_chain.size(), 1) << "Certificate chain size should be 1 after push_back.";

        std::string data_str = "This is some sample data to sign for testing.";
        m_data_to_sign.assign(data_str.begin(), data_str.end());

        m_valid_signature = sign_data_with_key_str(m_data_to_sign, m_leaf_key_pem_str, m_hash_algo);
        ASSERT_FALSE(m_valid_signature.empty()) << "Failed to sign data for test setup. Check OpenSSL errors if any reported by sign_data_with_key_str.";
    }

    void TearDown() override {
        ErrorStack::clear();
    }
};

// Define static const paths
/**
 * Test certificates are now generated using the FWID test certificate script:
 * unit-tests/testdata/generate_test_certs.sh
 * 
 * This creates a proper CA hierarchy with:
 * - Root CA certificate and key
 * - Leaf certificate with FWID extension and corresponding private key
 * - Leaf certificate without FWID extension (using same private key)
 */
const std::string X509CertChainSignatureTest::kTestX509CertChainDir = "testdata/x509_cert_chain/";
const std::string X509CertChainSignatureTest::kTestRootCertPath = X509CertChainSignatureTest::kTestX509CertChainDir + "root_cert";
const std::string X509CertChainSignatureTest::kTestLeafCertPath = X509CertChainSignatureTest::kTestX509CertChainDir + "leaf_cert_with_fwid";
const std::string X509CertChainSignatureTest::kTestLeafKeyPath = X509CertChainSignatureTest::kTestX509CertChainDir + "leaf_key";


TEST_F(X509CertChainSignatureTest, ValidSignature) {
    ErrorStack::clear();
    Error error = m_cert_chain.verify_signature(m_data_to_sign, m_valid_signature, m_hash_algo);
    EXPECT_EQ(error, Error::Ok) << "Signature verification failed for a valid signature.";
}

TEST_F(X509CertChainSignatureTest, InvalidSignatureTamperedData) {
    ErrorStack::clear();
    std::vector<uint8_t> tampered_data = m_data_to_sign;
    ASSERT_FALSE(tampered_data.empty()) << "Original data to sign is empty, cannot tamper.";
    tampered_data[0]++; // Modify the first byte

    Error error = m_cert_chain.verify_signature(tampered_data, m_valid_signature, m_hash_algo);
    EXPECT_EQ(error, Error::InternalError) << "Signature verification succeeded for tampered data.";
}

TEST_F(X509CertChainSignatureTest, InvalidSignatureIncorrectSignature) {
    ErrorStack::clear();
    std::vector<uint8_t> incorrect_signature = m_valid_signature;
    ASSERT_FALSE(incorrect_signature.empty()) << "Original valid signature is empty, cannot make incorrect.";
    incorrect_signature[0]++; // Modify the first byte of the signature

    Error error = m_cert_chain.verify_signature(m_data_to_sign, incorrect_signature, m_hash_algo);
    EXPECT_EQ(error, Error::InternalError) << "Signature verification succeeded for an incorrect signature.";
}

TEST_F(X509CertChainSignatureTest, NullHashAlgorithm) {
    ErrorStack::clear();
    Error error = m_cert_chain.verify_signature(m_data_to_sign, m_valid_signature, nullptr);
    EXPECT_EQ(error, Error::InternalError) << "Expected InternalError for null hash algorithm, but got: " << to_string(error);
}


class X509CertChainFwidTest : public ::testing::Test {
protected:
    std::string m_root_cert_pem_str;
    std::string m_leaf_cert_with_fwid_pem_str;
    std::string m_leaf_cert_without_fwid_pem_str;
    
    std::vector<uint8_t> m_expected_fwid_bytes;

    // Paths to test data files generated by the script.
    static const std::string kTestX509CertChainDir;
    static const std::string kTestFwidRootCertPath;
    static const std::string kTestFwidLeafCertWithFwidPath;
    static const std::string kTestFwidLeafCertWithoutFwidPath;


    void SetUp() override {
        ErrorStack::clear(); // Clear any previous SDK errors

        // Define expected FWID - generate 48 bytes sequentially
        m_expected_fwid_bytes.clear();
        m_expected_fwid_bytes.reserve(48);
        for (uint8_t i = 1; i <= 48; ++i) {
            m_expected_fwid_bytes.push_back(i);
        }

        Error error = readFileIntoString(kTestFwidRootCertPath, m_root_cert_pem_str);
        if (error != Error::Ok) {
            FAIL() << "Failed to read root certificate file: " << kTestFwidRootCertPath
                   << "\nPlease ensure you have run the 'unit-tests/testdata/generate_test_certs.sh' script"
                   << "\nto generate the required certificates in '" << kTestX509CertChainDir << "'.";
        }

        error = readFileIntoString(kTestFwidLeafCertWithFwidPath, m_leaf_cert_with_fwid_pem_str);
        if (error != Error::Ok) {
            FAIL() << "Failed to read leaf certificate with FWID file: " << kTestFwidLeafCertWithFwidPath
                   << "\nPlease ensure you have run the 'unit-tests/testdata/generate_test_certs.sh' script"
                   << "\nto generate the required certificates in '" << kTestX509CertChainDir << "'.";
        }

        error = readFileIntoString(kTestFwidLeafCertWithoutFwidPath, m_leaf_cert_without_fwid_pem_str);
        if (error != Error::Ok) {
            FAIL() << "Failed to read leaf certificate without FWID file: " << kTestFwidLeafCertWithoutFwidPath
                   << "\nPlease ensure you have run the 'unit-tests/testdata/generate_test_certs.sh' script"
                   << "\nto generate the required certificates in '" << kTestX509CertChainDir << "'.";
        }

        ASSERT_FALSE(m_root_cert_pem_str.empty()) << "Root certificate PEM is empty. File: " << kTestFwidRootCertPath;
        ASSERT_FALSE(m_leaf_cert_with_fwid_pem_str.empty()) << "Leaf certificate with FWID PEM is empty. File: " << kTestFwidLeafCertWithFwidPath;
        ASSERT_FALSE(m_leaf_cert_without_fwid_pem_str.empty()) << "Leaf certificate without FWID PEM is empty. File: " << kTestFwidLeafCertWithoutFwidPath;
    }

    void TearDown() override {
        ErrorStack::clear();
    }
};

// Define static const paths for FWID test certificates
const std::string X509CertChainFwidTest::kTestX509CertChainDir = "testdata/x509_cert_chain/";
const std::string X509CertChainFwidTest::kTestFwidRootCertPath = X509CertChainFwidTest::kTestX509CertChainDir + "root_cert";
const std::string X509CertChainFwidTest::kTestFwidLeafCertWithFwidPath = X509CertChainFwidTest::kTestX509CertChainDir + "leaf_cert_with_fwid";
const std::string X509CertChainFwidTest::kTestFwidLeafCertWithoutFwidPath = X509CertChainFwidTest::kTestX509CertChainDir + "leaf_cert_without_fwid";


TEST_F(X509CertChainFwidTest, FwidNotFoundInCert) {
    ErrorStack::clear();
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
    ErrorStack::clear();
    X509CertChain cert_chain_obj;
    Error error = X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, m_root_cert_pem_str, cert_chain_obj);
    ASSERT_EQ(error, Error::Ok) << "X509CertChain::create failed: " << to_string(error);

    error = cert_chain_obj.push_back(m_leaf_cert_with_fwid_pem_str);
    ASSERT_EQ(error, Error::Ok) << "push_back failed: " << to_string(error);
    ASSERT_EQ(cert_chain_obj.size(), 1);

    std::vector<uint8_t> out_fwid;
    error = cert_chain_obj.get_fwid(1, X509CertChain::FWIDType::FWID_2_23_133_5_4_1, out_fwid); // Index 1 is out of bounds
    EXPECT_EQ(error, Error::CertNotFound) << "get_fwid should return CertNotFound for out-of-bounds index, but returned: " << to_string(error);
}

TEST_F(X509CertChainFwidTest, IndexOutOfBoundsEmptyChain) {
    ErrorStack::clear();
    X509CertChain cert_chain_obj;
    // Create with a root cert, but don't push any certs to the chain itself (m_certs remains empty)
    Error error = X509CertChain::create(CertificateChainType::GPU_DEVICE_IDENTITY, m_root_cert_pem_str, cert_chain_obj);
    ASSERT_EQ(error, Error::Ok) << "X509CertChain::create failed: " << to_string(error);
    
    ASSERT_EQ(cert_chain_obj.size(), 0) << "Certificate chain should be empty.";

    std::vector<uint8_t> out_fwid;
    error = cert_chain_obj.get_fwid(0, X509CertChain::FWIDType::FWID_2_23_133_5_4_1, out_fwid);
    EXPECT_EQ(error, Error::CertNotFound) << "get_fwid should return CertNotFound for empty chain, but returned: " << to_string(error);
}