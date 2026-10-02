/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#include <cstdint>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "nv_attestation/cmw.h"
#include "nv_attestation/corim_evidence/evidence_handler.h"
#include "nv_attestation/corim_evidence/evidence_handler_settings.h"
#include "nv_attestation/cose.h"
#include "nv_attestation/error.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/utils.h"

namespace nvattestation {
namespace {

std::vector<uint8_t> read_coev_fixture_bytes(const std::string &name) {
    std::string path = "testdata/sample_rims/coev/" + name + ".cbor";
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        ADD_FAILURE() << "Failed to open fixture: " << path;
        return {};
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
}

CmwEvidenceItem spdm_item(std::vector<uint8_t> transcript,
                          bool with_cert = true) {
    CmwEvidenceItem item;
    item.evidence = CmwRecord(kCmwMediaSpdmTranscript, std::move(transcript));
    if (with_cert) {
        item.certificate = std::unique_ptr<CmwRecord>(
            new CmwRecord(kCmwMediaPemCertChain, {0x01, 0x02}));
    }
    return item;
}

std::vector<uint8_t> load_eat_fixture(const std::string &name) {
    const std::string path = "testdata/sample_rims/eat/" + name + ".cbor";
    std::ifstream s(path, std::ios::binary);
    if (!s) {
        ADD_FAILURE() << "missing fixture: " << path;
        return {};
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(s)),
                                std::istreambuf_iterator<char>());
}

std::string read_text_file(const std::string &path) {
    std::ifstream in(path);
    if (!in) {
        ADD_FAILURE() << "missing file: " << path;
        return {};
    }
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

CmwEvidenceItem eat_item(std::vector<uint8_t> payload,
                         std::vector<uint8_t> nonce = {}) {
    CmwEvidenceItem item;
    item.evidence = CmwRecord(kCmwMediaEatCwt, std::move(payload));
    item.nonce = std::move(nonce);
    return item;
}

X509CertChain anchor_eat_chain(const std::vector<uint8_t> &chain_pem) {
    X509CertChain chain;
    const std::string root_pem =
        read_text_file("testdata/x509_cert_chain/cose_signing_root.crt");
    const std::string chain_str(chain_pem.begin(), chain_pem.end());
    if (X509CertChain::create_from_cert_chain_str(
            CertificateChainType::GENERIC, root_pem, chain_str, chain) !=
        Error::Ok) {
        ADD_FAILURE() << "failed to build EAT test chain";
        return chain;
    }
    if (chain.verify() != Error::Ok) {
        ADD_FAILURE() << "failed to anchor EAT test chain";
    }
    return chain;
}

TEST(EvidenceHandlerRegistry, FindsSpdmHandler) {
    const IEvidenceHandler *handler =
        find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);
    EXPECT_TRUE(handler->accepts_media_type(kCmwMediaSpdmTranscript));
}

TEST(EvidenceHandlerRegistry, UnknownMediaTypeReturnsNull) {
    EXPECT_EQ(find_evidence_handler("application/vnd.nvidia.not-real"),
              nullptr);
}

TEST(EvidenceHandlerRegistry, IsSupportedReflectsRegistry) {
    EXPECT_TRUE(is_evidence_media_type_supported(kCmwMediaSpdmTranscript));
    EXPECT_FALSE(is_evidence_media_type_supported("application/octet-stream"));
}

TEST(SpdmHandler, ExtractCertChainSourcesCompanion) {
    const IEvidenceHandler *handler =
        find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = spdm_item({0xAA, 0xBB});
    EvidenceHandlerSettings settings;
    std::vector<uint8_t> pem;
    ASSERT_EQ(handler->extract_cert_chain(item, settings, pem), Error::Ok);
    EXPECT_EQ(pem, (std::vector<uint8_t>{0x01, 0x02}));
}

TEST(SpdmHandler, ExtractCertChainRejectsMissingCompanion) {
    const IEvidenceHandler *handler =
        find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = spdm_item({0xAA}, /*with_cert=*/false);
    EvidenceHandlerSettings settings;
    std::vector<uint8_t> pem;
    EXPECT_EQ(handler->extract_cert_chain(item, settings, pem), Error::BadArgument);
}

TEST(SpdmHandler, ExtractCertChainRejectsWrongCompanionMediaType) {
    const IEvidenceHandler *handler =
        find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = spdm_item({0xAA});
    item.certificate->media_type = kCmwMediaJson;
    EvidenceHandlerSettings settings;
    std::vector<uint8_t> pem;
    EXPECT_EQ(handler->extract_cert_chain(item, settings, pem), Error::BadArgument);
}

TEST(SpdmHandler, ExtractCertChainToleratesMissingCompanionWhenDisabled) {
    const IEvidenceHandler *handler =
        find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = spdm_item({0xAA}, /*with_cert=*/false);
    EvidenceHandlerSettings settings;
    settings.m_verify_evidence_signature = false;
    std::vector<uint8_t> pem;
    EXPECT_EQ(handler->extract_cert_chain(item, settings, pem), Error::Ok);
    EXPECT_TRUE(pem.empty());
}

TEST(SpdmHandler, ExtractCertChainToleratesWrongCompanionMediaTypeWhenDisabled) {
    const IEvidenceHandler *handler =
        find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = spdm_item({0xAA});
    item.certificate->media_type = kCmwMediaJson;
    EvidenceHandlerSettings settings;
    settings.m_verify_evidence_signature = false;
    std::vector<uint8_t> pem;
    EXPECT_EQ(handler->extract_cert_chain(item, settings, pem), Error::Ok);
    EXPECT_TRUE(pem.empty());
}

TEST(SpdmHandler, ExtractCertChainIgnoresSettings) {
    const IEvidenceHandler *handler =
        find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = spdm_item({0xAA, 0xBB});
    EvidenceHandlerSettings settings;
    settings.m_verify_evidence_signature = false;
    std::vector<uint8_t> pem;
    ASSERT_EQ(handler->extract_cert_chain(item, settings, pem), Error::Ok);
    EXPECT_EQ(pem, (std::vector<uint8_t>{0x01, 0x02}));
}

TEST(SpdmHandler, VerifyAndExtractRejectsShortTranscript) {
    const IEvidenceHandler *handler =
        find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = spdm_item(std::vector<uint8_t>(8, 0));
    X509CertChain chain;
    EvidenceHandlerSettings settings;
    EvidenceVerification verification;
    EXPECT_EQ(handler->verify_and_extract_ects(item, chain, settings, verification),
              Error::EvidenceMalformed);
    EXPECT_FALSE(verification.signature_checked);
    EXPECT_FALSE(verification.signature_valid);
    EXPECT_FALSE(verification.nonce_matches);
    EXPECT_TRUE(verification.ects.empty());
}

TEST(SpdmHandler, ExposesDeviceIdentifierMeasurementAndRecords) {
    const IEvidenceHandler *handler =
        find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);

    // Real captured Hopper SPDM transcript with block index 52 present.
    std::string report_hex;
    std::ifstream report_file("testdata/hopperAttestationReport.txt");
    ASSERT_TRUE(report_file.is_open());
    std::getline(report_file, report_hex);
    ASSERT_FALSE(report_hex.empty());
    std::vector<uint8_t> transcript = hex_string_to_bytes(report_hex);

    std::string cert_chain_pem;
    ASSERT_EQ(readFileIntoString("testdata/hopperCertChain.txt", cert_chain_pem),
              Error::Ok);
    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GENERIC, cert_chain_pem,
                  cert_chain_pem, chain),
              Error::Ok);

    CmwEvidenceItem item = spdm_item(transcript, /*with_cert=*/false);
    EvidenceHandlerSettings settings;
    EvidenceVerification out;
    Error err = handler->verify_and_extract_ects(item, chain, settings, out);

    ASSERT_EQ(err, Error::Ok);
    EXPECT_TRUE(out.signature_valid);
    // Hopper doesn't populate this slot; the real capture is 48 zero bytes.
    EXPECT_EQ(out.device_identifier_measurement, std::vector<uint8_t>(48, 0));
    ASSERT_NE(out.measurement_records, nullptr);
    EXPECT_GT(out.measurement_hash_algorithm_id, 0);
}

TEST(SpdmHandler, ExposesRealBlackwellFspDeviceIdentifierMeasurement) {
    const IEvidenceHandler *handler =
        find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);

    // Real captured GB100 FSP-responder SPDM transcript; block 52 carries
    // the device identifier (contains the ASCII "APSKU" marker).
    std::string report_hex;
    std::ifstream report_file(
        "testdata/sample_attestation_data/gpu/blackwellFspAttestationReport.txt");
    ASSERT_TRUE(report_file.is_open());
    std::getline(report_file, report_hex);
    ASSERT_FALSE(report_hex.empty());
    std::vector<uint8_t> transcript = hex_string_to_bytes(report_hex);

    std::string cert_chain_pem;
    ASSERT_EQ(readFileIntoString(
                  "testdata/sample_attestation_data/gpu/blackwellFspCertChain.txt",
                  cert_chain_pem),
              Error::Ok);
    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GENERIC, cert_chain_pem,
                  cert_chain_pem, chain),
              Error::Ok);

    CmwEvidenceItem item = spdm_item(transcript, /*with_cert=*/false);
    EvidenceHandlerSettings settings;
    EvidenceVerification out;
    Error err = handler->verify_and_extract_ects(item, chain, settings, out);

    ASSERT_EQ(err, Error::Ok);
    EXPECT_TRUE(out.signature_valid);
    EXPECT_EQ(out.device_identifier_measurement,
              hex_string_to_bytes(
                  "0043000000070100040047160000020010007865bed953204b6ab94d"
                  "8fa70b6283d6ffff0b0001054150534b555c06000000000200de1000"
                  "010200412901010200de10020102004620"));
    ASSERT_NE(out.measurement_records, nullptr);
    EXPECT_GT(out.measurement_hash_algorithm_id, 0);
}

// The Blackwell FSP transcript embeds no CoEV of its own (0 SPDM TOC matches
// among its measurement blocks), so verify_and_extract_ects() falls back to
// EvidenceHandlerSettings::m_backup_coev. Covers the backup_toc branch's
// profile extraction (evidence_handler.cpp's #6.570 SpdmToc arm).
TEST(SpdmHandler, BackupSpdmTocProfilePopulatesEvidenceProfile) {
    const IEvidenceHandler *handler =
        find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);

    std::string report_hex;
    std::ifstream report_file(
        "testdata/sample_attestation_data/gpu/blackwellFspAttestationReport.txt");
    ASSERT_TRUE(report_file.is_open());
    std::getline(report_file, report_hex);
    ASSERT_FALSE(report_hex.empty());
    std::vector<uint8_t> transcript = hex_string_to_bytes(report_hex);

    std::string cert_chain_pem;
    ASSERT_EQ(readFileIntoString(
                  "testdata/sample_attestation_data/gpu/blackwellFspCertChain.txt",
                  cert_chain_pem),
              Error::Ok);
    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GENERIC, cert_chain_pem,
                  cert_chain_pem, chain),
              Error::Ok);

    CmwEvidenceItem item = spdm_item(transcript, /*with_cert=*/false);
    EvidenceHandlerSettings settings;
    settings.m_backup_coev = read_coev_fixture_bytes("blackwell_fsp_with_profile");
    ASSERT_FALSE(settings.m_backup_coev.empty());

    EvidenceVerification out;
    Error err = handler->verify_and_extract_ects(item, chain, settings, out);

    ASSERT_EQ(err, Error::Ok);
    EXPECT_TRUE(out.used_backup_coev);
    ASSERT_TRUE(out.evidence_profile != nullptr)
        << "expected the backup #6.570 SpdmToc's profile to populate evidence_profile";
    EXPECT_EQ(out.evidence_profile->kind, ProfileKind::Uri);
    EXPECT_EQ(out.evidence_profile->value,
              "tag:nvidia.com,2026:evidence/profiles/spdm/gpu/blackwell-fsp/1.0.0");
}

// Same fallback, but with a standalone (non-SpdmToc-wrapped) #6.571
// ConciseEvidence backup. Covers evidence_handler.cpp's backup_ce arm.
TEST(SpdmHandler, BackupConciseEvidenceProfilePopulatesEvidenceProfile) {
    const IEvidenceHandler *handler =
        find_evidence_handler(kCmwMediaSpdmTranscript);
    ASSERT_NE(handler, nullptr);

    std::string report_hex;
    std::ifstream report_file(
        "testdata/sample_attestation_data/gpu/blackwellFspAttestationReport.txt");
    ASSERT_TRUE(report_file.is_open());
    std::getline(report_file, report_hex);
    ASSERT_FALSE(report_hex.empty());
    std::vector<uint8_t> transcript = hex_string_to_bytes(report_hex);

    std::string cert_chain_pem;
    ASSERT_EQ(readFileIntoString(
                  "testdata/sample_attestation_data/gpu/blackwellFspCertChain.txt",
                  cert_chain_pem),
              Error::Ok);
    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GENERIC, cert_chain_pem,
                  cert_chain_pem, chain),
              Error::Ok);

    CmwEvidenceItem item = spdm_item(transcript, /*with_cert=*/false);
    EvidenceHandlerSettings settings;
    settings.m_backup_coev = read_coev_fixture_bytes("minimal_with_profile");
    ASSERT_FALSE(settings.m_backup_coev.empty());

    EvidenceVerification out;
    Error err = handler->verify_and_extract_ects(item, chain, settings, out);

    ASSERT_EQ(err, Error::Ok);
    EXPECT_TRUE(out.used_backup_coev);
    ASSERT_TRUE(out.evidence_profile != nullptr)
        << "expected the backup #6.571 ConciseEvidence's profile to populate "
           "evidence_profile";
    EXPECT_EQ(out.evidence_profile->kind, ProfileKind::Uri);
    EXPECT_EQ(out.evidence_profile->value,
              "tag:nvidia.com,2026:evidence/profiles/coev/backup-ce/1.0.0");
}

TEST(EvidenceHandlerRegistry, FindsEatHandler) {
    const IEvidenceHandler *handler = find_evidence_handler(kCmwMediaEatCwt);
    ASSERT_NE(handler, nullptr);
    EXPECT_TRUE(handler->accepts_media_type(kCmwMediaEatCwt));
}

TEST(CoseSign1, AcceptsUnprotectedX5chainWithoutThumbprint) {
    CoseSign1Components components;
    components.x5chain.push_back({0x01, 0x02, 0x03});

    EXPECT_EQ(validate_cose_sign1_x5chain(components), Error::Ok);
}

TEST(EatHandler, ExtractCertChainSignedModeReadsX5chain) {
    const IEvidenceHandler *handler = find_evidence_handler(kCmwMediaEatCwt);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = eat_item(load_eat_fixture("full_signed"));
    ASSERT_FALSE(item.evidence.value.empty());
    EvidenceHandlerSettings settings;
    std::vector<uint8_t> pem;
    ASSERT_EQ(handler->extract_cert_chain(item, settings, pem), Error::Ok);
    EXPECT_FALSE(pem.empty());
}

TEST(EatHandler, ExtractCertChainUnsignedModeYieldsNoChain) {
    const IEvidenceHandler *handler = find_evidence_handler(kCmwMediaEatCwt);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = eat_item(load_eat_fixture("full"));
    ASSERT_FALSE(item.evidence.value.empty());
    EvidenceHandlerSettings settings;
    settings.m_verify_evidence_signature = false;
    std::vector<uint8_t> pem;
    EXPECT_EQ(handler->extract_cert_chain(item, settings, pem), Error::Ok);
    EXPECT_TRUE(pem.empty());
}

TEST(EatHandler, VerifyAndExtractSignedHappyPath) {
    const IEvidenceHandler *handler = find_evidence_handler(kCmwMediaEatCwt);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = eat_item(load_eat_fixture("full_signed"));
    ASSERT_FALSE(item.evidence.value.empty());
    EvidenceHandlerSettings settings;
    std::vector<uint8_t> pem;
    ASSERT_EQ(handler->extract_cert_chain(item, settings, pem), Error::Ok);
    X509CertChain chain = anchor_eat_chain(pem);

    EvidenceVerification verification;
    ASSERT_EQ(handler->verify_and_extract_ects(item, chain, settings, verification),
              Error::Ok);
    EXPECT_TRUE(verification.signature_checked);
    EXPECT_TRUE(verification.parsed);
    EXPECT_TRUE(verification.signature_valid);
    EXPECT_FALSE(verification.ects.empty());
}

TEST(EatHandler, VerifyAndExtractNonceMatchSetsNonceMatches) {
    const IEvidenceHandler *handler = find_evidence_handler(kCmwMediaEatCwt);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = eat_item(load_eat_fixture("full_signed"));
    ASSERT_FALSE(item.evidence.value.empty());
    EvidenceHandlerSettings settings;
    std::vector<uint8_t> pem;
    ASSERT_EQ(handler->extract_cert_chain(item, settings, pem), Error::Ok);
    X509CertChain chain = anchor_eat_chain(pem);

    // Discover the fixture's real nonce first (item.nonce left unset above).
    EvidenceVerification baseline;
    ASSERT_EQ(handler->verify_and_extract_ects(item, chain, settings, baseline),
              Error::Ok);
    ASSERT_FALSE(baseline.eat_nonce.empty());

    CmwEvidenceItem matching_item =
        eat_item(load_eat_fixture("full_signed"), baseline.eat_nonce);
    EvidenceVerification verification;
    ASSERT_EQ(handler->verify_and_extract_ects(matching_item, chain, settings,
                                               verification),
              Error::Ok);
    EXPECT_TRUE(verification.nonce_matches);
    EXPECT_EQ(verification.eat_nonce, baseline.eat_nonce);
}

TEST(EatHandler, VerifyAndExtractNonceMismatchLeavesNonceMatchesFalse) {
    const IEvidenceHandler *handler = find_evidence_handler(kCmwMediaEatCwt);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item =
        eat_item(load_eat_fixture("full_signed"), {0xDE, 0xAD, 0xBE, 0xEF});
    ASSERT_FALSE(item.evidence.value.empty());
    EvidenceHandlerSettings settings;
    std::vector<uint8_t> pem;
    ASSERT_EQ(handler->extract_cert_chain(item, settings, pem), Error::Ok);
    X509CertChain chain = anchor_eat_chain(pem);

    EvidenceVerification verification;
    ASSERT_EQ(handler->verify_and_extract_ects(item, chain, settings, verification),
              Error::Ok);
    EXPECT_FALSE(verification.nonce_matches);
    EXPECT_FALSE(verification.eat_nonce.empty());
}

TEST(EatHandler, VerifyAndExtractSignedModeRejectsBadSignature) {
    const IEvidenceHandler *handler = find_evidence_handler(kCmwMediaEatCwt);
    ASSERT_NE(handler, nullptr);
    std::vector<uint8_t> tampered = load_eat_fixture("full_signed");
    ASSERT_FALSE(tampered.empty());
    tampered.back() ^= 0xFF;
    CmwEvidenceItem item = eat_item(tampered);
    EvidenceHandlerSettings settings;
    std::vector<uint8_t> pem;
    ASSERT_EQ(handler->extract_cert_chain(item, settings, pem), Error::Ok);
    X509CertChain chain = anchor_eat_chain(pem);

    EvidenceVerification verification;
    EXPECT_EQ(handler->verify_and_extract_ects(item, chain, settings, verification),
              Error::Ok);
    EXPECT_TRUE(verification.signature_checked);
    EXPECT_FALSE(verification.parsed);
    EXPECT_FALSE(verification.signature_valid);
    EXPECT_TRUE(verification.ects.empty());
}

TEST(EatHandler, VerifyAndExtractUnsignedHappyPath) {
    const IEvidenceHandler *handler = find_evidence_handler(kCmwMediaEatCwt);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = eat_item(load_eat_fixture("full"));
    ASSERT_FALSE(item.evidence.value.empty());
    EvidenceHandlerSettings settings;
    settings.m_verify_evidence_signature = false;

    X509CertChain chain;
    EvidenceVerification verification;
    ASSERT_EQ(handler->verify_and_extract_ects(item, chain, settings, verification),
              Error::Ok);
    EXPECT_FALSE(verification.signature_checked);
    EXPECT_TRUE(verification.parsed);
    EXPECT_FALSE(verification.signature_valid);
    EXPECT_FALSE(verification.ects.empty());
}

TEST(EatHandler, VerifyAndExtractToleratesBadSignatureWhenDisabled) {
    const IEvidenceHandler *handler = find_evidence_handler(kCmwMediaEatCwt);
    ASSERT_NE(handler, nullptr);
    std::vector<uint8_t> tampered = load_eat_fixture("full_signed");
    ASSERT_FALSE(tampered.empty());
    tampered.back() ^= 0xFF;
    CmwEvidenceItem item = eat_item(tampered);
    EvidenceHandlerSettings settings;
    settings.m_verify_evidence_signature = false;
    std::vector<uint8_t> pem;
    ASSERT_EQ(handler->extract_cert_chain(item, settings, pem), Error::Ok);
    EXPECT_FALSE(pem.empty());
    X509CertChain chain = anchor_eat_chain(pem);

    EvidenceVerification verification;
    ASSERT_EQ(handler->verify_and_extract_ects(item, chain, settings, verification),
              Error::Ok);
    EXPECT_TRUE(verification.signature_checked);
    EXPECT_TRUE(verification.parsed);
    EXPECT_FALSE(verification.signature_valid);
    EXPECT_FALSE(verification.ects.empty());
}

TEST(EatHandler, ExtractCertChainToleratesBareClaimsWhenDisabled) {
    const IEvidenceHandler *handler = find_evidence_handler(kCmwMediaEatCwt);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = eat_item(load_eat_fixture("full"));
    EvidenceHandlerSettings settings;
    settings.m_verify_evidence_signature = false;
    std::vector<uint8_t> pem;
    EXPECT_EQ(handler->extract_cert_chain(item, settings, pem), Error::Ok);
    EXPECT_TRUE(pem.empty());
}

TEST(EatHandler, VerifyAndExtractRejectsMalformedPayload) {
    const IEvidenceHandler *handler = find_evidence_handler(kCmwMediaEatCwt);
    ASSERT_NE(handler, nullptr);
    CmwEvidenceItem item = eat_item({0x00, 0x01, 0x02});
    EvidenceHandlerSettings settings;
    X509CertChain chain;
    EvidenceVerification verification;
    EXPECT_NE(handler->verify_and_extract_ects(item, chain, settings, verification),
              Error::Ok);
}

} // namespace
} // namespace nvattestation
