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

#include "gtest/gtest.h"

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "nv_attestation/dice_tcb_info.h"
#include "nv_attestation/error.h"
#include "nv_attestation/utils.h"

using namespace nvattestation;

// --- FWID Tests ---

TEST(FWIDTest, ConstructionAndGetters) {
    std::string oid = "2.16.840.1.101.3.4.2.2";  // sha384
    std::vector<uint8_t> digest = {0xd0, 0x90, 0xca, 0xb1};
    FWID fwid(oid, digest);

    EXPECT_EQ(fwid.hash_alg_oid(), oid);
    EXPECT_EQ(fwid.digest(), digest);
}

TEST(FWIDTest, DefaultConstruction) {
    FWID fwid;
    EXPECT_TRUE(fwid.hash_alg_oid().empty());
    EXPECT_TRUE(fwid.digest().empty());
}

TEST(FWIDTest, Equality) {
    std::string oid = "2.16.840.1.101.3.4.2.2";
    std::vector<uint8_t> digest1 = {0xaa, 0xbb};
    std::vector<uint8_t> digest2 = {0xcc, 0xdd};

    FWID a(oid, digest1);
    FWID b(oid, digest1);
    FWID c(oid, digest2);

    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

// --- DiceTcbInfo Construction Tests ---

TEST(DiceTcbInfoTest, DefaultConstruction) {
    DiceTcbInfo info;
    EXPECT_FALSE(info.has_vendor());
    EXPECT_FALSE(info.has_model());
    EXPECT_FALSE(info.has_version());
    EXPECT_FALSE(info.has_svn());
    EXPECT_FALSE(info.has_layer());
    EXPECT_FALSE(info.has_index());
    EXPECT_FALSE(info.has_fwids());
    EXPECT_FALSE(info.has_flags());
    EXPECT_FALSE(info.has_flags_mask());
    EXPECT_FALSE(info.has_integrity_registers());
    EXPECT_FALSE(info.has_vendor_info());
    EXPECT_FALSE(info.has_type());
}

TEST(DiceTcbInfoTest, SetAndGetAllFields) {
    DiceTcbInfo info;
    info.set_vendor("NVIDIA");
    info.set_model("GB100 A01 GSP");
    info.set_version("01");
    info.set_svn(1);
    info.set_layer(0);
    info.set_index(0);

    std::vector<FWID> fwids;
    fwids.emplace_back("2.16.840.1.101.3.4.2.2", std::vector<uint8_t>(48, 0xAA));
    info.set_fwids(fwids);

    info.set_flags(0x800001);
    info.set_flags_mask(0xFF);
    info.set_vendor_info({0xc0});
    info.set_type({0x00});

    EXPECT_TRUE(info.has_vendor());
    EXPECT_EQ(info.vendor(), "NVIDIA");
    EXPECT_TRUE(info.has_model());
    EXPECT_EQ(info.model(), "GB100 A01 GSP");
    EXPECT_TRUE(info.has_version());
    EXPECT_EQ(info.version(), "01");
    EXPECT_TRUE(info.has_svn());
    EXPECT_EQ(info.svn(), 1);
    EXPECT_TRUE(info.has_layer());
    EXPECT_EQ(info.layer(), 0);
    EXPECT_TRUE(info.has_index());
    EXPECT_EQ(info.index(), 0);
    EXPECT_TRUE(info.has_fwids());
    EXPECT_EQ(info.fwids().size(), 1u);
    EXPECT_TRUE(info.has_flags());
    EXPECT_EQ(info.flags(), 0x800001u);
    EXPECT_TRUE(info.has_flags_mask());
    EXPECT_EQ(info.flags_mask(), 0xFFu);
    EXPECT_TRUE(info.has_vendor_info());
    EXPECT_EQ(info.vendor_info(), std::vector<uint8_t>({0xc0}));
    EXPECT_TRUE(info.has_type());
    EXPECT_EQ(info.type(), std::vector<uint8_t>({0x00}));
}

TEST(DiceTcbInfoTest, GetFirstFwidDigest) {
    DiceTcbInfo info;

    // No FWIDs -> error
    std::vector<uint8_t> digest;
    EXPECT_NE(info.get_first_fwid_digest(digest), Error::Ok);

    // With FWID -> success
    std::vector<uint8_t> expected = {0x01, 0x02, 0x03};
    std::vector<FWID> fwids;
    fwids.emplace_back("2.16.840.1.101.3.4.2.2", expected);
    fwids.emplace_back("2.16.840.1.101.3.4.2.2", std::vector<uint8_t>{0xFF});
    info.set_fwids(fwids);

    EXPECT_EQ(info.get_first_fwid_digest(digest), Error::Ok);
    EXPECT_EQ(digest, expected);
}

// --- DiceTcbInfo DER Parsing Tests ---

TEST(DiceTcbInfoTest, ParseFromDerBlackwell) {
    // Known-good hex from nv_x509.cpp:715 comment — a real Blackwell DiceTcbInfo extension
    // NOLINTBEGIN(readability-identifier-length)
    std::string hex_blob = "3081b180064e5649444941810d47423130302041303120475350820230318301018401008501";
    hex_blob += "00a67e303d06096086480165030402020430d090cab1b6e6ffddca83d1781e25b3f040fa1f";
    hex_blob += "3c7608230cb5f41b1c1b99f5f748349e59d0ef8eb830c9bc79ccf77502303d060960864801";
    hex_blob += "650304020204300000000000000000000000000000000000000000000000000000000000000";
    hex_blob += "00000000000000000000000000000000000870500800000018801c0890100";
    // NOLINTEND(readability-identifier-length)
    std::vector<uint8_t> der = hex_string_to_bytes(hex_blob);

    DiceTcbInfo info;
    Error err = DiceTcbInfo::parse_from_der(der, info);
    ASSERT_EQ(err, Error::Ok);

    ASSERT_TRUE(info.has_vendor());
    EXPECT_EQ(info.vendor(), "NVIDIA");

    ASSERT_TRUE(info.has_model());
    EXPECT_EQ(info.model(), "GB100 A01 GSP");

    ASSERT_TRUE(info.has_version());
    EXPECT_EQ(info.version(), "01");

    ASSERT_TRUE(info.has_svn());
    EXPECT_EQ(info.svn(), 1);

    ASSERT_TRUE(info.has_layer());
    EXPECT_EQ(info.layer(), 0);

    ASSERT_TRUE(info.has_index());
    EXPECT_EQ(info.index(), 0);

    ASSERT_TRUE(info.has_fwids());
    EXPECT_EQ(info.fwids().size(), 2u);

    // First FWID: sha384 with real digest
    EXPECT_EQ(info.fwids()[0].hash_alg_oid(), "2.16.840.1.101.3.4.2.2");
    EXPECT_EQ(info.fwids()[0].digest().size(), 48u);
    EXPECT_EQ(info.fwids()[0].digest()[0], 0xd0);
    EXPECT_EQ(info.fwids()[0].digest()[1], 0x90);

    // Second FWID: sha384 with all-zeros digest
    EXPECT_EQ(info.fwids()[1].hash_alg_oid(), "2.16.840.1.101.3.4.2.2");
    EXPECT_EQ(info.fwids()[1].digest().size(), 48u);
    EXPECT_EQ(info.fwids()[1].digest()[0], 0x00);

    ASSERT_TRUE(info.has_flags());
    // BIT STRING: 00 80 00 00 01 → unused_bits=0, value=0x80000001
    // Bit 0 (notConfigured) and bit 31 (fixedWidth) are set
    EXPECT_EQ(info.flags(), 0x80000001u);

    ASSERT_TRUE(info.has_vendor_info());
    EXPECT_EQ(info.vendor_info(), std::vector<uint8_t>({0xc0}));

    ASSERT_TRUE(info.has_type());
    EXPECT_EQ(info.type(), std::vector<uint8_t>({0x00}));

    // Backward compat: first FWID digest
    std::vector<uint8_t> first_digest;
    EXPECT_EQ(info.get_first_fwid_digest(first_digest), Error::Ok);
    EXPECT_EQ(first_digest.size(), 48u);
    EXPECT_EQ(first_digest[0], 0xd0);
}

// --- get_extension_der_bytes coverage (via parse_from_x509_extension with null cert) ---

TEST(DiceTcbInfoTest, ParseFromX509ExtensionNullCert) {
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_x509_extension(nullptr, OID_TCG_DICE_TCB_INFO, info), Error::Ok);
}

TEST(DiceTcbInfoTest, ParseFromX509ExtensionAliasNullCert) {
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_x509_extension(nullptr, OID_TCG_DICE_TCB_INFO_ALIAS, info), Error::Ok);
}

TEST(MultiDiceTcbInfoTest, ParseFromX509ExtensionNullCert) {
    MultiDiceTcbInfo info;
    EXPECT_NE(MultiDiceTcbInfo::parse_from_x509_extension(nullptr, info), Error::Ok);
}

// --- DiceTcbInfo Error Cases ---

TEST(DiceTcbInfoTest, ParseFromDerEmpty) {
    std::vector<uint8_t> empty;
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(empty, info), Error::Ok);
}

TEST(DiceTcbInfoTest, ParseFromDerTruncated) {
    // Just the SEQUENCE header, truncated
    std::vector<uint8_t> truncated = {0x30, 0x81, 0xb1, 0x80, 0x06};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(truncated, info), Error::Ok);
}

TEST(DiceTcbInfoTest, ParseFromDerNegativeSvn) {
    // Hand-crafted DER: DiceTcbInfo with svn = -1 (0xFF as a signed INTEGER byte)
    // [3] svn IMPLICIT INTEGER: tag=0x83, length=0x01, value=0xFF → -1
    // Outer SEQUENCE: 30 03 83 01 ff
    std::vector<uint8_t> der = {0x30, 0x03, 0x83, 0x01, 0xFF};

    DiceTcbInfo info;
    Error err = DiceTcbInfo::parse_from_der(der, info);
    ASSERT_EQ(err, Error::Ok);

    ASSERT_TRUE(info.has_svn());
    EXPECT_EQ(info.svn(), -1);
}

TEST(DiceTcbInfoTest, ParseFromDerOversizedInteger) {
    // Hand-crafted DER: DiceTcbInfo with svn encoded as 9 bytes (exceeds int64_t capacity)
    // [3] svn IMPLICIT INTEGER: tag=0x83, length=0x09, value=9 zero bytes
    // Outer SEQUENCE: 30 0b 83 09 00 00 00 00 00 00 00 00 00
    std::vector<uint8_t> der = {0x30, 0x0b, 0x83, 0x09,
                                0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00};

    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

TEST(DiceTcbInfoTest, ParseFromDerElementLengthOverrun) {
    // SEQUENCE { [0] length=5, only 3 bytes available } — triggers invalid element length check
    std::vector<uint8_t> der = {0x30, 0x05, 0x80, 0x05, 0x00, 0x00, 0x00};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

TEST(DiceTcbInfoTest, ParseFromDerWithFlagsMask) {
    // SEQUENCE { [10] IMPLICIT BIT STRING: 0x01 0x00 (1 unused bit, value=0) }
    // tag [10] = context-specific (0x80) | tag_number (0x0A) = 0x8A
    std::vector<uint8_t> der = {0x30, 0x04, 0x8A, 0x02, 0x01, 0x00};
    DiceTcbInfo info;
    EXPECT_EQ(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
    EXPECT_TRUE(info.has_flags_mask());
}

// --- DiceTcbInfo Silent-mode Error Cases (probe/fallback path, silent=true) ---
// These exercise the LogLevel::DEBUG branch of the err_lvl ternary in parse_from_der
// and verify that silent=true suppresses LOG_ERROR without changing the return code.

TEST(DiceTcbInfoTest, ParseFromDerEmptySilent) {
    std::vector<uint8_t> empty;
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(empty, info, /*silent=*/true), Error::Ok);
}

TEST(DiceTcbInfoTest, ParseFromDerTruncatedSilent) {
    std::vector<uint8_t> truncated = {0x30, 0x81, 0xb1, 0x80, 0x06};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(truncated, info, /*silent=*/true), Error::Ok);
}

TEST(DiceTcbInfoTest, ParseFromDerOversizedIntegerSilent) {
    std::vector<uint8_t> der = {0x30, 0x0b, 0x83, 0x09,
                                0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info, /*silent=*/true), Error::Ok);
}

TEST(DiceTcbInfoTest, RejectsCompositeDeviceIdDerSilent) {
    std::string hex = "3060060667810505040130560201003012300b06072a8648ce3d020105000303000401";
    hex += "303d06096086480165030402020430";
    hex += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(hex_string_to_bytes(hex), info, /*silent=*/true), Error::Ok);
}

// --- OID 2.23.133.5.4.1 Ambiguity Tests ---
// OID 2.23.133.5.4.1 may contain either a DiceTcbInfo (context-specific tags) or a
// CompositeDeviceID (universal tags). The parsers must reject each other's format so
// the fallback chain in X509CertChain::get_fwid works correctly.

TEST(DiceTcbInfoTest, RejectsCompositeDeviceIdDer) {
    // CompositeDeviceID DER: SEQUENCE { OID, SEQUENCE { INTEGER, SPKI, FWID } }
    // Contains only universal tags — DiceTcbInfo parser should reject it
    // (context_specific_tags_found == 0)
    std::string hex = "3060060667810505040130560201003012300b06072a8648ce3d020105000303000401";
    hex += "303d06096086480165030402020430";
    hex += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::vector<uint8_t> der = hex_string_to_bytes(hex);

    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

TEST(CompositeDeviceIdTest, RejectsDiceTcbInfoDer) {
    // DiceTcbInfo DER with vendor="NV" (context-specific tag [0])
    // CompositeDeviceId expects SEQUENCE { OID, SEQUENCE { INTEGER, ... } }
    // and should fail on this structure
    std::vector<uint8_t> der = {0x30, 0x04, 0x80, 0x02, 'N', 'V'};

    CompositeDeviceId cdi;
    EXPECT_NE(CompositeDeviceId::parse_from_der(der, cdi), Error::Ok);
}

// --- JSON Round-trip ---

TEST(DiceTcbInfoTest, JsonRoundTrip) {
    DiceTcbInfo original;
    original.set_vendor("NVIDIA");
    original.set_model("GB100");
    original.set_version("01");
    original.set_svn(42);
    original.set_layer(1);
    original.set_index(3);

    std::vector<FWID> fwids;
    fwids.emplace_back("2.16.840.1.101.3.4.2.2", std::vector<uint8_t>{0xAA, 0xBB, 0xCC});
    original.set_fwids(fwids);

    original.set_flags(0x01);
    original.set_flags_mask(0x03);
    original.set_vendor_info({0xDE, 0xAD});
    original.set_type({0xBE, 0xEF});

    nlohmann::json j = original;
    DiceTcbInfo restored = j.get<DiceTcbInfo>();

    EXPECT_EQ(original, restored);
    ASSERT_TRUE(restored.has_flags_mask());
    EXPECT_EQ(restored.flags_mask(), 0x03u);
}

TEST(DiceTcbInfoTest, JsonRoundTripPartialFields) {
    DiceTcbInfo original;
    original.set_vendor("NVIDIA");
    // Leave other fields unset

    nlohmann::json j = original;
    DiceTcbInfo restored = j.get<DiceTcbInfo>();

    EXPECT_EQ(original, restored);
    EXPECT_TRUE(restored.has_vendor());
    EXPECT_FALSE(restored.has_model());
    EXPECT_FALSE(restored.has_svn());
    EXPECT_FALSE(restored.has_fwids());
}

TEST(FWIDTest, JsonRoundTrip) {
    FWID original("2.16.840.1.101.3.4.2.2", {0x01, 0x02, 0x03, 0x04});

    nlohmann::json j = original;
    FWID restored = j.get<FWID>();

    EXPECT_EQ(original, restored);
}

// --- MultiDiceTcbInfo Tests ---

TEST(MultiDiceTcbInfoTest, ConstructAndAccess) {
    MultiDiceTcbInfo multi;
    EXPECT_TRUE(multi.entries().empty());

    DiceTcbInfo entry1;
    entry1.set_vendor("NVIDIA");
    multi.add_entry(entry1);

    DiceTcbInfo entry2;
    entry2.set_vendor("OTHER");
    multi.add_entry(entry2);

    EXPECT_EQ(multi.entries().size(), 2u);
    EXPECT_EQ(multi.entries()[0].vendor(), "NVIDIA");
    EXPECT_EQ(multi.entries()[1].vendor(), "OTHER");
}

TEST(MultiDiceTcbInfoTest, ParseFromDer) {
    // Wrap the known Blackwell DiceTcbInfo blob in an outer SEQUENCE to form MultiDiceTcbInfo
    // NOLINTBEGIN(readability-identifier-length)
    std::string inner_hex = "3081b180064e5649444941810d47423130302041303120475350820230318301018401008501";
    inner_hex += "00a67e303d06096086480165030402020430d090cab1b6e6ffddca83d1781e25b3f040fa1f";
    inner_hex += "3c7608230cb5f41b1c1b99f5f748349e59d0ef8eb830c9bc79ccf77502303d060960864801";
    inner_hex += "650304020204300000000000000000000000000000000000000000000000000000000000000";
    inner_hex += "00000000000000000000000000000000000870500800000018801c0890100";
    // NOLINTEND(readability-identifier-length)

    // Outer SEQUENCE: tag 0x30, length 180 (0x81 0xb4), then the inner DiceTcbInfo
    std::string multi_hex = "3081b4" + inner_hex;
    std::vector<uint8_t> der = hex_string_to_bytes(multi_hex);

    MultiDiceTcbInfo multi;
    Error err = MultiDiceTcbInfo::parse_from_der(der, multi);
    ASSERT_EQ(err, Error::Ok);

    ASSERT_EQ(multi.entries().size(), 1u);
    const DiceTcbInfo& entry = multi.entries()[0];

    ASSERT_TRUE(entry.has_vendor());
    EXPECT_EQ(entry.vendor(), "NVIDIA");

    ASSERT_TRUE(entry.has_model());
    EXPECT_EQ(entry.model(), "GB100 A01 GSP");

    ASSERT_TRUE(entry.has_fwids());
    EXPECT_EQ(entry.fwids().size(), 2u);
    EXPECT_EQ(entry.fwids()[0].hash_alg_oid(), "2.16.840.1.101.3.4.2.2");
    EXPECT_EQ(entry.fwids()[0].digest().size(), 48u);
}

TEST(MultiDiceTcbInfoTest, ParseFromDerMultipleEntries) {
    // Two DiceTcbInfo entries in an outer SEQUENCE:
    //   Entry 1: Blackwell blob (vendor="NVIDIA", model="GB100 A01 GSP", 2 FWIDs, etc.)
    //   Entry 2: minimal DiceTcbInfo (vendor="AMD", svn=5)
    // NOLINTBEGIN(readability-identifier-length)
    std::string inner1 = "3081b180064e5649444941810d47423130302041303120475350820230318301018401008501";
    inner1 += "00a67e303d06096086480165030402020430d090cab1b6e6ffddca83d1781e25b3f040fa1f";
    inner1 += "3c7608230cb5f41b1c1b99f5f748349e59d0ef8eb830c9bc79ccf77502303d060960864801";
    inner1 += "650304020204300000000000000000000000000000000000000000000000000000000000000";
    inner1 += "00000000000000000000000000000000000870500800000018801c0890100";
    std::string inner2 = "30088003414d44830105";  // vendor="AMD", svn=5
    // NOLINTEND(readability-identifier-length)

    // Outer SEQUENCE: 0x30 0x81 0xbe (190 bytes content)
    std::string multi_hex = "3081be" + inner1 + inner2;
    std::vector<uint8_t> der = hex_string_to_bytes(multi_hex);

    MultiDiceTcbInfo multi;
    Error err = MultiDiceTcbInfo::parse_from_der(der, multi);
    ASSERT_EQ(err, Error::Ok);

    ASSERT_EQ(multi.entries().size(), 2u);

    // Entry 1: Blackwell
    ASSERT_TRUE(multi.entries()[0].has_vendor());
    EXPECT_EQ(multi.entries()[0].vendor(), "NVIDIA");
    ASSERT_TRUE(multi.entries()[0].has_model());
    EXPECT_EQ(multi.entries()[0].model(), "GB100 A01 GSP");
    ASSERT_TRUE(multi.entries()[0].has_fwids());
    EXPECT_EQ(multi.entries()[0].fwids().size(), 2u);

    // Entry 2: minimal
    ASSERT_TRUE(multi.entries()[1].has_vendor());
    EXPECT_EQ(multi.entries()[1].vendor(), "AMD");
    ASSERT_TRUE(multi.entries()[1].has_svn());
    EXPECT_EQ(multi.entries()[1].svn(), 5);
    EXPECT_FALSE(multi.entries()[1].has_model());
    EXPECT_FALSE(multi.entries()[1].has_fwids());
}

TEST(MultiDiceTcbInfoTest, JsonRoundTrip) {
    MultiDiceTcbInfo original;

    DiceTcbInfo entry;
    entry.set_vendor("NVIDIA");
    entry.set_svn(1);
    original.add_entry(entry);

    nlohmann::json j = original;
    MultiDiceTcbInfo restored = j.get<MultiDiceTcbInfo>();

    EXPECT_EQ(original, restored);
}

// --- CompositeDeviceId Tests ---

TEST(CompositeDeviceIdTest, ConstructionAndGetters) {
    CompositeDeviceId cdi;
    EXPECT_EQ(cdi.version(), 0);
    EXPECT_TRUE(cdi.subject_public_key_info().empty());
    EXPECT_TRUE(cdi.fwid().digest().empty());

    cdi.set_version(1);
    cdi.set_subject_public_key_info({0x30, 0x00});
    cdi.set_fwid(FWID("2.16.840.1.101.3.4.2.2", {0xAA, 0xBB}));

    EXPECT_EQ(cdi.version(), 1);
    EXPECT_EQ(cdi.subject_public_key_info(), std::vector<uint8_t>({0x30, 0x00}));
    EXPECT_EQ(cdi.fwid().hash_alg_oid(), "2.16.840.1.101.3.4.2.2");
    EXPECT_EQ(cdi.fwid().digest(), std::vector<uint8_t>({0xAA, 0xBB}));
}

TEST(CompositeDeviceIdTest, ParseFromDer) {
    // Constructed CompositeDeviceID DER:
    // SEQUENCE { OID 2.23.133.5.4.1, SEQUENCE { INTEGER 0, SubjectPublicKeyInfo, FWID(sha384, 48xAA) } }
    std::string hex = "3060060667810505040130560201003012300b06072a8648ce3d020105000303000401";
    hex += "303d06096086480165030402020430";
    hex += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::vector<uint8_t> der = hex_string_to_bytes(hex);

    CompositeDeviceId cdi;
    Error err = CompositeDeviceId::parse_from_der(der, cdi);
    ASSERT_EQ(err, Error::Ok);

    EXPECT_EQ(cdi.version(), 0);
    EXPECT_FALSE(cdi.subject_public_key_info().empty());
    EXPECT_EQ(cdi.fwid().hash_alg_oid(), "2.16.840.1.101.3.4.2.2");
    EXPECT_EQ(cdi.fwid().digest().size(), 48u);
    EXPECT_EQ(cdi.fwid().digest()[0], 0xAA);
}

TEST(CompositeDeviceIdTest, ParseFromDerEmpty) {
    std::vector<uint8_t> empty;
    CompositeDeviceId cdi;
    EXPECT_NE(CompositeDeviceId::parse_from_der(empty, cdi), Error::Ok);
}

TEST(CompositeDeviceIdTest, JsonRoundTrip) {
    CompositeDeviceId original;
    original.set_version(1);
    original.set_subject_public_key_info({0x30, 0x0A, 0x0B});
    original.set_fwid(FWID("2.16.840.1.101.3.4.2.2", {0x01, 0x02, 0x03}));

    nlohmann::json j = original;
    CompositeDeviceId restored = j.get<CompositeDeviceId>();

    EXPECT_EQ(original, restored);
}

TEST(CompositeDeviceIdTest, Equality) {
    CompositeDeviceId a;
    a.set_version(0);
    a.set_fwid(FWID("2.16.840.1.101.3.4.2.2", {0xAA}));

    CompositeDeviceId b;
    b.set_version(0);
    b.set_fwid(FWID("2.16.840.1.101.3.4.2.2", {0xAA}));

    CompositeDeviceId c;
    c.set_version(1);
    c.set_fwid(FWID("2.16.840.1.101.3.4.2.2", {0xAA}));

    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

// --- Equality Tests ---

TEST(DiceTcbInfoTest, EqualityDifferentFields) {
    DiceTcbInfo a;
    a.set_vendor("NVIDIA");
    a.set_svn(1);

    DiceTcbInfo b;
    b.set_vendor("NVIDIA");
    b.set_svn(1);

    DiceTcbInfo c;
    c.set_vendor("NVIDIA");
    c.set_svn(2);

    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST(DiceTcbInfoTest, EqualityOptionalPresence) {
    DiceTcbInfo a;
    a.set_vendor("NVIDIA");

    DiceTcbInfo b;
    // b has no vendor

    EXPECT_NE(a, b);
}

TEST(DiceTcbInfoTest, CopyConstructorAndAssignment) {
    DiceTcbInfo original;
    original.set_vendor("NVIDIA");
    original.set_model("GB100");
    original.set_svn(42);
    original.set_flags(0x01);
    original.set_flags_mask(0x03);
    original.set_fwids({FWID("2.16.840.1.101.3.4.2.2", {0xAA, 0xBB})});

    IntegrityRegister reg;
    reg.set_register_name("PCR0");
    reg.set_register_num(0);
    reg.set_register_digests({FWID("2.16.840.1.101.3.4.2.2", {0xCC, 0xDD})});
    original.set_integrity_registers({reg});

    // Copy constructor
    DiceTcbInfo copy(original);
    EXPECT_EQ(copy, original);

    // Copy assignment
    DiceTcbInfo assigned;
    assigned = original;
    EXPECT_EQ(assigned, original);

    // Verify deep copy — mutating original does not affect copies
    original.set_vendor("CHANGED");
    EXPECT_EQ(copy.vendor(), "NVIDIA");
    EXPECT_EQ(assigned.vendor(), "NVIDIA");
    EXPECT_TRUE(copy.has_integrity_registers());
    EXPECT_EQ(copy.integrity_registers().size(), 1u);
}

// --- IntegrityRegister Tests ---

TEST(IntegrityRegisterTest, DefaultConstruction) {
    IntegrityRegister reg;
    EXPECT_FALSE(reg.has_register_name());
    EXPECT_FALSE(reg.has_register_num());
    EXPECT_TRUE(reg.register_digests().empty());
}

TEST(IntegrityRegisterTest, SetAndGet) {
    IntegrityRegister reg;
    reg.set_register_name("PCR0");
    reg.set_register_num(0);
    reg.set_register_digests({FWID("2.16.840.1.101.3.4.2.2", {0xAA, 0xBB})});

    EXPECT_TRUE(reg.has_register_name());
    EXPECT_EQ(reg.register_name(), "PCR0");
    EXPECT_TRUE(reg.has_register_num());
    EXPECT_EQ(reg.register_num(), 0);
    EXPECT_EQ(reg.register_digests().size(), 1u);
    EXPECT_EQ(reg.register_digests()[0].hash_alg_oid(), "2.16.840.1.101.3.4.2.2");
}

TEST(IntegrityRegisterTest, Equality) {
    IntegrityRegister a;
    a.set_register_name("PCR0");
    a.set_register_num(0);
    a.set_register_digests({FWID("2.16.840.1.101.3.4.2.2", {0xAA})});

    IntegrityRegister b;
    b.set_register_name("PCR0");
    b.set_register_num(0);
    b.set_register_digests({FWID("2.16.840.1.101.3.4.2.2", {0xAA})});

    IntegrityRegister c;
    c.set_register_name("PCR1");
    c.set_register_num(1);

    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST(IntegrityRegisterTest, JsonRoundTrip) {
    IntegrityRegister original;
    original.set_register_name("PCR0");
    original.set_register_num(0);
    original.set_register_digests({FWID("2.16.840.1.101.3.4.2.2", {0xAA, 0xBB, 0xCC})});

    nlohmann::json j = original;
    IntegrityRegister restored = j.get<IntegrityRegister>();

    EXPECT_EQ(original, restored);
}

TEST(IntegrityRegisterTest, JsonRoundTripOptionalFieldsAbsent) {
    IntegrityRegister original;
    // Only registerDigests set, name and num absent
    original.set_register_digests({FWID("2.16.840.1.101.3.4.2.2", {0x01})});

    nlohmann::json j = original;
    IntegrityRegister restored = j.get<IntegrityRegister>();

    EXPECT_EQ(original, restored);
    EXPECT_FALSE(restored.has_register_name());
    EXPECT_FALSE(restored.has_register_num());
    EXPECT_EQ(restored.register_digests().size(), 1u);
}

TEST(DiceTcbInfoTest, IntegrityRegistersJsonRoundTrip) {
    DiceTcbInfo original;
    original.set_vendor("NVIDIA");

    IntegrityRegister reg1;
    reg1.set_register_name("PCR0");
    reg1.set_register_num(0);
    reg1.set_register_digests({FWID("2.16.840.1.101.3.4.2.2", {0xAA})});

    IntegrityRegister reg2;
    reg2.set_register_name("PCR1");
    reg2.set_register_num(1);
    reg2.set_register_digests({FWID("2.16.840.1.101.3.4.2.2", {0xBB})});

    original.set_integrity_registers({reg1, reg2});

    nlohmann::json j = original;
    DiceTcbInfo restored = j.get<DiceTcbInfo>();

    EXPECT_EQ(original, restored);
    ASSERT_TRUE(restored.has_integrity_registers());
    EXPECT_EQ(restored.integrity_registers().size(), 2u);
    EXPECT_EQ(restored.integrity_registers()[0].register_name(), "PCR0");
    EXPECT_EQ(restored.integrity_registers()[1].register_name(), "PCR1");
}

TEST(DiceTcbInfoTest, ParseFromDerWithIntegrityRegisters) {
    // Hand-crafted DER: DiceTcbInfo with vendor="NV" and integrityRegisters containing
    // one IntegrityRegister with registerName="R0", registerNum=0,
    // registerDigests=[FWID(sha256, 0xAABB)]
    //
    // Built inside-out with python3 to compute lengths:
    //   FWID SEQUENCE (17 bytes): 300f 0609608648016503040201 0402aabb
    //   [2] registerDigests (19 bytes): a211 + FWID
    //   [0] registerName "R0" (4 bytes): 80025230
    //   [1] registerNum 0 (3 bytes): 810100
    //   IntegrityRegister SEQUENCE (28 bytes): 301a + [0]+[1]+[2]
    //   [11] integrityRegisters (30 bytes): ab1c + IR SEQUENCE
    //   [0] vendor "NV" (4 bytes): 80024e56
    //   Outer DiceTcbInfo SEQUENCE (36 bytes): 3022 + [0]+[11]
    std::string outer = "302280024e56ab1c301a80025230810100a211300f06096086480165030402010402aabb";

    std::vector<uint8_t> der = hex_string_to_bytes(outer);

    DiceTcbInfo info;
    Error err = DiceTcbInfo::parse_from_der(der, info);
    ASSERT_EQ(err, Error::Ok);

    ASSERT_TRUE(info.has_vendor());
    EXPECT_EQ(info.vendor(), "NV");

    ASSERT_TRUE(info.has_integrity_registers());
    ASSERT_EQ(info.integrity_registers().size(), 1u);

    const IntegrityRegister& reg = info.integrity_registers()[0];
    ASSERT_TRUE(reg.has_register_name());
    EXPECT_EQ(reg.register_name(), "R0");
    ASSERT_TRUE(reg.has_register_num());
    EXPECT_EQ(reg.register_num(), 0);
    ASSERT_EQ(reg.register_digests().size(), 1u);
    EXPECT_EQ(reg.register_digests()[0].hash_alg_oid(), "2.16.840.1.101.3.4.2.1");
    EXPECT_EQ(reg.register_digests()[0].digest(), std::vector<uint8_t>({0xAA, 0xBB}));
}

// --- Error path coverage for helper functions (LOG_AT_LEVEL changed lines) ---
// These craft minimal DER that exercises each error branch in the helper chain.

// parse_fwid_list: non-SEQUENCE start byte
// SEQUENCE { [6] { 0x01 } } — first byte of FWID list is BOOLEAN, not SEQUENCE
TEST(DiceTcbInfoTest, ParseFromDerFwidListNonSequence) {
    std::vector<uint8_t> der = {0x30, 0x03, 0x86, 0x01, 0x01};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// parse_fwid_list: SEQUENCE tag at end of buffer (no length byte follows)
TEST(DiceTcbInfoTest, ParseFromDerFwidListTruncatedAfterTag) {
    std::vector<uint8_t> der = {0x30, 0x03, 0x86, 0x01, 0x30};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// parse_fwid_list: FWID SEQUENCE length overruns the list buffer
// SEQUENCE { [6] { 0x30 0x05 0x00 } } — FWID claims 5 bytes, only 1 available
TEST(DiceTcbInfoTest, ParseFromDerFwidListSequenceOverrun) {
    std::vector<uint8_t> der = {0x30, 0x05, 0x86, 0x03, 0x30, 0x05, 0x00};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// parse_fwid_from_der: FWID SEQUENCE has only 1 element (OID, no digest)
// SEQUENCE { [6] SEQUENCE { sha256-OID } }
TEST(DiceTcbInfoTest, ParseFromDerFwidTooFewElements) {
    std::vector<uint8_t> der = {
        0x30, 0x0F, 0x86, 0x0D,
        0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
    };
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// parse_fwid_from_der: FWID element 0 is an INTEGER, not an OID
// SEQUENCE { [6] SEQUENCE { INTEGER 0, OCTET STRING {} } }
TEST(DiceTcbInfoTest, ParseFromDerFwidElement0NotOid) {
    std::vector<uint8_t> der = {0x30, 0x09, 0x86, 0x07, 0x30, 0x05, 0x02, 0x01, 0x00, 0x04, 0x00};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// parse_fwid_from_der: FWID element 1 is an INTEGER, not an OCTET STRING
// SEQUENCE { [6] SEQUENCE { sha256-OID, INTEGER 0 } }
TEST(DiceTcbInfoTest, ParseFromDerFwidElement1NotOctetString) {
    std::vector<uint8_t> der = {
        0x30, 0x12, 0x86, 0x10,
        0x30, 0x0E, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x02, 0x01, 0x00
    };
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// parse_implicit_bit_string: FLAGS field is empty (0 bytes — too short)
// SEQUENCE { [7] {} }
TEST(DiceTcbInfoTest, ParseFromDerFlagsTooShort) {
    std::vector<uint8_t> der = {0x30, 0x02, 0x87, 0x00};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// parse_implicit_bit_string: FLAGS field is 6 bytes (exceeds max of 5 for uint32_t)
// SEQUENCE { [7] { 0x00 0x00 0x00 0x00 0x00 0x00 } }
TEST(DiceTcbInfoTest, ParseFromDerFlagsTooLong) {
    std::vector<uint8_t> der = {0x30, 0x08, 0x87, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// parse_implicit_bit_string: FLAGS unused-bits byte = 8 (invalid, must be 0-7)
// SEQUENCE { [7] { 0x08 0x00 } }
TEST(DiceTcbInfoTest, ParseFromDerFlagsInvalidUnusedBits) {
    std::vector<uint8_t> der = {0x30, 0x04, 0x87, 0x02, 0x08, 0x00};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// parse_integrity_register: register has no registerDigests [2] field
// SEQUENCE { [11] CONSTRUCTED { SEQUENCE { [0] "NV" } } }
TEST(DiceTcbInfoTest, ParseFromDerIntegrityRegisterMissingDigests) {
    std::vector<uint8_t> der = {0x30, 0x08, 0xAB, 0x06, 0x30, 0x04, 0x80, 0x02, 0x4E, 0x56};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// parse_integrity_register_list: first byte of list is not a SEQUENCE tag
// SEQUENCE { [11] CONSTRUCTED { 0x01 } }
TEST(DiceTcbInfoTest, ParseFromDerIntegrityRegisterListNonSequence) {
    std::vector<uint8_t> der = {0x30, 0x03, 0xAB, 0x01, 0x01};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// parse_integrity_register_list: SEQUENCE tag at end of buffer (truncated)
// SEQUENCE { [11] CONSTRUCTED { 0x30 } }
TEST(DiceTcbInfoTest, ParseFromDerIntegrityRegisterListTruncated) {
    std::vector<uint8_t> der = {0x30, 0x03, 0xAB, 0x01, 0x30};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// CompositeDeviceId: outer SEQUENCE element 0 is not an OID (it's an INTEGER)
// SEQUENCE { INTEGER 0, SEQUENCE {} }
TEST(CompositeDeviceIdTest, ParseFromDerElement0NotOid) {
    std::vector<uint8_t> der = {0x30, 0x06, 0x02, 0x01, 0x00, 0x30, 0x01, 0x00};
    CompositeDeviceId cdi;
    EXPECT_NE(CompositeDeviceId::parse_from_der(der, cdi), Error::Ok);
}

// CompositeDeviceId: outer SEQUENCE element 1 is not a SEQUENCE (it's an INTEGER)
// SEQUENCE { OID 2.23.133.5.4.1, INTEGER 0 }
TEST(CompositeDeviceIdTest, ParseFromDerElement1NotSequence) {
    std::vector<uint8_t> der = {
        0x30, 0x0B, 0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x01, 0x02, 0x01, 0x00
    };
    CompositeDeviceId cdi;
    EXPECT_NE(CompositeDeviceId::parse_from_der(der, cdi), Error::Ok);
}

// CompositeDeviceId: inner SEQUENCE has fewer than 3 elements
// SEQUENCE { OID 2.23.133.5.4.1, SEQUENCE { INTEGER, SEQUENCE } }
TEST(CompositeDeviceIdTest, ParseFromDerInnerTooFewElements) {
    std::vector<uint8_t> der = {
        0x30, 0x0F, 0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x01,
        0x30, 0x05, 0x02, 0x01, 0x00, 0x30, 0x00
    };
    CompositeDeviceId cdi;
    EXPECT_NE(CompositeDeviceId::parse_from_der(der, cdi), Error::Ok);
}

// parse_fwid_list: FWID SEQUENCE uses 0x80 (long-form, num_len_bytes=0) — invalid encoding
// SEQUENCE { [6] { 0x30 0x80 } }
TEST(DiceTcbInfoTest, ParseFromDerFwidMultiByteInvalidLength) {
    std::vector<uint8_t> der = {0x30, 0x04, 0x86, 0x02, 0x30, 0x80};
    DiceTcbInfo info;
    EXPECT_NE(DiceTcbInfo::parse_from_der(der, info), Error::Ok);
}

// CompositeDeviceId: inner SEQUENCE element 1 (SPKI) is not a SEQUENCE
// SEQUENCE { OID, SEQUENCE { INTEGER(version), INTEGER(spki), SEQUENCE(fwid) } }
TEST(CompositeDeviceIdTest, ParseFromDerSpkiNotSequence) {
    std::vector<uint8_t> der = {
        0x30, 0x12, 0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x01,
        0x30, 0x08, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00
    };
    CompositeDeviceId cdi;
    EXPECT_NE(CompositeDeviceId::parse_from_der(der, cdi), Error::Ok);
}

// CompositeDeviceId: inner SEQUENCE element 2 (FWID) is not a SEQUENCE
// SEQUENCE { OID, SEQUENCE { INTEGER(version), SEQUENCE(spki), INTEGER(fwid) } }
TEST(CompositeDeviceIdTest, ParseFromDerFwidNotSequence) {
    std::vector<uint8_t> der = {
        0x30, 0x12, 0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x01,
        0x30, 0x08, 0x02, 0x01, 0x00, 0x30, 0x00, 0x02, 0x01, 0x00
    };
    CompositeDeviceId cdi;
    EXPECT_NE(CompositeDeviceId::parse_from_der(der, cdi), Error::Ok);
}

// CompositeDeviceId: FWID SEQUENCE is empty (fwid_len == 0)
// SEQUENCE { OID, SEQUENCE { INTEGER(version), SEQUENCE(spki), SEQUENCE{} } }
TEST(CompositeDeviceIdTest, ParseFromDerFwidDataEmpty) {
    std::vector<uint8_t> der = {
        0x30, 0x11, 0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x01,
        0x30, 0x07, 0x02, 0x01, 0x00, 0x30, 0x00, 0x30, 0x00
    };
    CompositeDeviceId cdi;
    EXPECT_NE(CompositeDeviceId::parse_from_der(der, cdi), Error::Ok);
}

// CompositeDeviceId: version element is a SEQUENCE, not an INTEGER
// SEQUENCE { OID, SEQUENCE { SEQUENCE, SEQUENCE, SEQUENCE } }
TEST(CompositeDeviceIdTest, ParseFromDerVersionNotInteger) {
    std::vector<uint8_t> der = {
        0x30, 0x13, 0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x01,
        0x30, 0x09, 0x30, 0x01, 0x00, 0x30, 0x01, 0x00, 0x30, 0x01, 0x00
    };
    CompositeDeviceId cdi;
    EXPECT_NE(CompositeDeviceId::parse_from_der(der, cdi), Error::Ok);
}
