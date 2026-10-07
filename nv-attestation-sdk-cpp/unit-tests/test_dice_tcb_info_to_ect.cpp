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

#include "gtest/gtest.h"

#include <cstdint>
#include <limits>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

#include "nv_attestation/corim_evidence/dice_tcb_info_to_ect.h"
#include "nv_attestation/corim_verify.h"
#include "nv_attestation/dice_tcb_info.h"
#include "nv_attestation/error.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/utils.h"
#include "test_utils.h"

using namespace nvattestation;

namespace {

// Mirror of impl-private bit positions so tests don't depend on internal symbols.
constexpr uint32_t kNotConfigured = 1U << 31;
constexpr uint32_t kNotSecure     = 1U << 30;
constexpr uint32_t kRecovery      = 1U << 29;
constexpr uint32_t kDebug         = 1U << 28;
constexpr uint32_t kNotTcb        = 1U << 23;

DiceTcbInfo make_minimal_dti() {
    DiceTcbInfo dti;
    dti.set_vendor("NVIDIA");
    dti.set_model("GB100");
    return dti;
}

} // namespace

TEST(DiceTcbInfoToEct, MinimalEnvironmentOnly) {
    DiceTcbInfo dti = make_minimal_dti();

    Ect ect;
    ASSERT_EQ(dice_tcb_info_to_ect(dti, /*ueid=*/nullptr, ect), Error::Ok);

    const ClassMap *cls = ect.getEnvironment().getClass();
    ASSERT_NE(cls, nullptr);
    ASSERT_NE(cls->getVendor(), nullptr);
    EXPECT_EQ(*cls->getVendor(), "NVIDIA");
    ASSERT_NE(cls->getModel(), nullptr);
    EXPECT_EQ(*cls->getModel(), "GB100");
    EXPECT_EQ(cls->getClassId(), nullptr);
    EXPECT_EQ(cls->getLayer(), nullptr);
    EXPECT_EQ(cls->getIndex(), nullptr);

    EXPECT_EQ(ect.getEnvironment().getInstance(), nullptr);

    ASSERT_EQ(ect.getClaims().size(), 1u);
    const MeasurementValues &mv = ect.getClaims()[0].getValues();
    EXPECT_EQ(mv.getVersion(), nullptr);
    EXPECT_EQ(mv.getSvn(), nullptr);
    EXPECT_EQ(mv.getRawValue(), nullptr);
    EXPECT_EQ(mv.getFlags(), nullptr);
    EXPECT_TRUE(mv.getDigests().empty());
}

TEST(DiceTcbInfoToEct, AllScalarFieldsPopulated) {
    DiceTcbInfo dti = make_minimal_dti();
    dti.set_version("1.0");
    dti.set_svn(42);
    dti.set_layer(0);
    dti.set_index(7);
    dti.set_vendor_info({0xC0, 0xDE});
    dti.set_type({0xAB, 0xCD});
    std::vector<FWID> fwids;
    fwids.emplace_back("2.16.840.1.101.3.4.2.2",
                       std::vector<uint8_t>(48, 0x11));
    dti.set_fwids(fwids);

    Ect ect;
    ASSERT_EQ(dice_tcb_info_to_ect(dti, /*ueid=*/nullptr, ect), Error::Ok);

    const ClassMap *cls = ect.getEnvironment().getClass();
    ASSERT_NE(cls, nullptr);
    ASSERT_NE(cls->getClassId(), nullptr);
    EXPECT_EQ(cls->getClassId()->getKind(), ClassId::Kind::kBytes);
    EXPECT_EQ(cls->getClassId()->getValue().toVector(),
              std::vector<uint8_t>({0xAB, 0xCD}));
    ASSERT_NE(cls->getLayer(), nullptr);
    EXPECT_EQ(*cls->getLayer(), 0u);
    ASSERT_NE(cls->getIndex(), nullptr);
    EXPECT_EQ(*cls->getIndex(), 7u);

    const MeasurementValues &mv = ect.getClaims()[0].getValues();
    ASSERT_NE(mv.getVersion(), nullptr);
    EXPECT_EQ(mv.getVersion()->getValue(), "1.0");
    ASSERT_NE(mv.getSvn(), nullptr);
    EXPECT_EQ(mv.getSvn()->kind, SvnKind::kExact);
    EXPECT_EQ(mv.getSvn()->value, 42u);
    ASSERT_NE(mv.getRawValue(), nullptr);
    EXPECT_EQ(mv.getRawValue()->toVector(),
              std::vector<uint8_t>({0xC0, 0xDE}));
    ASSERT_EQ(mv.getDigests().size(), 1u);
    int32_t alg = 0;
    EXPECT_TRUE(mv.getDigests()[0].getAlgorithm(alg));
    EXPECT_EQ(alg, 7); // IANA NI: sha-384
}

TEST(DiceTcbInfoToEct, MultipleFwidsKeepsFirst) {
    DiceTcbInfo dti = make_minimal_dti();
    std::vector<FWID> fwids;
    fwids.emplace_back("2.16.840.1.101.3.4.2.2",
                       std::vector<uint8_t>{0x01, 0x02});
    fwids.emplace_back("2.16.840.1.101.3.4.2.1",
                       std::vector<uint8_t>{0xFF});
    dti.set_fwids(fwids);

    Ect ect;
    ASSERT_EQ(dice_tcb_info_to_ect(dti, nullptr, ect), Error::Ok);

    const auto &digests = ect.getClaims()[0].getValues().getDigests();
    ASSERT_EQ(digests.size(), 1u);
    EXPECT_EQ(digests[0].getValue().toVector(),
              std::vector<uint8_t>({0x01, 0x02}));
}

TEST(DiceTcbInfoToEct, KnownHashOidsMapToIanaNiInt) {
    struct Case {
        const char *oid;
        int32_t expected_ni;
    };
    const Case cases[] = {
        {"2.16.840.1.101.3.4.2.1", 1}, // sha-256
        {"2.16.840.1.101.3.4.2.2", 7}, // sha-384
        {"2.16.840.1.101.3.4.2.3", 8}, // sha-512
    };
    for (const auto &tc : cases) {
        DiceTcbInfo dti = make_minimal_dti();
        std::vector<FWID> fwids;
        fwids.emplace_back(tc.oid, std::vector<uint8_t>{0x11, 0x22});
        dti.set_fwids(fwids);

        Ect ect;
        ASSERT_EQ(dice_tcb_info_to_ect(dti, nullptr, ect), Error::Ok)
            << "OID " << tc.oid;
        const auto &digests = ect.getClaims()[0].getValues().getDigests();
        ASSERT_EQ(digests.size(), 1u);
        int32_t alg_int = 0;
        std::string alg_str;
        EXPECT_TRUE(digests[0].getAlgorithm(alg_int)) << "OID " << tc.oid;
        EXPECT_FALSE(digests[0].getAlgorithm(alg_str)) << "OID " << tc.oid;
        EXPECT_EQ(alg_int, tc.expected_ni) << "OID " << tc.oid;
    }
}

TEST(DiceTcbInfoToEct, UnknownHashOidIsRejected) {
    DiceTcbInfo dti = make_minimal_dti();
    std::vector<FWID> fwids;
    // SHA-1 OID — outside supported SHA-2 family.
    fwids.emplace_back("1.3.14.3.2.26", std::vector<uint8_t>(20, 0xAB));
    dti.set_fwids(fwids);

    Ect ect;
    EXPECT_EQ(dice_tcb_info_to_ect(dti, nullptr, ect), Error::BadArgument);
}

TEST(DiceTcbInfoToEct, FlagsWithSubsetMaskEmitsOnlyMaskedBits) {
    DiceTcbInfo dti = make_minimal_dti();
    dti.set_flags(kNotConfigured | kRecovery | kNotTcb);
    dti.set_flags_mask(kNotConfigured | kNotTcb);

    Ect ect;
    ASSERT_EQ(dice_tcb_info_to_ect(dti, nullptr, ect), Error::Ok);

    const FlagsMap *fm = ect.getClaims()[0].getValues().getFlags();
    ASSERT_NE(fm, nullptr);
    ASSERT_NE(fm->getConfigured(), nullptr);
    EXPECT_FALSE(*fm->getConfigured());
    ASSERT_NE(fm->getTcb(), nullptr);
    EXPECT_FALSE(*fm->getTcb());
    EXPECT_EQ(fm->getRecovery(), nullptr);
    EXPECT_EQ(fm->getSecure(), nullptr);
    EXPECT_EQ(fm->getDebug(), nullptr);
}

TEST(DiceTcbInfoToEct, FlagsWithoutMaskTreatsAllBitsAsAsserted) {
    DiceTcbInfo dti = make_minimal_dti();
    dti.set_flags(kNotSecure | kDebug);

    Ect ect;
    ASSERT_EQ(dice_tcb_info_to_ect(dti, nullptr, ect), Error::Ok);

    const FlagsMap *fm = ect.getClaims()[0].getValues().getFlags();
    ASSERT_NE(fm, nullptr);
    ASSERT_NE(fm->getSecure(), nullptr);
    EXPECT_FALSE(*fm->getSecure());
    ASSERT_NE(fm->getDebug(), nullptr);
    EXPECT_TRUE(*fm->getDebug());
    ASSERT_NE(fm->getConfigured(), nullptr);
    EXPECT_TRUE(*fm->getConfigured());
    ASSERT_NE(fm->getRecovery(), nullptr);
    EXPECT_FALSE(*fm->getRecovery());
}

TEST(DiceTcbInfoToEct, IntegrityRegistersAreDropped) {
    DiceTcbInfo dti = make_minimal_dti();
    IntegrityRegister reg;
    reg.set_register_num(1);
    dti.set_integrity_registers({reg});

    Ect ect;
    EXPECT_EQ(dice_tcb_info_to_ect(dti, nullptr, ect), Error::Ok);
    EXPECT_EQ(ect.getClaims().size(), 1u);
}

TEST(DiceTcbInfoToEct, UeidPopulatesInstanceId) {
    DiceTcbInfo dti = make_minimal_dti();
    std::vector<uint8_t> ueid = {0x01, 0x02, 0x03, 0x04};

    Ect ect;
    ASSERT_EQ(dice_tcb_info_to_ect(dti, &ueid, ect), Error::Ok);

    const InstanceId *inst = ect.getEnvironment().getInstance();
    ASSERT_NE(inst, nullptr);
    EXPECT_EQ(inst->getKind(), InstanceId::Kind::kUeid);
    EXPECT_EQ(inst->getValue().toVector(), ueid);
}

TEST(DiceTcbInfoToEct, MultiTransformPreservesOrder) {
    MultiDiceTcbInfo multi;
    DiceTcbInfo a = make_minimal_dti();
    a.set_model("layer-0");
    DiceTcbInfo b = make_minimal_dti();
    b.set_model("layer-1");
    multi.add_entry(a);
    multi.add_entry(b);

    std::vector<Ect> ects;
    ASSERT_EQ(multi_dice_tcb_info_to_ect_list(multi, nullptr, ects), Error::Ok);
    ASSERT_EQ(ects.size(), 2u);
    EXPECT_EQ(*ects[0].getEnvironment().getClass()->getModel(), "layer-0");
    EXPECT_EQ(*ects[1].getEnvironment().getClass()->getModel(), "layer-1");
}

TEST(DiceTcbInfoToEct, NegativeLayerIsRejected) {
    DiceTcbInfo dti = make_minimal_dti();
    dti.set_layer(-1);

    Ect ect;
    EXPECT_EQ(dice_tcb_info_to_ect(dti, nullptr, ect), Error::BadArgument);
}

TEST(DiceTcbInfoToEct, IndexOutOfUint32RangeIsRejected) {
    DiceTcbInfo dti = make_minimal_dti();
    dti.set_index(static_cast<int64_t>(std::numeric_limits<uint32_t>::max()) + 1);

    Ect ect;
    EXPECT_EQ(dice_tcb_info_to_ect(dti, nullptr, ect), Error::BadArgument);
}

TEST(DiceTcbInfoToEct, SvnOutOfUint32RangeIsRejected) {
    DiceTcbInfo dti = make_minimal_dti();
    dti.set_svn(-1);
    Ect ect;
    EXPECT_EQ(dice_tcb_info_to_ect(dti, nullptr, ect), Error::BadArgument);

    DiceTcbInfo dti_big = make_minimal_dti();
    dti_big.set_svn(static_cast<int64_t>(std::numeric_limits<uint32_t>::max()) + 1);
    Ect ect_big;
    EXPECT_EQ(dice_tcb_info_to_ect(dti_big, nullptr, ect_big), Error::BadArgument);
}

// flags present + mask=0 → no bit is meaningful → FlagsMap omitted entirely.
TEST(DiceTcbInfoToEct, FlagsPresentButFullyMaskedOutOmitsFlagsField) {
    DiceTcbInfo dti = make_minimal_dti();
    dti.set_flags(0xFFFFFFFFU);
    dti.set_flags_mask(0);

    Ect ect;
    ASSERT_EQ(dice_tcb_info_to_ect(dti, nullptr, ect), Error::Ok);
    EXPECT_EQ(ect.getClaims()[0].getValues().getFlags(), nullptr);
}

TEST(DiceTcbInfoToEct, MultiTransformAbortsAndClearsOnEntryFailure) {
    MultiDiceTcbInfo multi;
    DiceTcbInfo good = make_minimal_dti();
    good.set_model("good");
    DiceTcbInfo bad = make_minimal_dti();
    bad.set_layer(-1);
    multi.add_entry(good);
    multi.add_entry(bad);

    std::vector<Ect> ects;
    EXPECT_EQ(multi_dice_tcb_info_to_ect_list(multi, nullptr, ects),
              Error::BadArgument);
    EXPECT_TRUE(ects.empty());
}

namespace {

constexpr const char *kBlackwellChainPath =
    "testdata/sample_attestation_data/gpu/blackwellCertChain.txt";

constexpr const char *kRubinChainPath =
    "testdata/sample_attestation_data/gpu/rubinCertChain.txt";

std::string ect_golden_path(const std::string &name) {
    return "testdata/sample_attestation_data/gpu/golden/" + name + ".json";
}

nv_unique_ptr<X509> load_blackwell_leaf() {
    std::string pem;
    Error err = readFileIntoString(kBlackwellChainPath, pem);
    EXPECT_EQ(err, Error::Ok) << "Missing " << kBlackwellChainPath;
    if (err != Error::Ok) {
        return {};
    }
    return x509_from_cert_string(pem);
}

} // namespace

TEST(DiceTcbInfoToEct, BlackwellChainEmitsOnlyLeafDti) {
    std::string pem;
    ASSERT_EQ(readFileIntoString(kBlackwellChainPath, pem), Error::Ok);

    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GPU_DEVICE_IDENTITY, pem, pem, chain),
              Error::Ok);
    ASSERT_GT(chain.size(), 1u);

    std::vector<Ect> ects;
    ASSERT_EQ(x509_chain_to_evidence_ects(chain, /*ueid=*/nullptr, ects),
              Error::Ok);

    nlohmann::json j = ects;
    compare_to_golden(j, ect_golden_path("blackwell_chain"));
}

// Vera chain (leaf-first): DPE Leaf (Multi: RMTR, VICC, LCDS), Rt Alias
// (RT_INFO), FMC Alias (Multi: DEVICE_INFO, FMC_INFO). UEID per cert.
TEST(DiceTcbInfoToEct, VeraChainAllDtisExtracted) {
    std::string pem;
    ASSERT_EQ(readFileIntoString(
                  "testdata/sample_attestation_data/cpu/veraCertChain.txt", pem),
              Error::Ok);
    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GENERIC, pem, pem, chain),
              Error::Ok);
    ASSERT_EQ(chain.size(), 8u);

    std::vector<Ect> ects;
    ASSERT_EQ(x509_chain_to_evidence_ects(chain, /*ueid_fallback=*/nullptr,
                                          ects),
              Error::Ok);
    ASSERT_EQ(ects.size(), 6u);

    const auto type_bytes = [&](size_t idx) {
        const ClassId *cid = ects[idx].getEnvironment().getClass()->getClassId();
        return cid ? cid->getValue().toVector() : std::vector<uint8_t>{};
    };
    EXPECT_EQ(type_bytes(0), std::vector<uint8_t>({'R', 'M', 'T', 'R'}));
    EXPECT_EQ(type_bytes(1), std::vector<uint8_t>({'V', 'I', 'C', 'C'}));
    EXPECT_EQ(type_bytes(2), std::vector<uint8_t>({'L', 'C', 'D', 'S'}));
    EXPECT_EQ(type_bytes(3),
              std::vector<uint8_t>({'R', 'T', '_', 'I', 'N', 'F', 'O'}));
    EXPECT_EQ(type_bytes(4), std::vector<uint8_t>({'D', 'E', 'V', 'I', 'C',
                                                   'E', '_', 'I', 'N', 'F',
                                                   'O'}));
    EXPECT_EQ(type_bytes(5),
              std::vector<uint8_t>({'F', 'M', 'C', '_', 'I', 'N', 'F', 'O'}));

    const auto ueid_of = [&](size_t idx) {
        const InstanceId *inst = ects[idx].getEnvironment().getInstance();
        return inst ? inst->getValue().toVector() : std::vector<uint8_t>{};
    };
    const std::vector<uint8_t> leaf_ueid = ueid_of(0);
    EXPECT_EQ(leaf_ueid.size(), 48u);
    EXPECT_EQ(std::string(leaf_ueid.begin(), leaf_ueid.begin() + 18),
              "SPDM IDENTITY CERT");
    EXPECT_EQ(ueid_of(1), leaf_ueid);
    EXPECT_EQ(ueid_of(2), leaf_ueid);
    const std::vector<uint8_t> inner_ueid = ueid_of(3);
    ASSERT_FALSE(inner_ueid.empty());
    EXPECT_NE(inner_ueid, leaf_ueid);
    EXPECT_EQ(ueid_of(4), inner_ueid);
    EXPECT_EQ(ueid_of(5), inner_ueid);
}

TEST(DiceTcbInfoToEct, ChainHelperFallbackUeidAppliedWhenAbsent) {
    std::string pem;
    ASSERT_EQ(readFileIntoString(kBlackwellChainPath, pem), Error::Ok);
    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GPU_DEVICE_IDENTITY, pem, pem, chain),
              Error::Ok);

    std::vector<uint8_t> fallback = {0xCA, 0xFE};
    std::vector<Ect> ects;
    ASSERT_EQ(x509_chain_to_evidence_ects(chain, &fallback, ects), Error::Ok);
    ASSERT_EQ(ects.size(), 1u);
    const InstanceId *inst = ects[0].getEnvironment().getInstance();
    ASSERT_NE(inst, nullptr);
    EXPECT_EQ(inst->getKind(), InstanceId::Kind::kUeid);
    EXPECT_EQ(inst->getValue().toVector(), fallback);
}

TEST(DiceTcbInfoToEct, DiceUeidParserReturnsNotFoundWhenAbsent) {
    nv_unique_ptr<X509> leaf = load_blackwell_leaf();
    ASSERT_NE(leaf.get(), nullptr);
    std::vector<uint8_t> out;
    EXPECT_EQ(parse_dice_ueid_from_x509_extension(leaf.get(), out, /*silent=*/true),
              Error::CertFwidNotFound);
}

TEST(DiceTcbInfoToEct, ChainHelperOkOnEmptyChain) {
    X509CertChain chain;
    std::vector<Ect> ects;
    EXPECT_EQ(x509_chain_to_evidence_ects(chain, nullptr, ects), Error::Ok);
    EXPECT_TRUE(ects.empty());
}

TEST(DiceTcbInfoToEct, RubinChainEmitsOnlyLeafDti) {
    std::string pem;
    ASSERT_EQ(readFileIntoString(kRubinChainPath, pem), Error::Ok);

    X509CertChain chain;
    ASSERT_EQ(X509CertChain::create_from_cert_chain_str(
                  CertificateChainType::GPU_DEVICE_IDENTITY, pem, pem, chain),
              Error::Ok);
    ASSERT_GT(chain.size(), 1u);

    std::vector<Ect> ects;
    ASSERT_EQ(x509_chain_to_evidence_ects(chain, /*ueid=*/nullptr, ects),
              Error::Ok);

    nlohmann::json j = ects;
    compare_to_golden(j, ect_golden_path("rubin_chain"));
}
