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

#include "nv_attestation/corim_evidence/dice_tcb_info_to_ect.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

#include "nv_attestation/log.h"

namespace nvattestation {

namespace {

// BIT STRING bit N → uint32 bit (31 - N); fixedWidth pads to 32 bits.
// See dice_tcb_info_test.cpp ParseFromDerBlackwell for the encoding anchor.
constexpr uint32_t kBitNotConfigured         = 1U << 31;
constexpr uint32_t kBitNotSecure             = 1U << 30;
constexpr uint32_t kBitRecovery              = 1U << 29;
constexpr uint32_t kBitDebug                 = 1U << 28;
constexpr uint32_t kBitNotReplayProtected    = 1U << 27;
constexpr uint32_t kBitNotIntegrityProtected = 1U << 26;
constexpr uint32_t kBitNotRuntimeMeasured    = 1U << 25;
constexpr uint32_t kBitNotImmutable          = 1U << 24;
constexpr uint32_t kBitNotTcb                = 1U << 23;

// DICE FWID.hashAlg is a NIST CSOR DER OID; CoRIM digest.alg is the IANA NI
// hash registry id (RFC 6920). CoCLI accepts the text name in its JSON
// template but encodes the int on the wire, so consumers compare ints.
bool ni_hash_alg_from_oid(const std::string &oid, int32_t &out_alg) {
    struct Entry {
        const char *oid;
        int32_t ni_alg;
    };
    static constexpr Entry kMap[] = {
        {"2.16.840.1.101.3.4.2.1", 1}, // sha-256
        {"2.16.840.1.101.3.4.2.2", 7}, // sha-384
        {"2.16.840.1.101.3.4.2.3", 8}, // sha-512
    };
    for (const auto &entry : kMap) {
        if (oid == entry.oid) {
            out_alg = entry.ni_alg;
            return true;
        }
    }
    return false;
}

Error narrow_int64_to_uint32(int64_t in, const char *field, uint32_t &out) {
    if (in < 0 || in > std::numeric_limits<uint32_t>::max()) {
        LOG_ERROR("DICE→ECT: " << field << " value out of uint32 range: "
                               << in);
        return Error::BadArgument;
    }
    out = static_cast<uint32_t>(in);
    return Error::Ok;
}

Error build_environment(const DiceTcbInfo &dti,
                        const std::vector<uint8_t> *ueid,
                        EnvironmentMap &out) {
    std::unique_ptr<ClassId> class_id;
    if (dti.has_type()) {
        class_id.reset(new ClassId(ClassId::Kind::kBytes, ByteString(dti.type())));
    }

    std::unique_ptr<std::string> vendor;
    if (dti.has_vendor()) {
        vendor.reset(new std::string(dti.vendor()));
    }
    std::unique_ptr<std::string> model;
    if (dti.has_model()) {
        model.reset(new std::string(dti.model()));
    }

    std::unique_ptr<uint32_t> layer;
    if (dti.has_layer()) {
        uint32_t narrowed = 0;
        Error err = narrow_int64_to_uint32(dti.layer(), "layer", narrowed);
        if (err != Error::Ok) {
            return err;
        }
        layer.reset(new uint32_t(narrowed));
    }
    std::unique_ptr<uint32_t> index;
    if (dti.has_index()) {
        uint32_t narrowed = 0;
        Error err = narrow_int64_to_uint32(dti.index(), "index", narrowed);
        if (err != Error::Ok) {
            return err;
        }
        index.reset(new uint32_t(narrowed));
    }

    std::unique_ptr<ClassMap> class_map;
    if (class_id || vendor || model || layer || index) {
        class_map.reset(new ClassMap(std::move(class_id), std::move(vendor),
                                     std::move(model), std::move(layer),
                                     std::move(index)));
    }

    std::unique_ptr<InstanceId> instance;
    if (ueid != nullptr && !ueid->empty()) {
        instance.reset(
            new InstanceId(InstanceId::Kind::kUeid, ByteString(*ueid)));
    }

    out = EnvironmentMap(std::move(class_map), std::move(instance),
                         /*group=*/nullptr);
    return Error::Ok;
}

// `polarity_inverts` true for `notX` DICE bits (invert into positive is-X).
void set_flag_bit(uint32_t flags, uint32_t mask, uint32_t bit,
                  bool polarity_inverts, FlagsMap &out,
                  void (FlagsMap::*setter)(bool)) {
    if ((mask & bit) == 0) {
        return;
    }
    bool raw = (flags & bit) != 0;
    bool value = polarity_inverts ? !raw : raw;
    (out.*setter)(value);
}

// DICE rule: flags present without mask ⇒ effective mask = all-ones.
std::unique_ptr<FlagsMap> build_flags(const DiceTcbInfo &dti) {
    if (!dti.has_flags()) {
        return nullptr;
    }
    const uint32_t flags = dti.flags();
    const uint32_t mask = dti.has_flags_mask() ? dti.flags_mask() : 0xFFFFFFFFU;

    FlagsMap fm;
    set_flag_bit(flags, mask, kBitNotConfigured,         true,  fm, &FlagsMap::setConfigured);
    set_flag_bit(flags, mask, kBitNotSecure,             true,  fm, &FlagsMap::setSecure);
    // DICE `recovery` and `debug` are positive-form (not `notX`). The draft
    // §4.2 step 3.iv text inverts them, which contradicts the bit name; we
    // follow TCG DICE Architecture v1.2 §A.1 and keep them positive.
    set_flag_bit(flags, mask, kBitRecovery,              false, fm, &FlagsMap::setRecovery);
    set_flag_bit(flags, mask, kBitDebug,                 false, fm, &FlagsMap::setDebug);
    set_flag_bit(flags, mask, kBitNotReplayProtected,    true,  fm, &FlagsMap::setReplayProtected);
    set_flag_bit(flags, mask, kBitNotIntegrityProtected, true,  fm, &FlagsMap::setIntegrityProtected);
    set_flag_bit(flags, mask, kBitNotRuntimeMeasured,    true,  fm, &FlagsMap::setRuntimeMeas);
    set_flag_bit(flags, mask, kBitNotImmutable,          true,  fm, &FlagsMap::setImmutable);
    set_flag_bit(flags, mask, kBitNotTcb,                true,  fm, &FlagsMap::setTcb);

    if (fm.empty()) {
        return nullptr;
    }
    return std::unique_ptr<FlagsMap>(new FlagsMap(std::move(fm)));
}

Error build_measurement_values(const DiceTcbInfo &dti, MeasurementValues &out) {
    std::unique_ptr<Version> version;
    if (dti.has_version()) {
        version.reset(new Version(dti.version()));
    }

    std::unique_ptr<Svn> svn;
    if (dti.has_svn()) {
        uint32_t narrowed = 0;
        Error err = narrow_int64_to_uint32(dti.svn(), "svn", narrowed);
        if (err != Error::Ok) {
            return err;
        }
        svn.reset(new Svn(SvnKind::kExact, narrowed));
    }

    std::unique_ptr<ByteString> raw_value;
    if (dti.has_vendor_info()) {
        raw_value.reset(new ByteString(dti.vendor_info()));
    }

    std::vector<Digest> digests;
    if (dti.has_fwids() && !dti.fwids().empty()) {
        // TODO: support additional FWIDs as alternative-algorithm digests.
        const FWID &fwid = dti.fwids()[0];
        int32_t ni_alg = 0;
        if (!ni_hash_alg_from_oid(fwid.hash_alg_oid(), ni_alg)) {
            LOG_ERROR("DICE→ECT: unsupported FWID hash OID "
                      << fwid.hash_alg_oid()
                      << "; supported: SHA-256/384/512 (NIST CSOR OIDs "
                         "2.16.840.1.101.3.4.2.{1,2,3})");
            return Error::BadArgument;
        }
        digests.emplace_back(ni_alg, ByteString(fwid.digest()));
        if (dti.fwids().size() > 1) {
            LOG_WARN("DICE→ECT: DiceTcbInfo carries "
                     << dti.fwids().size()
                     << " FWIDs; only the first is consumed");
        }
    }

    std::unique_ptr<FlagsMap> flags = build_flags(dti);

    out = MeasurementValues(
        std::move(version), std::move(flags), std::move(raw_value),
        /*raw_value_mask=*/nullptr, /*name=*/nullptr,
        /*int_range=*/nullptr, std::move(svn), std::move(digests));
    return Error::Ok;
}

} // namespace

Error dice_tcb_info_to_ect(const DiceTcbInfo &dti,
                           const std::vector<uint8_t> *ueid, Ect &out) {
    if (dti.has_integrity_registers()) {
        LOG_WARN("DICE→ECT: DiceTcbInfo has "
                 << dti.integrity_registers().size()
                 << " integrity register(s); dropped (not yet modeled in "
                    "MeasurementValues)");
    }

    EnvironmentMap env;
    Error err = build_environment(dti, ueid, env);
    if (err != Error::Ok) {
        return err;
    }

    MeasurementValues values;
    err = build_measurement_values(dti, values);
    if (err != Error::Ok) {
        return err;
    }
    std::vector<MeasurementMap> claims;
    claims.emplace_back(MeasurementMapKey::ofAbsent(), std::move(values));

    out = Ect(std::move(env), std::move(claims));
    return Error::Ok;
}

Error multi_dice_tcb_info_to_ect_list(const MultiDiceTcbInfo &multi,
                                      const std::vector<uint8_t> *ueid,
                                      std::vector<Ect> &out) {
    out.clear();
    out.reserve(multi.entries().size());
    for (const auto &dti : multi.entries()) {
        Ect ect;
        Error err = dice_tcb_info_to_ect(dti, ueid, ect);
        if (err != Error::Ok) {
            out.clear();
            return err;
        }
        out.push_back(std::move(ect));
    }
    return Error::Ok;
}

namespace {

// A UEID carried by the certificate itself takes precedence over the
// chain-level fallback.
const std::vector<uint8_t> *resolve_cert_ueid(const X509CertChain &chain,
                                              size_t index,
                                              const std::vector<uint8_t> *fallback,
                                              std::vector<uint8_t> &storage) {
    if (chain.get_dice_ueid(index, storage, /*silent=*/true) == Error::Ok) {
        return &storage;
    }
    return fallback;
}

// Appends the ECTs derived from one certificate's DiceTcbInfo. out_appended
// stays false when the certificate carries no such extension.
Error cert_to_evidence_ects(const X509CertChain &chain, size_t index,
                            const std::vector<uint8_t> *ueid_fallback,
                            std::vector<Ect> &out, bool &out_appended) {
    out_appended = false;
    std::vector<uint8_t> per_cert_ueid;
    const std::vector<uint8_t> *cert_ueid =
        resolve_cert_ueid(chain, index, ueid_fallback, per_cert_ueid);

    MultiDiceTcbInfo multi;
    if (chain.get_multi_dice_tcb_info(index, multi, /*silent=*/true) ==
        Error::Ok) {
        std::vector<Ect> ects;
        Error err = multi_dice_tcb_info_to_ect_list(multi, cert_ueid, ects);
        if (err != Error::Ok) {
            return err;
        }
        for (auto &ect : ects) {
            out.push_back(std::move(ect));
        }
        out_appended = true;
        return Error::Ok;
    }

    for (const std::string *oid :
         {&OID_TCG_DICE_TCB_INFO_ALIAS, &OID_TCG_DICE_TCB_INFO}) {
        DiceTcbInfo dti;
        if (chain.get_dice_tcb_info(index, *oid, dti, /*silent=*/true) !=
            Error::Ok) {
            continue;
        }
        Ect ect;
        Error err = dice_tcb_info_to_ect(dti, cert_ueid, ect);
        if (err != Error::Ok) {
            return err;
        }
        out.push_back(std::move(ect));
        out_appended = true;
        return Error::Ok;
    }
    return Error::Ok;
}

} // namespace

Error x509_chain_to_evidence_ects(const X509CertChain &chain,
                                  const std::vector<uint8_t> *ueid_fallback,
                                  std::vector<Ect> &out,
                                  std::vector<size_t> *out_dti_indices) {
    out.clear();
    if (out_dti_indices != nullptr) {
        out_dti_indices->clear();
    }
    for (size_t i = 0; i < chain.size(); i++) {
        bool appended = false;
        Error err = cert_to_evidence_ects(chain, i, ueid_fallback, out, appended);
        if (err != Error::Ok) {
            out.clear();
            return err;
        }
        if (appended && out_dti_indices != nullptr) {
            out_dti_indices->push_back(i);
        }
    }
    return Error::Ok;
}

Error find_device_cert_index(const std::vector<size_t> &dti_indices,
                             size_t chain_size, size_t &out_index) {
    size_t index = 0;
    while (index < chain_size &&
           std::find(dti_indices.begin(), dti_indices.end(), index) !=
               dti_indices.end()) {
        ++index;
    }
    if (index >= chain_size) {
        return Error::CertNotFound;
    }
    out_index = index;
    return Error::Ok;
}

} // namespace nvattestation
