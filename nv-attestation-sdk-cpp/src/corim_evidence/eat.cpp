/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "nv_attestation/corim_evidence/eat.h"

#include <cstdint>
#include <utility>

#include <nlohmann/json.hpp>

#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"
#include "corim_decode.h"
#include "corim_decode_types.h"
#include "internal/cbor_decode_utils.h"
#include "internal/corim_decoders.h"

namespace nvattestation {

namespace {
// dbgstat (claim 263) is constrained to 0..4 by RFC 9711.
constexpr uint32_t kMaxDbgStat = 4;

// Below this integer key, EAT claims are private/opaque (RFC 9711) and pass
// silently; at or above it an unrecognized key is an unexpected public claim
// worth a warning.
constexpr int64_t kPrivateClaimKeyThreshold = -65536;

const char* content_type_name(uint64_t content_format_id) {
    if (content_format_id == kConciseEvidenceContentFormatId) {
        return kConciseEvidenceMediaType;
    }
    return nullptr;
}

// Deep-copies an optional field held as a raw pointer into a fresh owner.
// Takes a plain pointer (not a unique_ptr) so the helper does not tie itself to
// the caller's ownership type. Allocates into a named owner before returning so
// static analysis can track that the copy is owned (avoids a spurious leak
// diagnostic on a conditional make_unique/nullptr return).
template <typename T>
std::unique_ptr<T> clone_ptr(const T* src) {
    std::unique_ptr<T> copy;
    if (src != nullptr) {
        copy = std::make_unique<T>(*src);
    }
    return copy;
}

std::vector<uint8_t> to_bytes(const zcbor_string& str) {
    return std::vector<uint8_t>(str.value, str.value + str.len);
}

// RFC 9711 profile-type-choice is untagged: major type is the only discriminator.
ProfileValue make_eat_profile(const eat_profile_type_choice& choice) {
    ProfileValue pv;
    if (choice.eat_profile_type_choice_choice == eat_profile_type_choice::eat_profile_type_choice_tstr_c) {
        pv.kind = ProfileKind::Uri;
        pv.value.assign(reinterpret_cast<const char*>(choice.eat_profile_type_choice_tstr.value),
                        choice.eat_profile_type_choice_tstr.len);
    } else {
        pv.kind = ProfileKind::Oid;
        pv.value = oid_dotted_body(choice.eat_profile_type_choice_bstr.value,
                                   choice.eat_profile_type_choice_bstr.len);
    }
    return pv;
}

// JSON tag for an eat_profile value's representation (RFC 9711 profile-type-choice).
const char* profile_kind_name(ProfileKind kind) {
    switch (kind) {
        case ProfileKind::Uri:
            return "uri";
        case ProfileKind::Oid:
            return "oid";
        default:
            return "text";
    }
}

}  // namespace

Eat::Eat(const Eat& other)
    : m_nonce(other.m_nonce)
    , m_dbgstat(clone_ptr(other.m_dbgstat.get()))
    , m_profile(clone_ptr(other.m_profile.get()))
    , m_measurements(other.m_measurements)
    , m_iss(clone_ptr(other.m_iss.get()))
    , m_cti(clone_ptr(other.m_cti.get()))
    , m_ueid(clone_ptr(other.m_ueid.get()))
    , m_sueid(clone_ptr(other.m_sueid.get()))
    , m_hwmodel(clone_ptr(other.m_hwmodel.get()))
    , m_uptime(clone_ptr(other.m_uptime.get()))
    , m_bootcount(clone_ptr(other.m_bootcount.get()))
    , m_bootseed(clone_ptr(other.m_bootseed.get()))
    , m_rim_locators(other.m_rim_locators) {}

Eat& Eat::operator=(const Eat& other) {
    if (this != &other) {
        Eat tmp(other);
        *this = std::move(tmp);
    }
    return *this;
}

// Optional eat-claims-map members. The mandatory ones (nonce 10, eat-profile
// 265, measurements 273) use an expect, so a malformed value fails the decode.
constexpr SchemaKey kEatClaimsSchemaKeys[] = {
    {263, "dbgstat"},  {1, "iss"},        {7, "cti"},         {256, "ueid"},
    {257, "sueid"},    {258, "oemid"},    {259, "hwmodel"},   {261, "uptime"},
    {267, "bootcount"}, {268, "bootseed"}, {-70001, "rim-locators"},
};

Error parse_eat_claims(const std::vector<uint8_t>& payload_bytes, Eat& out_eat) {
    if (payload_bytes.empty()) {
        LOG_ERROR("EAT parse_eat_claims called with empty buffer");
        return Error::EvidenceMalformed;
    }

    std::unique_ptr<eat_claims_map> decoded;
    Error err = decode_cbor(payload_bytes, "EAT claims",
                            cbor_decode_eat_claims_map, decoded,
                            Error::EvidenceMalformed);
    if (err != Error::Ok) {
        LOG_ERROR("EAT zcbor decode of claims-set failed");
        return err;
    }
    const eat_claims_map& claims = *decoded;

    Eat result;

    // --- Mandatory: nonce (10). Missing key => zcbor decode failure above. ---
    result.setNonce(to_bytes(claims.eat_claims_map_nonce));

    // --- Mandatory: eat_profile (265). Parsed as a URI or OID (RFC 9711); the
    //     parser is profile-agnostic — which profile is acceptable is a verifier
    //     policy decision, not a parse-time check. ---
    result.setProfile(std::make_unique<ProfileValue>(
        make_eat_profile(claims.eat_claims_map_eat_profile)));

    // --- Mandatory: measurements (273) ---
    const measurements_type& meas = claims.eat_claims_map_measurements;
    const size_t meas_count = meas.measurements_type_measurements_format_m_count;
    if (meas_count == 0) {
        LOG_ERROR("EAT measurements claim has no entries");
        return Error::EvidenceMalformed;
    }
    std::vector<MeasurementsFormat> measurements;
    measurements.reserve(meas_count);
    for (size_t i = 0; i < meas_count; ++i) {
        const measurements_format& fmt = meas.measurements_type_measurements_format_m[i];
        MeasurementsFormat mf;
        mf.content_format_id = fmt.measurements_format_content_format;
        std::vector<uint8_t> body = to_bytes(fmt.measurements_format_body);
        Error pce = parse_concise_evidence(body, mf.evidence);
        if (pce != Error::Ok) {
            LOG_ERROR("EAT measurements[" << i
                      << "] body is not valid concise-evidence");
            return pce;
        }
        measurements.push_back(std::move(mf));
    }
    result.setMeasurements(std::move(measurements));

    // --- Optional claims ---
    if (claims.eat_claims_map_dbgstat_present) {
        const uint32_t dbg = claims.eat_claims_map_dbgstat.eat_claims_map_dbgstat;
        if (dbg > kMaxDbgStat) {
            LOG_ERROR("EAT dbgstat out of range: " << dbg);
            return Error::BadArgument;
        }
        result.setDebugStatus(
            std::make_unique<DebugStatus>(static_cast<DebugStatus>(dbg)));
    }
    if (claims.eat_claims_map_iss_present) {
        const zcbor_string& iss = claims.eat_claims_map_iss.eat_claims_map_iss;
        result.setIssuer(std::make_unique<std::string>(iss.value, iss.value + iss.len));
    }
    if (claims.eat_claims_map_cti_present) {
        result.setCti(std::make_unique<std::vector<uint8_t>>(
            to_bytes(claims.eat_claims_map_cti.eat_claims_map_cti)));
    }
    if (claims.eat_claims_map_ueid_present) {
        result.setUeid(std::make_unique<std::vector<uint8_t>>(
            to_bytes(claims.eat_claims_map_ueid.eat_claims_map_ueid)));
    }
    if (claims.eat_claims_map_sueid_present) {
        result.setSueid(std::make_unique<std::vector<uint8_t>>(
            to_bytes(claims.eat_claims_map_sueid.eat_claims_map_sueid)));
    }
    if (claims.eat_claims_map_hwmodel_present) {
        result.setHwModel(std::make_unique<std::vector<uint8_t>>(
            to_bytes(claims.eat_claims_map_hwmodel.eat_claims_map_hwmodel)));
    }
    if (claims.eat_claims_map_uptime_present) {
        result.setUptime(std::make_unique<uint64_t>(
            claims.eat_claims_map_uptime.eat_claims_map_uptime));
    }
    if (claims.eat_claims_map_bootcount_present) {
        result.setBootCount(std::make_unique<uint64_t>(
            claims.eat_claims_map_bootcount.eat_claims_map_bootcount));
    }
    if (claims.eat_claims_map_bootseed_present) {
        result.setBootSeed(std::make_unique<std::vector<uint8_t>>(
            to_bytes(claims.eat_claims_map_bootseed.eat_claims_map_bootseed)));
    }
    if (claims.eat_claims_map_rim_locators_present) {
        const auto& locs = claims.eat_claims_map_rim_locators;
        const size_t lcount = locs.eat_claims_map_rim_locators_corim_locator_map_m_count;
        std::vector<CorimLocatorMap> rim_locators;
        rim_locators.reserve(lcount);
        for (size_t i = 0; i < lcount; ++i) {
            CorimLocatorMap loc;
            if (make_corim_locator(
                    &locs.eat_claims_map_rim_locators_corim_locator_map_m[i], loc) == Error::Ok) {
                rim_locators.push_back(std::move(loc));
            }
        }
        result.setRimLocators(std::move(rim_locators));
    }

    // Known claims in the extension array have malformed values.
    if (report_shadowed_keys("EAT", "eat-claims-map", claims.eat_claims_map_intany,
                             claims.eat_claims_map_intany_count,
                             kEatClaimsSchemaKeys)) {
        return Error::EvidenceMalformed;
    }

    // Ignore private claims; debug-log unexpected registered claims.
    for (size_t i = 0; i < claims.eat_claims_map_intany_count; ++i) {
        const int32_t key = claims.eat_claims_map_intany[i].eat_claims_map_intany_key;
        if (key >= kPrivateClaimKeyThreshold) {
            LOG_DEBUG("EAT unknown claim key tolerated: " << key);
        }
    }

    out_eat = std::move(result);
    return Error::Ok;
}

void to_json(nlohmann::json& json_out, const Eat& eat) {
    json_out = nlohmann::json::object();
    json_out["eat_nonce"] = to_hex_string(eat.getNonce());
    if (eat.getProfile() != nullptr) {
        const ProfileValue& profile = *eat.getProfile();
        json_out["eat_profile"] = {{"kind", profile_kind_name(profile.kind)}, {"value", profile.value}};
    }

    nlohmann::json measurements = nlohmann::json::array();
    for (const auto& mf : eat.getMeasurements()) {
        nlohmann::json mj = nlohmann::json::object();
        const char* content_type = content_type_name(mf.content_format_id);
        if (content_type != nullptr) {
            mj["content-type"] = content_type;
        } else {
            mj["content-type"] = mf.content_format_id;
        }
        nlohmann::json ev;
        to_json(ev, mf.evidence);
        mj["evidence"] = std::move(ev);
        measurements.push_back(std::move(mj));
    }
    json_out["measurements"] = std::move(measurements);

    if (eat.getDebugStatus() != nullptr) {
        json_out["dbgstat"] = static_cast<int>(*eat.getDebugStatus());
    }
    if (eat.getIssuer() != nullptr) {
        json_out["iss"] = *eat.getIssuer();
    }
    if (eat.getCti() != nullptr) {
        json_out["cti"] = to_hex_string(*eat.getCti());
    }
    if (eat.getUeid() != nullptr) {
        json_out["ueid"] = to_hex_string(*eat.getUeid());
    }
    if (eat.getSueid() != nullptr) {
        json_out["sueid"] = to_hex_string(*eat.getSueid());
    }
    if (eat.getHwModel() != nullptr) {
        json_out["hwmodel"] = to_hex_string(*eat.getHwModel());
    }
    if (eat.getUptime() != nullptr) {
        json_out["uptime"] = *eat.getUptime();
    }
    if (eat.getBootCount() != nullptr) {
        json_out["bootcount"] = *eat.getBootCount();
    }
    if (eat.getBootSeed() != nullptr) {
        json_out["bootseed"] = to_hex_string(*eat.getBootSeed());
    }

    if (!eat.getRimLocators().empty()) {
        nlohmann::json locs = nlohmann::json::array();
        for (const auto& loc : eat.getRimLocators()) {
            nlohmann::json lj;
            to_json(lj, loc);
            locs.push_back(std::move(lj));
        }
        json_out["rim_locators"] = std::move(locs);
    }
}

}  // namespace nvattestation
