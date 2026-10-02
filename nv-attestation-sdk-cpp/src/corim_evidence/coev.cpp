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
#include "nv_attestation/corim_evidence/coev.h"

#include <array>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "nv_attestation/log.h"
#include "corim_decode.h"
#include "corim_decode_types.h"
#include "internal/cbor_decode_utils.h"
#include "internal/corim_decoders.h"
#include "zcbor_print.h"

namespace nvattestation {

SpdmIndirectMap::SpdmIndirectMap(std::vector<uint64_t> indexes)
    : m_indexes(std::move(indexes)) {}

void to_json(nlohmann::json& json_out, const SpdmIndirectMap& val) {
    json_out = nlohmann::json::object();
    json_out["indexes"] = val.getIndexes();
}

CorimLocatorMap::CorimLocatorMap(std::vector<std::string> uris,
                                 std::vector<Digest> thumbprints)
    : m_uris(std::move(uris)), m_thumbprints(std::move(thumbprints)) {}

void to_json(nlohmann::json& json_out, const CorimLocatorMap& val) {
    json_out = nlohmann::json::object();
    nlohmann::json uris = nlohmann::json::array();
    for (const auto& uri : val.getUris()) {
        uris.push_back(uri);
    }
    json_out["uris"] = std::move(uris);
    if (!val.getThumbprints().empty()) {
        nlohmann::json thumbprints = nlohmann::json::array();
        for (const auto& dig : val.getThumbprints()) {
            nlohmann::json dj;
            to_json(dj, dig);
            thumbprints.push_back(std::move(dj));
        }
        json_out["thumbprints"] = std::move(thumbprints);
    }
}

EvidenceTripleRecord::EvidenceTripleRecord(EnvironmentMap env,
                                           std::vector<MeasurementMap> measurements)
    : m_environment(std::move(env)), m_measurements(std::move(measurements)) {}

void to_json(nlohmann::json& json_out, const EvidenceTripleRecord& val) {
    json_out = nlohmann::json::object();
    to_json(json_out["environment"], val.getEnvironment());
    nlohmann::json measurements = nlohmann::json::array();
    for (const auto& meas : val.getMeasurements()) {
        nlohmann::json mj;
        to_json(mj, meas);
        measurements.push_back(std::move(mj));
    }
    json_out["measurements"] = std::move(measurements);
}

EvTriples::EvTriples(std::vector<EvidenceTripleRecord> records)
    : m_evidence_triples(std::move(records)) {}

void to_json(nlohmann::json& json_out, const EvTriples& val) {
    json_out = nlohmann::json::object();
    nlohmann::json records = nlohmann::json::array();
    for (const auto& rec : val.getEvidenceTriples()) {
        nlohmann::json rj;
        to_json(rj, rec);
        records.push_back(std::move(rj));
    }
    json_out["evidence_triples"] = std::move(records);
}

ConciseEvidence::ConciseEvidence(EvTriples triples,
                                 std::unique_ptr<std::string> evidence_id,
                                 std::unique_ptr<ProfileValue> profile)
    : m_ev_triples(std::move(triples))
    , m_evidence_id(std::move(evidence_id))
    , m_profile(std::move(profile)) {}

ConciseEvidence::ConciseEvidence(const ConciseEvidence& other)
    : m_ev_triples(other.m_ev_triples)
    , m_evidence_id(other.m_evidence_id
        ? std::make_unique<std::string>(*other.m_evidence_id)
        : nullptr)
    , m_profile(other.m_profile
        ? std::make_unique<ProfileValue>(*other.m_profile)
        : nullptr) {}

ConciseEvidence& ConciseEvidence::operator=(const ConciseEvidence& other) {
    if (this != &other) {
        ConciseEvidence tmp(other);
        *this = std::move(tmp);
    }
    return *this;
}

void to_json(nlohmann::json& json_out, const ConciseEvidence& val) {
    json_out = nlohmann::json::object();
    to_json(json_out["ev_triples"], val.getEvTriples());
    if (val.getEvidenceId() != nullptr) {
        json_out["evidence_id"] = *val.getEvidenceId();
    }
    if (const ProfileValue* profile = val.getProfile()) {
        json_out["profile"] = profile_value_to_string(*profile);
    }
}

SpdmToc::SpdmToc(std::vector<ConciseEvidence> evidence,
                 std::vector<CorimLocatorMap> rim_locators,
                 std::unique_ptr<ProfileValue> profile)
    : m_evidence(std::move(evidence))
    , m_rim_locators(std::move(rim_locators))
    , m_profile(std::move(profile)) {}

SpdmToc::SpdmToc(const SpdmToc& other)
    : m_evidence(other.m_evidence)
    , m_rim_locators(other.m_rim_locators)
    , m_profile(other.m_profile
        ? std::make_unique<ProfileValue>(*other.m_profile)
        : nullptr) {}

SpdmToc& SpdmToc::operator=(const SpdmToc& other) {
    if (this != &other) {
        SpdmToc tmp(other);
        *this = std::move(tmp);
    }
    return *this;
}

// zcbor struct -> wrapper helpers (make_digest, make_measurement_map, ...)
// are shared with the CoRIM parser via src/internal/corim_decoders.h.
// CoEV passes Strictness::Permissive so unsupported fields warn-log and
// skip rather than failing the parse.

namespace {

// RFC 9277 TN-derived tag heads. We detect these as a 5-byte CBOR prefix
// so callers see a precise error rather than a generic zcbor failure if
// a producer ever emits the TN form instead of #6.570 / #6.571.
constexpr std::array<uint8_t, 5> TN_SPDM_TOC         = {0xDA, 0x63, 0x74, 0x2A, 0x74};  // 1668557428
constexpr std::array<uint8_t, 5> TN_CONCISE_EVIDENCE = {0xDA, 0x63, 0x74, 0x2A, 0x75};  // 1668557429

template <size_t N>
bool starts_with(const std::vector<uint8_t>& bytes, const std::array<uint8_t, N>& prefix) {
    if (bytes.size() < N) {
        return false;
    }
    for (size_t i = 0; i < N; ++i) {
        if (bytes[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}

constexpr SchemaKey kEvTriplesSchemaKeys[] = {
    {0, "evidence-triples"},   {1, "identity-triples"},
    {2, "dependency-triples"}, {3, "membership-triples"},
    {4, "coswid-triples"},     {5, "attest-key-triples"},
};

// Only optional members can be shadowed. A mandatory one is decoded with an
// expect rather than a present_decode, so a malformed value fails the whole map
// decode instead of backtracking into the extension array. That is why
// spdm-toc-map.tagged-evidence and concise-evidence-map.ev-triples — both key 0
// and both mandatory — are omitted from the arrays below.
constexpr SchemaKey kSpdmTocSchemaKeys[] = {
    {1, "rim-locators"}, {2, "profile"},
};

constexpr SchemaKey kConciseEvidenceSchemaKeys[] = {
    {1, "evidence-id"}, {2, "profile"},
};

// One overload per decoded map, each pairing that map's extension array with
// its own key table, so callers just ask "did this map shadow anything?".
bool report_shadowed_keys(const ev_triples_map* map) {
    return report_shadowed_keys("CoEV", "ev-triples-map", map->ev_triples_map_intany,
                                map->ev_triples_map_intany_count,
                                kEvTriplesSchemaKeys);
}

bool report_shadowed_keys(const spdm_toc_map* map) {
    return report_shadowed_keys("CoEV", "spdm-toc-map", map->spdm_toc_map_intany,
                                map->spdm_toc_map_intany_count,
                                kSpdmTocSchemaKeys);
}

bool report_shadowed_keys(const concise_evidence_map* map) {
    return report_shadowed_keys("CoEV", "concise-evidence-map",
                                map->concise_evidence_map_intany,
                                map->concise_evidence_map_intany_count,
                                kConciseEvidenceSchemaKeys);
}

// Surfaces evidence-triples; warn-skips the other five triple types.
// A completely empty ev-triples-map (no triple type populated) is
// rejected per TCG DICE Concise Evidence Binding for SPDM §6.3.2.
Error walk_ev_triples(const ev_triples_map* ptr, EvTriples& out) {
    // Must run before the emptiness check below: a malformed evidence-triples
    // is indistinguishable from an absent one by the *_present flags alone.
    if (report_shadowed_keys(ptr)) {
        return Error::EvidenceMalformed;
    }
    if (ptr->ev_triples_map_identity_triples_present) {
        LOG_WARN("CoEV: permissive skip: ev-triples-map.identity-triples (key 1) not surfaced");
    }
    if (ptr->ev_triples_map_dependency_triples_present) {
        LOG_WARN("CoEV: permissive skip: ev-triples-map.dependency-triples (key 2) not surfaced");
    }
    if (ptr->ev_triples_map_membership_triples_present) {
        LOG_WARN("CoEV: permissive skip: ev-triples-map.membership-triples (key 3) not surfaced");
    }
    if (ptr->ev_triples_map_coswid_triples_present) {
        LOG_WARN("CoEV: permissive skip: ev-triples-map.coswid-triples (key 4) not surfaced");
    }
    if (ptr->ev_triples_map_attest_key_triples_present) {
        LOG_WARN("CoEV: permissive skip: ev-triples-map.attest-key-triples (key 5) not surfaced");
    }
    bool any_triple_present =
        ptr->ev_triples_map_evidence_triples_present
        || ptr->ev_triples_map_identity_triples_present
        || ptr->ev_triples_map_dependency_triples_present
        || ptr->ev_triples_map_membership_triples_present
        || ptr->ev_triples_map_coswid_triples_present
        || ptr->ev_triples_map_attest_key_triples_present;
    if (!any_triple_present) {
        LOG_ERROR("CoEV ev-triples-map is empty: at least one triple type must be populated");
        return Error::EvidenceMalformed;
    }
    std::vector<EvidenceTripleRecord> records;
    if (ptr->ev_triples_map_evidence_triples_present) {
        const auto& trips = ptr->ev_triples_map_evidence_triples;
        size_t count = trips.ev_triples_map_evidence_triples_evidence_triple_record_m_count;
        records.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            const auto& rec = trips.ev_triples_map_evidence_triples_evidence_triple_record_m[i];
            EnvironmentMap env = make_environment_map(&rec.evidence_triple_record_environment_map_m);
            std::vector<MeasurementMap> measurements;
            size_t mcount = rec.evidence_triple_record_measurement_map_m_l_measurement_map_m_count;
            measurements.reserve(mcount);
            for (size_t j = 0; j < mcount; ++j) {
                measurements.push_back(
                    make_measurement_map(&rec.evidence_triple_record_measurement_map_m_l_measurement_map_m[j], Strictness::Permissive));
            }
            records.emplace_back(std::move(env), std::move(measurements));
        }
    }
    out = EvTriples(std::move(records));
    return Error::Ok;
}

// Shared by parse_concise_evidence and the per-element loop inside
// parse_spdm_toc (each spdm-toc-map.tagged-evidence entry is a
// concise-evidence-map).
Error convert_concise_evidence(const concise_evidence_map* ce_map, ConciseEvidence& out) {
    // ev-triples (key 0) is mandatory, so the decoder hard-fails on it rather
    // than backtracking; only evidence-id and profile can be silently dropped.
    // Checked here rather than in the callers so both parse_concise_evidence
    // and the per-element loop in parse_spdm_toc are covered.
    if (report_shadowed_keys(ce_map)) {
        return Error::EvidenceMalformed;
    }
    EvTriples triples;
    Error err = walk_ev_triples(&ce_map->concise_evidence_map_ev_triples, triples);
    if (err != Error::Ok) {
        return err;
    }
    std::unique_ptr<std::string> evidence_id;
    if (ce_map->concise_evidence_map_evidence_id_present) {
        const auto& eid = ce_map->concise_evidence_map_evidence_id.concise_evidence_map_evidence_id;
        evidence_id = std::make_unique<std::string>(format_uuid(eid.value, eid.len));
    }
    std::unique_ptr<ProfileValue> profile;
    if (ce_map->concise_evidence_map_profile_present) {
        profile = std::make_unique<ProfileValue>(
            make_profile(&ce_map->concise_evidence_map_profile.concise_evidence_map_profile));
    }
    out = ConciseEvidence(std::move(triples), std::move(evidence_id), std::move(profile));
    return Error::Ok;
}

}  // namespace

// Converts a generated corim-locator-map into the CorimLocatorMap wrapper
// (corim-href URI single/list + optional corim-thumbprint). Declared in
// internal/corim_decoders.h and shared by the CoEV and EAT parsers.
Error make_corim_locator(const corim_locator_map* loc, CorimLocatorMap& out_locator) {
    std::vector<std::string> uris{};
    switch (loc->corim_locator_map_corim_href_choice) {
        case corim_locator_map::corim_locator_map_corim_href_uri_m_c: {
            const auto& zstr = loc->corim_locator_map_corim_href_uri_m;
            uris.emplace_back(zstr.value, zstr.value + zstr.len);
            break;
        }
        case corim_locator_map::corim_href_uri_m_l_c: {
            const size_t count = loc->corim_href_uri_m_l_uri_m_count;
            uris.reserve(count);
            for (size_t i = 0; i < count; ++i) {
                const auto& zstr = loc->corim_href_uri_m_l_uri_m[i];
                uris.emplace_back(zstr.value, zstr.value + zstr.len);
            }
            break;
        }
    }
    std::vector<Digest> thumbprints{};
    if (loc->corim_locator_map_corim_thumbprint_present) {
        const auto& thumb = loc->corim_locator_map_corim_thumbprint;
        switch (thumb.corim_locator_map_corim_thumbprint_choice) {
            case corim_locator_map_corim_thumbprint_r::corim_locator_map_corim_thumbprint_digest_m_c:
                thumbprints.push_back(make_digest(&thumb.corim_locator_map_corim_thumbprint_digest_m));
                break;
            case corim_locator_map_corim_thumbprint_r::corim_thumbprint_digest_m_l_digest_m_c:
                thumbprints.push_back(make_digest(&thumb.corim_thumbprint_digest_m_l_digest_m));
                break;
        }
    }
    out_locator = CorimLocatorMap(std::move(uris), std::move(thumbprints));
    return Error::Ok;
}

Error parse_concise_evidence(const std::vector<uint8_t>& bytes, ConciseEvidence& out) {
    if (bytes.empty()) {
        LOG_ERROR("CoEV parse_concise_evidence called with empty buffer");
        return Error::EvidenceMalformed;
    }
    if (starts_with(bytes, TN_CONCISE_EVIDENCE)) {
        LOG_ERROR("CoEV uses unsupported RFC 9277 TN() CBOR tag: 1668557429 (only #6.571 is supported)");
        return Error::EvidenceMalformed;
    }

    std::unique_ptr<concise_evidence> decoded;
    // concise-evidence = concise-evidence-map / tagged-concise-evidence (#6.571).
    // Permissive: accepts both the untagged map (e.g. EAT-embedded evidence,
    // where content-format 10571 already declares the type) and the #6.571-
    // tagged form (e.g. standalone/CoRIM-locator-fetched CoEV artifacts).
    const Error err = decode_cbor(bytes, "concise-evidence", cbor_decode_concise_evidence,
                                  decoded, Error::EvidenceMalformed);
    if (err != Error::Ok) {
        return err;
    }

    const concise_evidence_map* ce_map =
        (decoded->concise_evidence_choice == concise_evidence::tagged_concise_evidence_m_c)
            ? &decoded->tagged_concise_evidence_m
            : &decoded->concise_evidence_map_m;
    try {
        return convert_concise_evidence(ce_map, out);
    } catch (const UnsupportedCorimFeatureException& e) {
        LOG_ERROR(e.what());
        return Error::EvidenceMalformed;
    }
}

Error parse_spdm_toc(const std::vector<uint8_t>& bytes, SpdmToc& out) {
    if (bytes.empty()) {
        LOG_ERROR("CoEV parse_spdm_toc called with empty buffer");
        return Error::EvidenceMalformed;
    }
    if (starts_with(bytes, TN_SPDM_TOC)) {
        LOG_ERROR("CoEV uses unsupported RFC 9277 TN() CBOR tag: 1668557428 (only #6.570 is supported)");
        return Error::EvidenceMalformed;
    }

    std::unique_ptr<spdm_toc_map> decoded(new spdm_toc_map{});
    size_t consumed = 0;
    int rc = cbor_decode_tagged_spdm_toc(bytes.data(), bytes.size(), decoded.get(), &consumed);
    if (rc != ZCBOR_SUCCESS) {
        LOG_ERROR("CoEV zcbor decode of tagged-spdm-toc failed: rc="
                  << rc << " (" << zcbor_error_str(rc)
                  << ") after consuming " << consumed << " of " << bytes.size()
                  << " bytes");
        return Error::EvidenceMalformed;
    }
    if (consumed != bytes.size()) {
        LOG_ERROR("CoEV tagged-spdm-toc decoder consumed " << consumed
                  << " bytes of " << bytes.size()
                  << " (" << (bytes.size() - consumed) << " trailing)");
        return Error::EvidenceMalformed;
    }
    const spdm_toc_map* tm = decoded.get();

    // rim-locators and profile are optional, so a malformed value for either
    // decodes as "absent" rather than as an error. Left unchecked, a bad
    // rim-locators yields zero RIM URLs and the failure only surfaces later,
    // as an unexplained inability to locate reference values.
    if (report_shadowed_keys(tm)) {
        return Error::EvidenceMalformed;
    }

    size_t te_count = tm->spdm_toc_map_tagged_evidence_tagged_concise_evidence_m_count;
    if (te_count == 0) {
        LOG_ERROR("CoEV spdm-toc-map.tagged-evidence is empty: at least one concise-evidence required");
        return Error::EvidenceMalformed;
    }

    std::vector<ConciseEvidence> evidence;
    evidence.reserve(te_count);
    try {
        for (size_t i = 0; i < te_count; ++i) {
            const concise_evidence_map* ce_map = &tm->spdm_toc_map_tagged_evidence_tagged_concise_evidence_m[i];
            ConciseEvidence ce;
            Error err = convert_concise_evidence(ce_map, ce);
            if (err != Error::Ok) {
                return err;
            }
            evidence.push_back(std::move(ce));
        }
        std::vector<CorimLocatorMap> rim_locators;
        if (tm->spdm_toc_map_rim_locators_present) {
            const auto& locators_arr = tm->spdm_toc_map_rim_locators;
            size_t lcount = locators_arr.spdm_toc_map_rim_locators_corim_locator_map_m_count;
            rim_locators.reserve(lcount);
            for (size_t i = 0; i < lcount; ++i) {
                CorimLocatorMap loc;
                Error err = make_corim_locator(
                    &locators_arr.spdm_toc_map_rim_locators_corim_locator_map_m[i], loc);
                if (err != Error::Ok) {
                    return err;
                }
                rim_locators.push_back(std::move(loc));
            }
        }
        std::unique_ptr<ProfileValue> profile;
        if (tm->spdm_toc_map_profile_present) {
            profile = std::make_unique<ProfileValue>(
                make_profile(&tm->spdm_toc_map_profile.spdm_toc_map_profile));
        }
        out = SpdmToc(std::move(evidence), std::move(rim_locators), std::move(profile));
        return Error::Ok;
    } catch (const UnsupportedCorimFeatureException& e) {
        LOG_ERROR(e.what());
        return Error::EvidenceMalformed;
    }
}

void to_json(nlohmann::json& json_out, const SpdmToc& val) {
    json_out = nlohmann::json::object();
    nlohmann::json evidence = nlohmann::json::array();
    for (const auto& ce : val.getEvidence()) {
        nlohmann::json cej;
        to_json(cej, ce);
        evidence.push_back(std::move(cej));
    }
    json_out["evidence"] = std::move(evidence);
    if (!val.getRimLocators().empty()) {
        nlohmann::json locators = nlohmann::json::array();
        for (const auto& loc : val.getRimLocators()) {
            nlohmann::json lj;
            to_json(lj, loc);
            locators.push_back(std::move(lj));
        }
        json_out["rim_locators"] = std::move(locators);
    }
    if (const ProfileValue* profile = val.getProfile()) {
        json_out["profile"] = profile_value_to_string(*profile);
    }
}

}  // namespace nvattestation
