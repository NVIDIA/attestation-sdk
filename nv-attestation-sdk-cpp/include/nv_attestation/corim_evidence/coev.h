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
#pragma once

#include "nv_attestation/corim.h"
#include "nv_attestation/error.h"
// SpdmIndirectMap lives in its own header to let MeasurementValues
// (in corim.h) hold a unique_ptr<SpdmIndirectMap> without a circular include.
#include "nv_attestation/spdm_indirect_map.h"

namespace nvattestation {

// IANA CoAP Content-Formats registry entry for TCG DICE concise-evidence.
constexpr uint64_t kConciseEvidenceContentFormatId = 10571;
constexpr const char* kConciseEvidenceMediaType = "application/ce+cbor";

// TCG DICE §6.3.1 corim-locator-map: a RIM locator referenced from
// spdm-toc-map.rim-locators. The wrapper carries both URIs (single or
// multi) and any thumbprints; integrity verification of a fetched CoRIM
// against the thumbprint is the fetcher's responsibility, not the parser's.
class CorimLocatorMap {
public:
    CorimLocatorMap() = default;
    explicit CorimLocatorMap(std::vector<std::string> uris,
                             std::vector<Digest> thumbprints = {});
    CorimLocatorMap(const CorimLocatorMap&) = default;
    CorimLocatorMap(CorimLocatorMap&&) = default;
    CorimLocatorMap& operator=(const CorimLocatorMap&) = default;
    CorimLocatorMap& operator=(CorimLocatorMap&&) = default;

    const std::vector<std::string>& getUris() const { return m_uris; }
    const std::vector<Digest>& getThumbprints() const { return m_thumbprints; }

private:
    std::vector<std::string> m_uris;
    std::vector<Digest> m_thumbprints;
};

void to_json(nlohmann::json& json_out, const CorimLocatorMap& v);

// TCG DICE §6.3.2 evidence-triple-record: [environment-map, [+measurement-map]].
// Reuses EnvironmentMap and MeasurementMap from corim.h.
class EvidenceTripleRecord {
public:
    EvidenceTripleRecord() = default;
    EvidenceTripleRecord(EnvironmentMap env, std::vector<MeasurementMap> measurements);
    EvidenceTripleRecord(const EvidenceTripleRecord&) = default;
    EvidenceTripleRecord(EvidenceTripleRecord&&) = default;
    EvidenceTripleRecord& operator=(const EvidenceTripleRecord&) = default;
    EvidenceTripleRecord& operator=(EvidenceTripleRecord&&) = default;

    const EnvironmentMap& getEnvironment() const { return m_environment; }
    const std::vector<MeasurementMap>& getMeasurements() const { return m_measurements; }

private:
    EnvironmentMap m_environment;
    std::vector<MeasurementMap> m_measurements;
};

void to_json(nlohmann::json& json_out, const EvidenceTripleRecord& v);

// TCG DICE §6.3.2 ev-triples-map. Only evidence-triples is surfaced; other
// triple types (identity/dependency/membership/coswid/attest-key) parse
// successfully but the parser drops them with a warn-log.
class EvTriples {
public:
    EvTriples() = default;
    explicit EvTriples(std::vector<EvidenceTripleRecord> records);
    EvTriples(const EvTriples&) = default;
    EvTriples(EvTriples&&) = default;
    EvTriples& operator=(const EvTriples&) = default;
    EvTriples& operator=(EvTriples&&) = default;

    const std::vector<EvidenceTripleRecord>& getEvidenceTriples() const { return m_evidence_triples; }

private:
    std::vector<EvidenceTripleRecord> m_evidence_triples;
};

void to_json(nlohmann::json& json_out, const EvTriples& v);

// TCG DICE §6.3.2 concise-evidence-map.
class ConciseEvidence {
public:
    ConciseEvidence() = default;
    ~ConciseEvidence() = default;
    explicit ConciseEvidence(EvTriples triples,
                             std::unique_ptr<std::string> evidence_id = nullptr,
                             std::unique_ptr<ProfileValue> profile = nullptr);
    ConciseEvidence(const ConciseEvidence& other);
    ConciseEvidence(ConciseEvidence&&) = default;
    ConciseEvidence& operator=(const ConciseEvidence& other);
    ConciseEvidence& operator=(ConciseEvidence&&) = default;

    const EvTriples& getEvTriples() const { return m_ev_triples; }
    const std::string* getEvidenceId() const { return m_evidence_id.get(); }
    const ProfileValue* getProfile() const { return m_profile.get(); }

private:
    EvTriples m_ev_triples;
    std::unique_ptr<std::string> m_evidence_id;
    std::unique_ptr<ProfileValue> m_profile;
};

void to_json(nlohmann::json& json_out, const ConciseEvidence& v);

// TCG DICE §6.3.1 spdm-toc-map.
class SpdmToc {
public:
    SpdmToc() = default;
    ~SpdmToc() = default;
    explicit SpdmToc(std::vector<ConciseEvidence> evidence,
                     std::vector<CorimLocatorMap> rim_locators = {},
                     std::unique_ptr<ProfileValue> profile = nullptr);
    SpdmToc(const SpdmToc& other);
    SpdmToc(SpdmToc&&) = default;
    SpdmToc& operator=(const SpdmToc& other);
    SpdmToc& operator=(SpdmToc&&) = default;

    const std::vector<ConciseEvidence>& getEvidence() const { return m_evidence; }
    const std::vector<CorimLocatorMap>& getRimLocators() const { return m_rim_locators; }
    const ProfileValue* getProfile() const { return m_profile.get(); }

private:
    std::vector<ConciseEvidence> m_evidence;
    std::vector<CorimLocatorMap> m_rim_locators;
    std::unique_ptr<ProfileValue> m_profile;
};

void to_json(nlohmann::json& json_out, const SpdmToc& v);

// =====================================================================
// Parser entry points
// =====================================================================

// Parse a Concise Evidence blob, tagged (#6.571) or bare. Returns Error::BadArgument
// on a zcbor decode failure or an empty ev-triples-map (spec requires at
// least one triple type). Unsupported fields are permissively skipped
// with a warn-log. `out` is undefined unless Error::Ok is returned.
Error parse_concise_evidence(
    const std::vector<uint8_t>& bytes,
    ConciseEvidence& out);

// Parse a #6.570-tagged SPDM Table-of-Contents blob (the manifest a
// Responder returns from SPDM GET_MEASUREMENTS at L=0xFD). Each contained
// tagged-concise-evidence is decoded recursively. Returns
// Error::BadArgument on a zcbor decode failure or empty tagged-evidence.
Error parse_spdm_toc(
    const std::vector<uint8_t>& bytes,
    SpdmToc& out);

}  // namespace nvattestation
