/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

#include "nv_attestation/error.h"
#include "nv_attestation/corim.h"                // ProfileValue
#include "nv_attestation/corim_evidence/coev.h"  // ConciseEvidence, CorimLocatorMap

namespace nvattestation {

// RFC 9711 dbgstat values (claim 263).
enum class DebugStatus {
    Enabled = 0,
    Disabled = 1,
    DisabledSinceBoot = 2,
    DisabledPermanently = 3,
    DisabledFullyAndPermanently = 4,
};

// One entry of the measurements claim (273): a CoAP content-format id plus the
// concise-evidence parsed from the entry body.
struct MeasurementsFormat {
    uint64_t content_format_id = 0;
    ConciseEvidence evidence;
};

// Parsed OCP-profile EAT claims-set. Owns all data (no zcbor types, no pointers
// into source buffers). Optionals are unique_ptr (nullptr = absent) or empty
// vectors, matching the corim.h / coev.h convention.
class Eat {
public:
    Eat() = default;
    ~Eat() = default;
    Eat(const Eat& other);
    Eat(Eat&&) = default;
    Eat& operator=(const Eat& other);
    Eat& operator=(Eat&&) = default;

    // Mandatory claims.
    const std::vector<uint8_t>& getNonce() const { return m_nonce; }
    const ProfileValue* getProfile() const { return m_profile.get(); }
    const std::vector<MeasurementsFormat>& getMeasurements() const { return m_measurements; }

    // Optional claims (nullptr / empty = absent).
    const DebugStatus* getDebugStatus() const { return m_dbgstat.get(); }
    const std::string* getIssuer() const { return m_iss.get(); }
    const std::vector<uint8_t>* getCti() const { return m_cti.get(); }
    const std::vector<uint8_t>* getUeid() const { return m_ueid.get(); }
    const std::vector<uint8_t>* getSueid() const { return m_sueid.get(); }
    const std::vector<uint8_t>* getHwModel() const { return m_hwmodel.get(); }
    const uint64_t* getUptime() const { return m_uptime.get(); }
    const uint64_t* getBootCount() const { return m_bootcount.get(); }
    const std::vector<uint8_t>* getBootSeed() const { return m_bootseed.get(); }
    const std::vector<CorimLocatorMap>& getRimLocators() const { return m_rim_locators; }

    // Mutators used by the parser (kept public for the free-function parser;
    // mirrors how coev.cpp populates wrappers).
    void setNonce(std::vector<uint8_t> v) { m_nonce = std::move(v); }
    void setDebugStatus(std::unique_ptr<DebugStatus> v) { m_dbgstat = std::move(v); }
    void setProfile(std::unique_ptr<ProfileValue> v) { m_profile = std::move(v); }
    void setMeasurements(std::vector<MeasurementsFormat> v) { m_measurements = std::move(v); }
    void setIssuer(std::unique_ptr<std::string> v) { m_iss = std::move(v); }
    void setCti(std::unique_ptr<std::vector<uint8_t>> v) { m_cti = std::move(v); }
    void setUeid(std::unique_ptr<std::vector<uint8_t>> v) { m_ueid = std::move(v); }
    void setSueid(std::unique_ptr<std::vector<uint8_t>> v) { m_sueid = std::move(v); }
    void setHwModel(std::unique_ptr<std::vector<uint8_t>> v) { m_hwmodel = std::move(v); }
    void setUptime(std::unique_ptr<uint64_t> v) { m_uptime = std::move(v); }
    void setBootCount(std::unique_ptr<uint64_t> v) { m_bootcount = std::move(v); }
    void setBootSeed(std::unique_ptr<std::vector<uint8_t>> v) { m_bootseed = std::move(v); }
    void setRimLocators(std::vector<CorimLocatorMap> v) { m_rim_locators = std::move(v); }

private:
    std::vector<uint8_t> m_nonce;
    std::unique_ptr<DebugStatus> m_dbgstat;
    std::unique_ptr<ProfileValue> m_profile;
    std::vector<MeasurementsFormat> m_measurements;

    std::unique_ptr<std::string> m_iss;
    std::unique_ptr<std::vector<uint8_t>> m_cti;
    std::unique_ptr<std::vector<uint8_t>> m_ueid;
    std::unique_ptr<std::vector<uint8_t>> m_sueid;
    std::unique_ptr<std::vector<uint8_t>> m_hwmodel;
    std::unique_ptr<uint64_t> m_uptime;
    std::unique_ptr<uint64_t> m_bootcount;
    std::unique_ptr<std::vector<uint8_t>> m_bootseed;
    std::vector<CorimLocatorMap> m_rim_locators;
};

void to_json(nlohmann::json& json_out, const Eat& eat);

// Pure CBOR -> class. Parses the CWT claims-set payload (the COSE_Sign1 payload
// bstr). Returns Error::EvidenceMalformed on EAT CBOR/schema failure, including
// missing mandatory claims (10/265/273) and an out-of-range dbgstat (263).
// Errors from parsing measurements bodies are propagated. Unknown claims are
// tolerated: private/opaque keys pass silently; unexpected public keys are
// debug-logged. `out_eat` is modified only when Error::Ok is returned.
//
// This entry point does NOT verify a COSE signature or strip the CWT/self-
// described-CBOR tag stack; see eat_cwt.h (verify_and_parse_eat_cwt) for the
// signed-token path.
Error parse_eat_claims(const std::vector<uint8_t>& payload_bytes, Eat& out_eat);

}  // namespace nvattestation
