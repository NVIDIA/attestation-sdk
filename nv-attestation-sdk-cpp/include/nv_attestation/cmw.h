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

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "nv_attestation/error.h"

namespace nvattestation {

constexpr const char *kCmwInputProfile =
    "tag:nvidia.com,2026:verifier-input/profiles/base/pre-1.0.0";
constexpr const char *kCmwEvidenceItemProfile =
    "tag:nvidia.com,2026:evidence-item/v1";

constexpr const char *kCmwMediaOctetStream = "application/octet-stream";
constexpr const char *kCmwMediaJson = "application/json";
constexpr const char *kCmwMediaPemCertChain =
    "application/vnd.nvidia.pem-cert-chain";
constexpr const char *kCmwMediaSpdmTranscript =
    "application/vnd.nvidia.spdm-measurement-transcript";
// RFC 9711 EAT, CWT-encoded (RFC 8392). Signed: #6.18(COSE_Sign1), optionally
// wrapped in tag 61 and/or tag 55799. Unsigned: bare claims-set CBOR map.
constexpr const char *kCmwMediaEatCwt = "application/eat+cwt";

enum class CmwFormat {
    kJson = 0,
    // TODO(v2): CBOR. Currently returns Error::FeatureNotEnabled.
    kCbor = 1,
};

struct CmwRecord {
    std::string media_type;
    std::vector<uint8_t> value;

    CmwRecord() = default;
    CmwRecord(std::string mt, std::vector<uint8_t> v)
        : media_type(std::move(mt)), value(std::move(v)) {}
};

// The label (e.g. "gpu_1") is held by the parent CmwCollection.
struct CmwEvidenceItem {
    CmwRecord evidence;
    // Optional challenge nonce (empty = absent); freshness-checked when present.
    std::vector<uint8_t> nonce;
    // nullptr when absent; some evidence types embed the chain in the payload.
    std::unique_ptr<CmwRecord> certificate;
    // nullptr when absent. Untrusted, caller-supplied key-value bundle.
    std::unique_ptr<CmwRecord> hints;
};

class CmwCollection {
  public:
    CmwCollection() = default;

    void set_nonce(std::vector<uint8_t> nonce_bytes) {
        m_nonce = std::move(nonce_bytes);
    }
    const std::vector<uint8_t> &nonce() const { return m_nonce; }

    void set_appraisal_settings(std::vector<uint8_t> settings) {
        m_appraisal_settings = std::move(settings);
    }
    // Decoded appraisal-settings JSON; empty when the field is absent.
    const std::vector<uint8_t> &appraisal_settings() const {
        return m_appraisal_settings;
    }

    void add_evidence_item(std::string label, CmwEvidenceItem item) {
        m_items.emplace_back(std::move(label), std::move(item));
    }
    const std::vector<std::pair<std::string, CmwEvidenceItem>> &
    evidence_items() const {
        return m_items;
    }

    // Bytes: JSON is UTF-8 text, CBOR is binary. CBOR: FeatureNotEnabled.
    Error serialize(CmwFormat format, std::vector<uint8_t> &out_serialized) const;

    // Parse and validate the wire format. CBOR returns FeatureNotEnabled.
    static Error parse(const uint8_t *data, std::size_t length,
                       CmwFormat format, CmwCollection &out_collection);

  private:
    std::vector<uint8_t> m_nonce;
    std::vector<uint8_t> m_appraisal_settings;
    std::vector<std::pair<std::string, CmwEvidenceItem>> m_items;
};

} // namespace nvattestation
