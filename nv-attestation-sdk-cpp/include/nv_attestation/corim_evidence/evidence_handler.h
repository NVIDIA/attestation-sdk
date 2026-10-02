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

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "nv_attestation/cmw.h"
#include "nv_attestation/corim_evidence/evidence_handler_settings.h"
#include "nv_attestation/corim_verify.h"
#include "nv_attestation/error.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/spdm/spdm_measurement_records.hpp"

namespace nvattestation {

struct EvidenceVerification {
    bool signature_checked = false;
    bool parsed = false;
    bool signature_valid = false;
    bool nonce_matches = false;
    // Nonce extracted from the evidence; set once the payload is parsed.
    std::vector<uint8_t> eat_nonce;
    // Profile of the source SPDM ToC or standalone CoEV, when supplied.
    std::unique_ptr<ProfileValue> evidence_profile;
    std::vector<Ect> ects;
    std::vector<std::string> rim_locator_urls;
    // True if EvidenceHandlerSettings::m_backup_coev was used as a fallback.
    bool used_backup_coev = false;
    // Below: populated only by SPDM-based handlers, empty/null for others.
    // DMTF block 52. TODO(P1): only the Blackwell FSP WAR needs this; move
    // it out of this generic struct.
    std::vector<uint8_t> device_identifier_measurement;
    std::shared_ptr<const SpdmMeasurementRecordParser> measurement_records;
    int32_t measurement_hash_algorithm_id = 0;
};

// Per-evidence-media-type processing. appraise_item looks up the handler once
// and runs the same steps for every type; it never branches on media type.
class IEvidenceHandler {
  protected:
    IEvidenceHandler() = default;

  public:
    virtual ~IEvidenceHandler() = default;

    virtual bool accepts_media_type(const std::string &media_type) const = 0;

    // Pull the device-identity cert chain bytes (PEM) out of the evidence
    // item. May come from the companion certificate slot (raw SPDM today) or
    // from inside the evidence payload (ARM CCA, EAT). An empty out_pem with
    // Error::Ok means no chain is available; the caller skips anchoring.
    virtual Error extract_cert_chain(const CmwEvidenceItem &item,
                                     const EvidenceHandlerSettings &settings,
                                     std::vector<uint8_t> &out_pem) const = 0;

    // A failed signature/nonce gate is reported in out_verification with
    // Error::Ok; Error is non-Ok only for a malformed payload.
    virtual Error verify_and_extract_ects(const CmwEvidenceItem &item,
                                          X509CertChain &validated_chain,
                                          const EvidenceHandlerSettings &settings,
                                          EvidenceVerification &out_verification) const = 0;
};

// Returns the handler for a media type, or nullptr if none is registered.
// The returned pointer has static lifetime.
const IEvidenceHandler *find_evidence_handler(const std::string &media_type);

bool is_evidence_media_type_supported(const std::string &media_type);

} // namespace nvattestation
