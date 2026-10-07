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
#include <vector>

namespace nvattestation {

// Per-appraisal configuration forwarded to evidence handlers. Handlers that
// do not use a field ignore it. The caller (LocalCorimVerifier::appraise_item)
// selects or constructs settings before dispatch, which leaves room to derive
// device-specific settings from the anchored cert chain in the future.
struct EvidenceHandlerSettings {
    // Fallback #6.571 ConciseEvidence for SPDM handlers that find no embedded
    // #6.570 SpdmToc. The SPDM handler resolves spdm-indirect references
    // against the actual measurement records. Empty = disabled.
    std::vector<uint8_t> m_backup_coev;

    // Require the evidence payload's own signature (e.g. an EAT's COSE_Sign1).
    // Disable only for unauthenticated development fixtures.
    bool m_verify_evidence_signature = true;
};

} // namespace nvattestation
