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

#include "nv_attestation/corim_verify.h"
#include "nv_attestation/dice_tcb_info.h"
#include "nv_attestation/error.h"
#include "nv_attestation/nv_x509.h"

namespace nvattestation {

// Transform per draft-ietf-rats-evidence-trans §4.2. Limitations: only the
// first FWID is consumed; integrity-registers and ECT.authority are dropped
// (not yet modeled).
Error dice_tcb_info_to_ect(const DiceTcbInfo &dti,
                           const std::vector<uint8_t> *ueid, Ect &out);

Error multi_dice_tcb_info_to_ect_list(const MultiDiceTcbInfo &multi,
                                      const std::vector<uint8_t> *ueid,
                                      std::vector<Ect> &out);

// Per cert, tries MultiDiceTcbInfo then alias then primary OID; `ueid_fallback`
// applies only to certs without their own DiceUeid. `out_dti_indices`, when
// non-null, receives every index that yielded a DiceTcbInfo.
Error x509_chain_to_evidence_ects(const X509CertChain &chain,
                                  const std::vector<uint8_t> *ueid_fallback,
                                  std::vector<Ect> &out,
                                  std::vector<size_t> *out_dti_indices = nullptr);

// First cert from the leaf that carries no DiceTcbInfo; `dti_indices` comes
// from x509_chain_to_evidence_ects. CertNotFound = not identified, which is
// normal rather than a failure.
// Open: a cert holding the older CompositeDeviceID under 2.23.133.5.4.1 is
// not counted, so on those chains the walk stops at the leaf.
Error find_device_cert_index(const std::vector<size_t> &dti_indices,
                             size_t chain_size, size_t &out_index);


} // namespace nvattestation
