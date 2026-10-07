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

#include <vector>

#include "nv_attestation/corim_evidence/coev.h"  // CorimLocatorMap
#include "nv_attestation/corim_evidence/eat.h"   // Eat, MeasurementsFormat
#include "nv_attestation/corim_verify.h"         // Ect
#include "nv_attestation/error.h"                // Error

namespace nvattestation {

// Convert a parsed EAT into evidence Ects for the core verification algorithm.
// Each measurement's inline concise-evidence is converted (reusing
// concise_evidence_to_ects) and appended to `out_ects` in measurement order. The
// EAT's rim-locators are copied into `out_rim_locators` for the caller to drive
// CoRIM fetches.
//
// Returns the first non-Ok error from the underlying concise-evidence
// conversion; otherwise Error::Ok. `out_ects` and `out_rim_locators` are
// appended to (not cleared).
Error eat_to_ects(const Eat& eat,
                  std::vector<Ect>& out_ects,
                  std::vector<CorimLocatorMap>& out_rim_locators);

}  // namespace nvattestation
