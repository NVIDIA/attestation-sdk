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
#include "nv_attestation/corim_evidence/eat_to_ect.h"

#include "nv_attestation/corim_evidence/coev_to_ect.h"  // concise_evidence_to_ects

namespace nvattestation {

Error eat_to_ects(const Eat& eat,
                  std::vector<Ect>& out_ects,
                  std::vector<CorimLocatorMap>& out_rim_locators) {
    // The OCP EAT delivers self-contained concise-evidence, so convert with no
    // SPDM record source; an spdm-indirect reference (none expected here) would
    // surface as an error from concise_evidence_to_ects.
    for (const auto& mf : eat.getMeasurements()) {
        Error err = concise_evidence_to_ects(mf.evidence, out_ects);
        if (err != Error::Ok) {
            return err;
        }
    }

    for (const auto& loc : eat.getRimLocators()) {
        out_rim_locators.push_back(loc);
    }
    return Error::Ok;
}

}  // namespace nvattestation
