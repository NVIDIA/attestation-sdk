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

#include <cstddef>
#include <cstdint>

#include <nlohmann/json.hpp>

#include "nv_attestation/claims.h"
#include "nv_attestation/corim_verify.h"
#include "nv_attestation/error.h"

namespace nvattestation {

// Maps a CorimAttestationResult to an unsigned EAR JSON object.
// A claim whose encoding fails is logged and omitted; the EAR is still built.
Error map_to_ear_json(const CorimAttestationResult& result,
                      nlohmann::json& out_ear_json);

// Signs an EAR JSON object (from map_to_ear_json) into a compact JWT.
// options.m_private_key_pem empty => unsigned (alg=none); non-empty => ES384.
// options.m_kid, if non-empty, is set as the JWT header "kid" claim.
Error sign_ear(const nlohmann::json& ear_json, const DetachedEATOptions& options,
               std::string& out_ear_jwt);

} // namespace nvattestation
