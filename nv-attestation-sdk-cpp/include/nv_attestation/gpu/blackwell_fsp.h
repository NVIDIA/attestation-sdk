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

#include <cstdint>
#include <string>
#include <vector>

#include "nv_attestation/error.h"
#include "nv_attestation/nv_x509.h"

namespace nvattestation {

Error validate_firmware_version_hint(const std::string &fw);

bool is_blackwell_fsp_responder(const X509CertChain &validated_chain,
                                 const std::string &hw_model);

// out_reason names which input was unusable, so a caller can report it rather
// than leaving the cause in the log.
Error build_vbios_rim_locator(const std::string &hw_model,
                               const std::vector<uint8_t> &device_identifier_measurement,
                               const std::string &fw_version,
                               std::string &out_locator,
                               std::string &out_reason);

}  // namespace nvattestation
