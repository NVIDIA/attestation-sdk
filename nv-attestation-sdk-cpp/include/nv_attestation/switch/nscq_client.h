/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <string>
#include <vector>
#include <memory>

#ifdef ENABLE_NSCQ
#include "nv_attestation/switch/nscq_attestation.h"
#include "nv_attestation/switch/nscq_attestation_path.h"
#endif // ENABLE_NSCQ

#include "nv_attestation/error.h"
#include "nv_attestation/switch/evidence.h"

namespace nvattestation {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
extern bool g_nscq_initialized;
Error init_nscq();
void shutdown_nscq();

#ifdef ENABLE_NSCQ

enum class SwitchTnvlMode {
    Unknown = NSCQ_DEVICE_TNVL_MODE_UNKNOWN,
    Disabled = NSCQ_DEVICE_TNVL_MODE_DISABLED,
    Enabled = NSCQ_DEVICE_TNVL_MODE_ENABLED,
    Failure = NSCQ_DEVICE_TNVL_MODE_FAILURE,
    Locked = NSCQ_DEVICE_TNVL_MODE_LOCKED
};

Error get_all_switch_uuid(std::vector<std::string>& out_uuids);
Error get_switch_tnvl_status(const std::string& uuid, SwitchTnvlMode& out_tnvl_mode);

Error get_attestation_cert_chain(const std::string& uuid, std::string& out_cert_chain);
Error get_attestation_report(const std::string& uuid, const std::vector<uint8_t>& nonce_input, std::vector<uint8_t>& out_attestation_report);

Error get_switch_architecture(SwitchArchitecture& out_arch);

#endif // ENABLE_NSCQ

}