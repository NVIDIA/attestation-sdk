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

#include "nv_attestation/error.h"
#include "nv_attestation/gpu/evidence.h"

namespace nvattestation {

extern bool g_nvml_initialized;

Error init_nvml();
void shutdown_nvml();
Error get_driver_version(std::string& out_driver_version);
Error collect_evidence_nvml(const std::vector<uint8_t>& nonce_input, std::vector<std::shared_ptr<GpuEvidence>>& out_evidence);

} // namespace nvattestation

