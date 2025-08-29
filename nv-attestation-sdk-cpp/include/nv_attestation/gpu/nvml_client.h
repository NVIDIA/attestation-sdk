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

#ifdef ENABLE_NVML
#include <nvml.h>
#endif // ENABLE_NVML

#include "nv_attestation/error.h"
#include "nv_attestation/gpu/evidence.h"

namespace nvattestation {

Error init_nvml();
void shutdown_nvml();

#ifdef ENABLE_NVML
bool set_gpu_ready_state(bool ready);
std::unique_ptr<bool> is_cc_enabled();
std::unique_ptr<bool> is_cc_dev_mode();
std::unique_ptr<int> get_gpu_ready_state();

std::unique_ptr<std::string> get_attestation_cert_chain(nvmlDevice_t device_handle);
std::unique_ptr<std::vector<uint8_t>> get_attestation_report(nvmlDevice_t device_handle, const std::vector<uint8_t>& nonce_input);
std::unique_ptr<std::string> get_driver_version();
std::unique_ptr<std::string> get_vbios_version(nvmlDevice_t device_handle);
std::unique_ptr<std::string> get_uuid(nvmlDevice_t device_handle);


std::unique_ptr<GpuArchitecture> get_gpu_architecture(nvmlDevice_t device_handle);
#endif // ENABLE_NVML

} // namespace nvattestation

