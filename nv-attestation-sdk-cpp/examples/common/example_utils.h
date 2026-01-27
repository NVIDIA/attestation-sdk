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

#include <nvat.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

nvat_rc_t setup_sdk(nvat_sdk_opts_t* opts, nvat_logger_t* logger);

void cleanup_sdk(nvat_sdk_opts_t* opts, nvat_logger_t* logger);

nvat_rc_t create_default_gpu_ctx(nvat_attestation_ctx_t* ctx);

nvat_rc_t print_results(nvat_rc_t attestation_rc, nvat_str_t detached_eat, nvat_claims_collection_t claims);

#ifdef __cplusplus
}
#endif


