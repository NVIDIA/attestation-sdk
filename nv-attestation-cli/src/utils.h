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

#include "CLI/CLI.hpp"
#include "nvattest_options.h"
#include "nvat.h"
#include "nvattest_types.h"
#include "logging.h"

namespace nvattest {
    void add_evidence_collection_options(CLI::App* app, EvidenceCollectionOptions& options);
    void add_evidence_policy_options(CLI::App* app, EvidencePolicyOptions& options);
    void add_evidence_verification_options(CLI::App* app, EvidenceVerificationOptions& options);
    void add_common_options(CLI::App& app, CommonOptions& options);

    void print_error_help(const CliLogger& logger, nvat_rc_t rc);
    nvat_rc_t init_sdk(CliLogger& logger, const CommonOptions& common_options);
}
