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

#include "nvat.h"
#include "logging.h"

namespace nvattest {

// One process-global CliLogger shared by every in-process mock fixture.
// CliLogger registers a global spdlog logger named "cli"; constructing more than
// one — e.g. a separate static per fixture — throws "logger with name 'cli'
// already exists" once two mock suites run in the same process. The inline
// function's static local gives a single shared instance across translation units.
inline CliLogger& shared_mock_logger() {
    static CliLogger instance(NVAT_LOG_LEVEL_OFF);
    return instance;
}

} // namespace nvattest
