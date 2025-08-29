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
#include <nlohmann/json.hpp>
#include "CLI/CLI.hpp"

namespace nvattest {
    /**
     * @brief Creates and adds the 'version' subcommand to the main CLI application.
     * 
     * @param app The main CLI::App object to which the subcommand will be added.
     * @return A pointer to the created CLI::App subcommand object.
     */
    CLI::App* create_version_subcommand(CLI::App& app);
    
    /**
     * @brief Handles the logic when the 'version' subcommand is invoked. 
     * 
     * @return Exit code for the subcommand handler (0 for success).
     */
    int handle_version_subcommand();

}
