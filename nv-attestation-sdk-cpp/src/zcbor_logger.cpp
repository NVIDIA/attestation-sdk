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

#include <cstdarg>
#include <cstdio>
#include "spdlog/spdlog.h"

extern "C" {

/**
 * @brief Bridge function to redirect zcbor logging to spdlog
 * 
 * This function is called by zcbor's logging macros when ZCBOR_PRINT_FUNC
 * is defined at compile time. It formats the variadic arguments and passes
 * them to spdlog at trace level.
 * 
 * @param format Printf-style format string
 * @param ... Variadic arguments matching the format string
 */
void nvat_zcbor_log(const char* format, ...) {
    static constexpr size_t LOG_BUFFER_SIZE = 2048;
    char buffer[LOG_BUFFER_SIZE];
    va_list args;
    va_start(args, format);
    int written = vsnprintf(buffer, sizeof(buffer), format, args);  // NOLINT(clang-analyzer-valist.Uninitialized)
    va_end(args);
    
    // Remove trailing newlines/carriage returns for cleaner spdlog output
    if (written > 0 && written < (int)sizeof(buffer)) {
        while (written > 0 && (buffer[written-1] == '\n' || buffer[written-1] == '\r')) {
            buffer[--written] = '\0';
        }
    }
    
    // Log to spdlog at debug level with zcbor prefix
    spdlog::trace("[zcbor] {}", buffer);
}

} // extern "C"
