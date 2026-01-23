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

#include <memory>
#include <string>
#include <vector>
#include <mutex>

#include "nvat.h"
#include "spdlog/spdlog.h"

namespace nvattest {

/**
 * @brief CLI logger that captures error messages and provides callback bindings for nvat.
 * 
 * This logger integrates with the NVAT SDK's callback logger interface and maintains
 * a console logger for output along with a collection of error messages for later retrieval.
 */
class CliLogger {
public:
    explicit CliLogger(nvat_log_level_t level);
    std::vector<std::string> get_error_messages() const;
    void clear_error_messages();
    void install();
    nvat_rc_t create_nvat_logger(nvat_logger_t* out_logger);

    /*
     * Static callbacks for nvat logging functionality.
     */

    static bool should_log_callback(
        nvat_log_level_t level,
        const char* filename,
        const char* function,
        int line,
        void* user_data
    );

    static void log_callback(
        nvat_log_level_t level,
        const char* message,
        const char* filename,
        const char* function,
        int line,
        void* user_data
    );

    static void flush_callback(void* user_data);

private:
    bool should_log_impl(nvat_log_level_t level) const;
    void log_impl(
        nvat_log_level_t level,
        const char* message,
        const char* filename,
        const char* function,
        int line
    );
    void flush_impl();
    static spdlog::level::level_enum to_spdlog_level(nvat_log_level_t level);
    std::shared_ptr<spdlog::logger> m_cli_logger;
    std::shared_ptr<spdlog::logger> m_sdk_logger;
    std::vector<std::string> m_error_messages;
    nvat_log_level_t m_min_level;
    mutable std::mutex m_mutex;
};

} // namespace nvattest

