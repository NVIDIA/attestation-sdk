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

#include "logging.h"

#include <sstream>
#include "spdlog/sinks/stdout_color_sinks.h"

namespace nvattest {

CliLogger::CliLogger(nvat_log_level_t level)
    : m_min_level(level) {
    m_cli_logger = spdlog::stderr_color_mt("cli");
    m_cli_logger->set_level(to_spdlog_level(level));
    m_cli_logger->set_pattern("%v");
    
    m_sdk_logger = spdlog::stderr_color_mt("sdk");
    m_sdk_logger->set_level(to_spdlog_level(level));
    m_sdk_logger->set_pattern("%Y-%m-%d %H:%M:%S.%e [%@ %!] [%l] %v");
}

std::vector<std::string> CliLogger::get_error_messages() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_error_messages;
}

void CliLogger::clear_error_messages() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_error_messages.clear();
}

void CliLogger::install() {
    spdlog::set_default_logger(m_cli_logger);
}

nvat_rc_t CliLogger::create_nvat_logger(nvat_logger_t* out_logger) {
    return nvat_logger_callback_create(
        out_logger,
        &CliLogger::log_callback,
        &CliLogger::should_log_callback,
        &CliLogger::flush_callback,
        this
    );
}

bool CliLogger::should_log_callback(
    nvat_log_level_t level,
    const char* filename,
    const char* function,
    int line,
    void* user_data
) {
    if (user_data == nullptr) {
        return false;
    }
    CliLogger* logger = static_cast<CliLogger*>(user_data);
    return logger->should_log_impl(level);
}

void CliLogger::log_callback(
    nvat_log_level_t level,
    const char* message,
    const char* filename,
    const char* function,
    int line,
    void* user_data
) {
    if (user_data == nullptr) {
        return;
    }
    CliLogger* logger = static_cast<CliLogger*>(user_data);
    logger->log_impl(level, message, filename, function, line);
}

void CliLogger::flush_callback(void* user_data) {
    if (user_data == nullptr) {
        return;
    }
    CliLogger* logger = static_cast<CliLogger*>(user_data);
    logger->flush_impl();
}

bool CliLogger::should_log_impl(nvat_log_level_t level) const {
    return level >= m_min_level;
}

void CliLogger::log_impl(
    nvat_log_level_t level,
    const char* message,
    const char* filename,
    const char* function,
    int line
) {
    auto source_loc = spdlog::source_loc{filename, line, function};
    m_sdk_logger->log(source_loc, to_spdlog_level(level), message);
    
    if (level >= NVAT_LOG_LEVEL_ERROR) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_error_messages.push_back(message);
    }
}

void CliLogger::flush_impl() {
    if (m_cli_logger) {
        m_cli_logger->flush();
    }
    if (m_sdk_logger) {
        m_sdk_logger->flush();
    }
}

spdlog::level::level_enum CliLogger::to_spdlog_level(nvat_log_level_t level) {
    switch (level) {
        case NVAT_LOG_LEVEL_TRACE:
            return spdlog::level::trace;
        case NVAT_LOG_LEVEL_DEBUG:
            return spdlog::level::debug;
        case NVAT_LOG_LEVEL_INFO:
            return spdlog::level::info;
        case NVAT_LOG_LEVEL_WARN:
            return spdlog::level::warn;
        case NVAT_LOG_LEVEL_ERROR:
            return spdlog::level::err;
        case NVAT_LOG_LEVEL_OFF:
            return spdlog::level::off;
        default:
            return spdlog::level::info;
    }
}

} // namespace nvattest

