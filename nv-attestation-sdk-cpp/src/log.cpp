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

#include <cassert>
#include <spdlog/common.h>
#include <string>

#include "nvat.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "nv_attestation/log.h"

namespace nvattestation {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): Must be mutable
static std::shared_ptr<ILogger> g_logger;
constexpr const char* DEFAULT_SPDLOG_PATTERN = "%Y-%m-%d %H:%M:%S.%e [%n] [%@ %!] [%l] %v";

void set_logger(std::shared_ptr<ILogger> logger) {
    g_logger = std::move(logger);
}

void destroy_logger() {
    if (g_logger != nullptr) {
        g_logger->flush();
    }
    g_logger = nullptr;
}

std::shared_ptr<ILogger> get_logger() {
    assert(g_logger != nullptr);
    return g_logger;
}

SpdLogLogger::SpdLogLogger(LogLevel level) {
    m_logger = spdlog::stderr_color_mt("nvat");
    m_logger->set_level(get_spdlog_level(level));
    m_logger->set_pattern(DEFAULT_SPDLOG_PATTERN);
}

SpdLogLogger::SpdLogLogger(std::string& name, LogLevel level) {
    m_logger = spdlog::stderr_color_mt(name);
    m_logger->set_level(get_spdlog_level(level));
    m_logger->set_pattern(DEFAULT_SPDLOG_PATTERN);
}

void SpdLogLogger::log(LogLevel level, const std::string& message, const std::string& filename, const std::string& function, int line_number) {
    // TODO(p1): Add custom flag formatter to support filename, function, and line through flags
    // See: https://github.com/gabime/spdlog/wiki/Custom-formatting#extending-spdlog-with-your-own-flags
    auto source_log = spdlog::source_loc{filename.c_str(), line_number, function.c_str()};
    m_logger->log(source_log, get_spdlog_level(level), message);
}

bool SpdLogLogger::should_log(LogLevel level, const std::string& filename, const std::string& function, int line_number) {
    return m_logger->should_log(get_spdlog_level(level));
}

void SpdLogLogger::flush() {
    m_logger->flush();
}

void SpdLogLogger::set_format(const std::string& format) {
    m_logger->set_pattern(format);
}

spdlog::level::level_enum SpdLogLogger::get_spdlog_level(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return spdlog::level::trace;
            case LogLevel::DEBUG: return spdlog::level::debug;
            case LogLevel::INFO: return spdlog::level::info;
            case LogLevel::WARNING: return spdlog::level::warn;
            case LogLevel::ERROR: return spdlog::level::err;
        default: return spdlog::level::info;
    }
}

void CallbackLogger::log(LogLevel level, const std::string& message, const std::string& filename, const std::string& function, int line_number) {
    if (m_log_callback == nullptr) {
        return;
    }
    m_log_callback(log_level_to_c(level), message.c_str(), filename.c_str(), function.c_str(), line_number, m_user_data);
}

bool CallbackLogger::should_log(LogLevel level, const std::string& filename, const std::string& function, int line_number) {
    if (m_should_log_callback == nullptr) {
        return true;
    }
    return m_should_log_callback(log_level_to_c(level), filename.c_str(), function.c_str(), line_number, m_user_data);
}

void CallbackLogger::flush() {
    if (m_flush_callback == nullptr) {
        return;
    }
    m_flush_callback(m_user_data);
}

// TODO: define better naming convention
LogLevel log_level_from_c(nvat_log_level_t c_level) {
    switch (c_level) {
        case NVAT_LOG_LEVEL_OFF:   return LogLevel::OFF;
        case NVAT_LOG_LEVEL_TRACE: return LogLevel::TRACE;
        case NVAT_LOG_LEVEL_DEBUG: return LogLevel::DEBUG;
        case NVAT_LOG_LEVEL_INFO:  return LogLevel::INFO;
        case NVAT_LOG_LEVEL_WARN:  return LogLevel::WARNING;
        case NVAT_LOG_LEVEL_ERROR: return LogLevel::ERROR;
        default:                   return LogLevel::INFO;
    }
}

nvat_log_level_t log_level_to_c(LogLevel cpp_level) {
    switch (cpp_level) {
        case LogLevel::TRACE:   return NVAT_LOG_LEVEL_TRACE;
        case LogLevel::DEBUG:   return NVAT_LOG_LEVEL_DEBUG;
        case LogLevel::INFO:    return NVAT_LOG_LEVEL_INFO;
        case LogLevel::WARNING: return NVAT_LOG_LEVEL_WARN;
        case LogLevel::ERROR:   return NVAT_LOG_LEVEL_ERROR;
        case LogLevel::OFF:     return NVAT_LOG_LEVEL_OFF;
        default:                return NVAT_LOG_LEVEL_INFO;
    }
}

} // namespace nvattestation