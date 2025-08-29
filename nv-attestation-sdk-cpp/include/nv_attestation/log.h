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
#include <memory>
#include <sstream>
#include "spdlog/spdlog.h"

#include <nvat.h>
#include "error.h"

namespace nvattestation {

enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    OFF
};

// log macros
// ref: https://github.com/aws/aws-sdk-cpp/blob/main/src/aws-cpp-sdk-core/include/aws/core/utils/logging/LogMacros.h#L83
// ref: https://stackoverflow.com/questions/154136/why-use-apparently-meaningless-do-while-and-if-else-statements-in-macros
// NOLINTBEGIN(bugprone-macro-parentheses): relying on no parens to substitute multiple args via <<
#define LOG_TRACE(message) \
    do { \
        if (get_logger()->should_log(LogLevel::TRACE, __FILE__, __FUNCTION__, __LINE__)) { \
            std::stringstream stream; \
            stream << message; \
            get_logger()->log(LogLevel::TRACE, stream.str(), __FILE__, __FUNCTION__, __LINE__); \
        } \
    } while (false)
#define LOG_DEBUG(message) \
    do { \
        if (get_logger()->should_log(LogLevel::DEBUG, __FILE__, __FUNCTION__, __LINE__)) { \
            std::stringstream stream; \
            stream << message; \
            get_logger()->log(LogLevel::DEBUG, stream.str(), __FILE__, __FUNCTION__, __LINE__); \
        } \
    } while (false)
#define LOG_INFO(message) \
    do { \
        if (get_logger()->should_log(LogLevel::INFO, __FILE__, __FUNCTION__, __LINE__)) { \
            std::stringstream stream; \
            stream << message; \
            get_logger()->log(LogLevel::INFO, stream.str(), __FILE__, __FUNCTION__, __LINE__); \
        } \
    } while (false)
#define LOG_WARN(message) \
    do { \
        if (get_logger()->should_log(LogLevel::WARNING, __FILE__, __FUNCTION__, __LINE__)) { \
            std::stringstream stream; \
            stream << message; \
            get_logger()->log(LogLevel::WARNING, stream.str(), __FILE__, __FUNCTION__, __LINE__); \
        } \
    } while (false)
#define LOG_ERROR(message) \
    do { \
        if (get_logger()->should_log(LogLevel::ERROR, __FILE__, __FUNCTION__, __LINE__)) { \
            std::stringstream stream; \
            stream << message; \
            get_logger()->log(LogLevel::ERROR, stream.str(), __FILE__, __FUNCTION__, __LINE__); \
        } \
    } while (false)

#define LOG_PUSH_ERROR(error_code, message) \
    do { \
        std::stringstream stream; \
        stream << message; \
        get_logger()->log(LogLevel::ERROR, stream.str(), __FILE__, __FUNCTION__, __LINE__); \
        ErrorStack::push(error_code, stream.str()); \
    } while (false)
// NOLINTEND(bugprone-macro-parentheses)


inline std::string to_string(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

LogLevel log_level_from_c(nvat_log_level_t c_level);
nvat_log_level_t log_level_to_c(LogLevel cpp_level);

class ILogger {
    public:
        virtual ~ILogger() = default;
        virtual void log(LogLevel level, const std::string& message, const std::string& filename, const std::string& function, int line_number) = 0;
        virtual bool should_log(LogLevel level, const std::string& filename, const std::string& function, int line_number) = 0;
        virtual void flush() = 0;
};

class SpdLogLogger : public ILogger {
public:
    SpdLogLogger(LogLevel level);
    SpdLogLogger(std::string& name, LogLevel level);
    void log(LogLevel level, const std::string& message, const std::string& filename, const std::string& function, int line_number) override;
    bool should_log(LogLevel level, const std::string& filename, const std::string& function, int line_number) override;
    void flush() override;
    void set_format(const std::string& format);

private:
    std::shared_ptr<spdlog::logger> m_logger;
    static spdlog::level::level_enum get_spdlog_level(LogLevel level);
};

class CallbackLogger : public ILogger {
public:
    CallbackLogger(
        nvat_should_log_callback_t slcb,
        nvat_log_callback_t lcb,
        nvat_flush_callback_t fcb,
        void* user_data
    ): 
        m_should_log_callback(slcb),
        m_log_callback(lcb),
        m_flush_callback(fcb),
        m_user_data(user_data)
     {}
    ~CallbackLogger() override = default;
    void log(LogLevel level, const std::string& message, const std::string& filename, const std::string& function, int line_number) override;
    bool should_log(LogLevel level, const std::string& filename, const std::string& function, int line_number) override;
    void flush() override;
private:
    nvat_should_log_callback_t m_should_log_callback;
    nvat_log_callback_t m_log_callback;
    nvat_flush_callback_t m_flush_callback;
    void* m_user_data;
};

void set_logger(std::shared_ptr<ILogger> logger);
void destroy_logger();
std::shared_ptr<ILogger> get_logger();

}