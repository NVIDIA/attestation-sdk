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

#include <stdio.h>

#include <nvat.h>


nvat_rc_t run(void);

int main(void) {
    nvat_rc_t rc = run();
    nvat_sdk_shutdown();
    if (rc != NVAT_RC_OK) {
        fprintf(stderr, "custom-logger failed: %s (nvat code: %03d)\n", nvat_rc_to_string(rc), rc);
        return 1;
    }
    return 0;
}

// Custom callback to determine whether a log message should be processed
bool should_log_cb(nvat_log_level_t level, const char* filename, const char* function, int line_number, void* user_data) {
    // Allow all messages at TRACE level and above
    return level >= NVAT_LOG_LEVEL_TRACE;
}

// Custom callback to handle log messages
void log_cb(nvat_log_level_t level, const char* message, const char* filename, const char* function, int line_number, void* user_data) {
    char* level_str = "";
    if (level == NVAT_LOG_LEVEL_ERROR) {
        level_str = " [ERROR]";
    }
    // Format: [user_data] [filename:line function][LEVEL]: message
    fprintf(stdout, "[%s] [%s:%d %s]%s: %s\n", (char*) user_data, filename, line_number, function, level_str, message);
}

// Custom callback for flushing buffered log messages
void flush_cb(void* user_data) {
    fprintf(stdout, "invoked flush() on custom logger\n");
}

nvat_rc_t run(void) {
    // Step 1: Create SDK options
    nvat_sdk_opts_t opts;
    nvat_rc_t err = nvat_sdk_opts_create(&opts);
    if (err != NVAT_RC_OK) {
        return err;
    }

    // Step 2: Create custom logger with callbacks
    // Define three callback functions:
    // - should_log_cb: Filters messages based on log level, filename, function, and line number
    // - log_cb: Handles the actual log message formatting and output
    // - flush_cb: Handles requests to flush any buffered log messages
    // nvat_logger_callback_create creates a custom logger backend with your callback functions
    // The user_data parameter allows passing custom context to all callbacks
    nvat_logger_t logger;
    err = nvat_logger_callback_create(
        &logger,
        log_cb,              // Log message callback
        should_log_cb,       // Log filtering callback
        flush_cb,            // Flush callback
        "custom-logger-data" // User data passed to callbacks
    );
    if (err != NVAT_RC_OK) {
        return err;
    }
    // Step 3: Set the custom logger in SDK options
    // nvat_sdk_opts_set_logger connects your custom logger to the SDK options
    // The logger becomes active when nvat_sdk_init is called
    nvat_sdk_opts_set_logger(opts, logger);

    // Step 4: Initialize SDK with custom logger
    err = nvat_sdk_init(opts);
    if (err != NVAT_RC_OK) {
        nvat_sdk_opts_free(&opts);
        nvat_logger_free(&logger);
        return err;
    }

    // Step 5: Trigger a log message (intentional error for demonstration)
    // When the SDK generates log messages, your callbacks are invoked:
    // - should_log_cb first determines if the message should be processed
    // - If allowed, log_cb handles formatting and output
    // - flush_cb is called when buffered messages should be flushed
    // The example intentionally triggers an error message by passing NULL to a function
    // that requires a valid pointer, demonstrating how SDK errors are logged through your custom system
    nvat_http_options_create_default(NULL);

    return NVAT_RC_OK;
}
