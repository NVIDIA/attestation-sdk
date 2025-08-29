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

bool should_log_cb(nvat_log_level_t level, const char* filename, const char* function, int line_number, void* user_data) {
    return level >= NVAT_LOG_LEVEL_TRACE;
}

void log_cb(nvat_log_level_t level, const char* message, const char* filename, const char* function, int line_number, void* user_data) {
    char* level_str = "";
    if (level == NVAT_LOG_LEVEL_ERROR) {
        level_str = " [ERROR]";
    }
   fprintf(stdout, "[%s] [%s:%d %s]%s: %s\n", (char*) user_data, filename, line_number, function, level_str, message);
}

void flush_cb(void* user_data) {
    fprintf(stdout, "invoked flush() on custom logger\n");
}

nvat_rc_t run(void) {
    nvat_sdk_opts_t opts;
    nvat_rc_t err = nvat_sdk_opts_create(&opts);
    if (err != NVAT_RC_OK) {
        return err;
    }

    nvat_logger_t logger;
    err = nvat_logger_callback_create(
        &logger,
        log_cb,
        should_log_cb,
        flush_cb,
        "custom-logger-data"
    );
    if (err != NVAT_RC_OK) {
        return err;
    }
    nvat_sdk_opts_set_logger(opts, &logger);

    err = nvat_sdk_init(&opts);
    if (err != NVAT_RC_OK) {
        return err;
    }

    // intentionally trigger an error message
    nvat_http_options_create_default(NULL);

    return NVAT_RC_OK;
}
