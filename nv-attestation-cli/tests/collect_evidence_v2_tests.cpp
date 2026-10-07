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

// Failure-path coverage for collect-evidence-v2. Real collection needs a GPU;
// on a GPU-less runner NVML init fails deterministically, which drives
// run_collect's error handling and print_error_help. Skipped whenever a
// device pass is requested (gpu or nvswitch): combined GPU+NVSwitch racks
// (e.g. PPCIE hosts) have real GPUs on the nvswitch pass too, so only a
// plain device-less run is guaranteed to see NVML fail.

#include <string>

#include "gtest/gtest.h"
#include <nlohmann/json.hpp>

#include "environment.h"
#include "test_utils.h"

TEST(CollectEvidenceV2Cli, NvmlCollectionReportsErrorJson) {
    if (g_cli_env->test_device_gpu || g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping GPU-less NVML failure-path test on a GPU/NVSwitch-equipped runner";
    }
    int exit_code = 0;
    const std::string cmd =
        g_cli_env->nvattest_bin +
        " collect-evidence-v2 --evidence-source nvml --format json";
    std::string output = exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0);
    EXPECT_NE(output.find("Error"), std::string::npos) << output;
}

// Text-mode failure exercises print_error_help.
TEST(CollectEvidenceV2Cli, NvmlCollectionReportsErrorText) {
    if (g_cli_env->test_device_gpu || g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping GPU-less NVML failure-path test on a GPU/NVSwitch-equipped runner";
    }
    int exit_code = 0;
    const std::string cmd =
        g_cli_env->nvattest_bin +
        " collect-evidence-v2 --evidence-source nvml --format text";
    std::string output = exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0) << output;
    EXPECT_NE(output.find("Error"), std::string::npos) << output;
}

TEST(CollectEvidenceV2Cli, SpdmFilesSourceWithoutTranscriptIsRejected) {
    int exit_code = 0;
    const std::string cmd =
        g_cli_env->nvattest_bin +
        " collect-evidence-v2 --evidence-source spdm-files --format json";
    exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0);
}

TEST(CollectEvidenceV2Cli, SpdmFilesSourceWithoutCertChainIsRejected) {
    int exit_code = 0;
    const std::string cmd =
        g_cli_env->nvattest_bin +
        " collect-evidence-v2 --evidence-source spdm-files"
        " --spdm-transcript-file /dev/null --format json";
    exec_and_capture_output(cmd, exit_code);
    EXPECT_NE(exit_code, 0);
}
