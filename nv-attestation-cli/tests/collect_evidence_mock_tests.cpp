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

// In-process white-box tests for handle_collect_evidence_subcommand, driven
// against the fake nvat C API (fake_nvat.cpp). Real evidence collection needs
// GPU/switch hardware, so these steer the SDK responses to exercise the CLI
// orchestration (device / evidence-source branches, collect + serialize, and the
// result/exit-code mapping) without any hardware.

#include <iostream>
#include <sstream>
#include <string>

#include "gtest/gtest.h"

#include "nvat.h"
#include "collect_evidence.h"
#include "nvattest_options.h"
#include "logging.h"
#include "fake_nvat_control.h"
#include "mock_cli_logger.h"

using namespace nvattest;

class CollectEvidenceMock : public ::testing::Test {
  protected:
    EvidenceCollectionOptions collect;
    CommonOptions common;
    std::streambuf* m_old_cout = nullptr;
    std::ostringstream m_captured_cout;

    void SetUp() override {
        fake_nvat_reset();
        collect.device = "gpu";  // default source is NVML
        common.format = "json";
        m_old_cout = std::cout.rdbuf(m_captured_cout.rdbuf());
    }

    void TearDown() override {
        std::cout.rdbuf(m_old_cout);
    }

    int run() {
        return handle_collect_evidence_subcommand(shared_mock_logger(), collect, common);
    }
};

// --- success across the source branches ---

TEST_F(CollectEvidenceMock, GpuNvmlSuccessJson) {
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(CollectEvidenceMock, GpuNvmlSuccessText) {
    common.format = "text";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(CollectEvidenceMock, GpuFileSource) {
    collect.gpu_evidence_source = "file";
    collect.gpu_evidence_file = "/tmp/ignored-by-fake.json";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(CollectEvidenceMock, GpuCorelibWithArch) {
    collect.gpu_evidence_source = "corelib";
    collect.gpu_architecture = "blackwell";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(CollectEvidenceMock, GpuCorelibMissingArchRejected) {
    collect.gpu_evidence_source = "corelib";  // no --gpu-architecture
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_BAD_ARGUMENT));
}

TEST_F(CollectEvidenceMock, SwitchNscqSuccess) {
    collect.device = "nvswitch";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(CollectEvidenceMock, SwitchFileSource) {
    collect.device = "nvswitch";
    collect.switch_evidence_source = "file";
    collect.switch_evidence_file = "/tmp/ignored-by-fake.json";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

TEST_F(CollectEvidenceMock, NonceProvided) {
    collect.nonce = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}

// --- failure branches ---

TEST_F(CollectEvidenceMock, InitSdkFailure) {
    g_fake_nvat.sdk_init_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(CollectEvidenceMock, SourceCreateFailure) {
    g_fake_nvat.source_create_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(CollectEvidenceMock, CollectFailure) {
    g_fake_nvat.collect_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(CollectEvidenceMock, SerializeFailureMapsToInternalError) {
    g_fake_nvat.serialize_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(CollectEvidenceMock, StrGetDataFailure) {
    g_fake_nvat.str_get_data_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(CollectEvidenceMock, TextModeFailure) {
    common.format = "text";
    g_fake_nvat.collect_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

// --- per-source-type failure branches (source_create_rc is shared; the config
//     selects which source-create function it hits) ---

TEST_F(CollectEvidenceMock, GpuFileSourceCreateFailure) {
    collect.gpu_evidence_source = "file";
    collect.gpu_evidence_file = "/tmp/ignored-by-fake.json";
    g_fake_nvat.source_create_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(CollectEvidenceMock, GpuCorelibCreateFailure) {
    collect.gpu_evidence_source = "corelib";
    collect.gpu_architecture = "blackwell";
    g_fake_nvat.source_create_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(CollectEvidenceMock, SwitchNscqCreateFailure) {
    collect.device = "nvswitch";
    g_fake_nvat.source_create_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(CollectEvidenceMock, SwitchFileSourceCreateFailure) {
    collect.device = "nvswitch";
    collect.switch_evidence_source = "file";
    collect.switch_evidence_file = "/tmp/ignored-by-fake.json";
    g_fake_nvat.source_create_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(CollectEvidenceMock, SwitchCollectFailure) {
    collect.device = "nvswitch";
    g_fake_nvat.collect_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(CollectEvidenceMock, SwitchSerializeFailure) {
    collect.device = "nvswitch";
    g_fake_nvat.serialize_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_INTERNAL_ERROR));
}

TEST_F(CollectEvidenceMock, NonceParseFailure) {
    collect.nonce = "zz";  // fake nonce parse steered to fail
    g_fake_nvat.nonce_rc = NVAT_RC_BAD_ARGUMENT;
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_BAD_ARGUMENT));
}

// Malformed serialized evidence exercises to_json's parse-error catch (json mode).
TEST_F(CollectEvidenceMock, ToJsonHandlesMalformedEvidences) {
    g_fake_nvat.evidences_json = "{not valid json";
    EXPECT_EQ(run(), static_cast<int>(NVAT_RC_OK));
}
