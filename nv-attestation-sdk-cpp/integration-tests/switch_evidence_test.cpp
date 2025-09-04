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

#ifdef ENABLE_NSCQ
#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <string>

#include "nv_attestation/switch/nscq_attestation.h"

#include "nv_attestation/switch/nscq_client.h"
#include "nv_attestation/switch/evidence.h"

using namespace nvattestation;

class NscqIntegrationTest : public ::testing::Test {
protected:
    std::string m_expected_arch;

    void SetUp() override {
        ASSERT_EQ(init_nscq(), Error::Ok);
        const char* env_arch = std::getenv("EXPECTED_SWITCH_ARCH");
        if (env_arch == nullptr) {
            m_expected_arch = "LS10";
        } else {
            m_expected_arch = env_arch;
        }
    }

    void TearDown() override {
        shutdown_nscq();
    }
};

TEST_F(NscqIntegrationTest, GetAllSwitchUUIDs) {
    std::vector<std::string> uuids;
    Error error = get_all_switch_uuid(uuids);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(uuids.empty());
    for (const auto& uuid_str : uuids) {
        ASSERT_FALSE(uuid_str.empty());
        ASSERT_EQ(uuid_str.length(), 40); 
    }
}

TEST_F(NscqIntegrationTest, GetSwitchArchitecture) {
    SwitchArchitecture arch;
    Error error = get_switch_architecture(arch);
    ASSERT_EQ(error, Error::Ok);
    
    std::string arch_str = to_string(arch);
    ASSERT_FALSE(arch_str.empty());
    ASSERT_EQ(arch_str, m_expected_arch);
}

TEST_F(NscqIntegrationTest, SwitchEvidence) {
    std::vector<std::string> uuids;
    Error error = get_all_switch_uuid(uuids);
    ASSERT_EQ(error, Error::Ok);
    if (!uuids.empty()) {
        std::vector<uint8_t> nonce(NSCQ_ATTESTATION_REPORT_NONCE_SIZE, 0);
        for (const auto& uuid : uuids) {
            SwitchTnvlMode tnvl_status;
            error = get_switch_tnvl_status(uuid, tnvl_status);
            ASSERT_EQ(error, Error::Ok);
            
            std::string cert_chain;
            error = get_attestation_cert_chain(uuid, cert_chain);
            ASSERT_EQ(error, Error::Ok);
            ASSERT_FALSE(cert_chain.empty());
            
            //TODO(p2): Verify the nonce
            std::vector<uint8_t> report;
            error = get_attestation_report(uuid, nonce, report);
            ASSERT_EQ(error, Error::Ok);
            ASSERT_FALSE(report.empty());
        }
    }
}

TEST_F(NscqIntegrationTest, NscqEvidenceCollectorGetEvidence) {
    NscqEvidenceCollector collector;
    std::vector<uint8_t> nonce(NSCQ_ATTESTATION_REPORT_NONCE_SIZE, 0);
    std::vector<std::shared_ptr<SwitchEvidence>> evidence_list;
    Error error = collector.get_evidence(nonce, evidence_list);
    ASSERT_EQ(error, Error::Ok);
    if (!evidence_list.empty()) {
        for (const auto& ev : evidence_list) {
            ASSERT_NE(ev->get_switch_architecture(), SwitchArchitecture::Unknown);
            ASSERT_FALSE(ev->get_uuid().empty());
            ASSERT_FALSE(ev->get_attestation_report().empty());
            ASSERT_FALSE(ev->get_attestation_cert_chain().empty());
        }
    }
}
#endif // ENABLE_NSCQ
