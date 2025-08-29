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

#include "switch_test_utils.h"

MockSwitchEvidenceData::MockSwitchEvidenceData()
    : architecture(SwitchArchitecture::LS10),
      uuid("SWITCH-11111111-2222-3333-4444-555555555555"),
      bios_version("96.10.55.00.01"),
      nonce("931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"),
      attestation_report_path("testdata/switchAttestationReport.txt"),
      attestation_cert_chain_path("testdata/switchCertChain.txt"),
      tnvl_mode(true),
      lock_mode(true) {
}

// Factory method implementations for MockSwitchEvidenceData

MockSwitchEvidenceData MockSwitchEvidenceData::create_default() {
    return MockSwitchEvidenceData();
}

MockSwitchEvidenceData MockSwitchEvidenceData::create_bad_nonce_scenario() {
    return MockSwitchEvidenceData(
        SwitchArchitecture::LS10,
        "SWITCH-11111111-2222-3333-4444-555555555555",
        "96.10.55.00.01",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "testdata/sample_attestation_data/switch/switchAttestationReport.txt",
        "testdata/sample_attestation_data/switch/switchCertChain.txt",
        true,
        true
    ); 
}

MockSwitchEvidenceData MockSwitchEvidenceData::create_bad_rim_signature_scenario() {
    return MockSwitchEvidenceData(
        SwitchArchitecture::LS10,
        "SWITCH-11111111-2222-3333-4444-555555555555",
        "96.10.55.00.01",
        "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb",
        "testdata/sample_attestation_data/switch/switchAttestationReport.txt",
        "testdata/sample_attestation_data/switch/switchCertChain.txt",
        true,
        true
    );
}

MockSwitchEvidenceData MockSwitchEvidenceData::create_measurements_mismatch_scenario() {
    return MockSwitchEvidenceData(
        SwitchArchitecture::LS10,
        "SWITCH-11111111-2222-3333-4444-555555555555",
        "96.10.55.00.01",
        "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb",
        "testdata/sample_attestation_data/switch/switchAttestationReport.txt",
        "testdata/sample_attestation_data/switch/switchCertChain.txt",
        true,
        true
    );
}

MockSwitchEvidenceData MockSwitchEvidenceData::create_invalid_signature_scenario() {
    return MockSwitchEvidenceData(
        SwitchArchitecture::LS10,
        "SWITCH-11111111-2222-3333-4444-555555555555",
        "96.10.55.00.01",
        "EA038ED507A451E005BAE91186BC9403150A3CB8971FDEBD05FFED65EEB6A997",
        "testdata/sample_attestation_data/switch/switchAttestationReportInvalidSignature.txt",
        "testdata/sample_attestation_data/switch/switchCertChain.txt",
        true,
        true
    );
}
