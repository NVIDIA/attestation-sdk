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

#include "test_utils.h"
#include "nv_attestation/gpu/claims.h"
#include "nv_attestation/claims.h"

// Default constructor implementation with Hopper GPU data
MockGpuEvidenceData::MockGpuEvidenceData()
    : architecture(GpuArchitecture::Hopper),
      board_id(11111),
      uuid("GPU-11111111-2222-3333-4444-555555555555"),
      vbios_version("96.00.9F.00.01"),
      driver_version("550.90.07"),
      nonce("931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"),
      attestation_report_path("testdata/hopperAttestationReport.txt"),
      attestation_cert_chain_path("testdata/hopperCertChain.txt") {
}

// Factory method implementations for MockGpuEvidenceData

MockGpuEvidenceData MockGpuEvidenceData::create_default() {
    return MockGpuEvidenceData();
}

MockGpuEvidenceData MockGpuEvidenceData::create_bad_nonce_scenario() {
    return MockGpuEvidenceData(
        GpuArchitecture::Hopper,
        11111,
        "GPU-11111111-2222-3333-4444-555555555555",
        "96.00.5E.00.01",
        "535.86.09",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "testdata/sample_attestation_data/gpu/hopperAttestationReport.txt",
        "testdata/sample_attestation_data/gpu/hopperCertChain.txt"
    ); 
}

MockGpuEvidenceData MockGpuEvidenceData::create_invalid_signature_scenario() {
    return MockGpuEvidenceData(
        GpuArchitecture::Hopper,
        11111,
        "GPU-11111111-2222-3333-4444-555555555555",
        "96.00.9F.00.01",
        "550.90.07",
        "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb",
        "testdata/sample_attestation_data/gpu/hopperAttestationReportInvalidSignature.txt",
        "testdata/sample_attestation_data/gpu/hopperCertChainExpired.txt"
    );
}

MockGpuEvidenceData MockGpuEvidenceData::create_expired_driver_rim_scenario() {
    return MockGpuEvidenceData(
        GpuArchitecture::Hopper,
        11111,
        "GPU-11111111-2222-3333-4444-555555555555",
        "96.00.5E.00.04",
        "570.124.03",
        "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb",
        "testdata/sample_attestation_data/gpu/hopperAttestationReportExpired.txt",
        "testdata/sample_attestation_data/gpu/hopperCertChainExpired.txt"
    );
}

MockGpuEvidenceData MockGpuEvidenceData::create_measurements_mismatch_scenario() {
    return MockGpuEvidenceData(
        GpuArchitecture::Hopper,
        11111,
        "GPU-11111111-2222-3333-4444-555555555555",
        "96.00.5E.00.01",
        "535.86.09",
        "27a328247bf7935c993341cf587be6f05986ccce4fe7ba2c54100bd616a58f66",
        "testdata/sample_attestation_data/gpu/hopperAttestationReport.txt",
        "testdata/sample_attestation_data/gpu/hopperCertChain.txt"
    );
}

MockGpuEvidenceData MockGpuEvidenceData::create_blackwell_scenario() {
    return MockGpuEvidenceData(
        GpuArchitecture::Blackwell,
        11111,
        "GPU-11111111-2222-3333-4444-555555555555",
        "97.00.88.00.0F",
        "575.32",
        "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb",
        "testdata/sample_attestation_data/gpu/blackwellAttestationReport.txt",
        "testdata/sample_attestation_data/gpu/blackwellCertChain.txt"
    );
}

Error get_git_repo_root(std::string& out_git_repo_root) {
    std::string git_cmd = "git rev-parse --show-toplevel 2>/dev/null";
    FILE* pipe = popen(git_cmd.c_str(), "r");
    if (pipe) {
        char buffer[1024];
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            std::string repo_root = std::string(buffer);
            if (!repo_root.empty() && repo_root.back() == '\n') {
                repo_root.pop_back();
            }
            out_git_repo_root = repo_root;
            return Error::Ok;
        }
    }
    return Error::InternalError;
}