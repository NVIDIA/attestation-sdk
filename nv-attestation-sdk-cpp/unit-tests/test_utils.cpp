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

#include <cstdlib>
#include <iostream>
#include <sstream>

#include "nv_attestation/gpu/claims.h"
#include "nv_attestation/claims.h"

namespace {

std::string render_value(const nlohmann::json& v) {
    if (v.is_object()) {
        return "<object with " + std::to_string(v.size()) + " field(s)>";
    }
    if (v.is_array()) {
        return "<array of " + std::to_string(v.size()) + ">";
    }
    return v.dump();
}

std::string format_diff(const nlohmann::json& patch, const nlohmann::json& expected) {
    std::ostringstream out;
    out << patch.size() << " mismatch(es) between actual and golden:\n";
    for (const auto& op : patch) {
        const std::string kind = op.at("op").get<std::string>();
        const std::string path = op.at("path").get<std::string>();
        const std::string display_path = path.empty() ? "<root>" : path;
        if (kind == "replace") {
            auto exp = expected.at(nlohmann::json::json_pointer(path));
            out << "  changed value at " << display_path << "\n"
                << "      golden: " << render_value(exp) << "\n"
                << "      actual: " << render_value(op.at("value")) << "\n";
        } else if (kind == "add") {
            out << "  actual has extra field at " << display_path
                << " = " << render_value(op.at("value")) << "\n";
        } else if (kind == "remove") {
            auto exp = expected.at(nlohmann::json::json_pointer(path));
            out << "  actual is missing field at " << display_path
                << " (golden had: " << render_value(exp) << ")\n";
        } else {
            out << "  " << kind << " at " << display_path << "\n";
        }
    }
    return out.str();
}

} // namespace

void compare_to_golden(const nlohmann::json& actual, const std::string& golden_path) {
    if (std::getenv("REGEN_GOLDENS") != nullptr) {
        std::ofstream out(golden_path);
        ASSERT_TRUE(out.is_open()) << "Cannot open golden for write: " << golden_path;
        out << actual.dump(2) << "\n";
        std::cerr << "REGEN: wrote " << golden_path << std::endl;
        return;
    }
    std::ifstream in(golden_path);
    ASSERT_TRUE(in.is_open())
        << "Missing golden: " << golden_path << " (run with REGEN_GOLDENS=1)";
    nlohmann::json expected;
    in >> expected;
    auto patch = nlohmann::json::diff(expected, actual);
    EXPECT_TRUE(patch.empty())
        << "Golden mismatch for '" << golden_path << "':\n"
        << format_diff(patch, expected);
}

// Default constructor implementation with Hopper GPU data
MockGpuEvidenceData::MockGpuEvidenceData()
    : architecture(GpuArchitecture::Hopper),
      board_id(11111),
      uuid("GPU-11111111-2222-3333-4444-555555555555"),
      vbios_version("96.00.74.00.20"),
      driver_version("580.159.03"),
      nonce("5bb22e377702d4e1e8215a903ba094826b9ac7f731dee1fe8102958bf2840aca"),
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

MockGpuEvidenceData MockGpuEvidenceData::create_rubin_scenario() {
    // Placeholder vbios/driver/nonce — overwrite when real Rubin fixtures land in
    // testdata/sample_attestation_data/gpu/rubin*.txt.
    return MockGpuEvidenceData(
        GpuArchitecture::Rubin,
        11111,
        "GPU-11111111-2222-3333-4444-555555555555",
        "00.00.00.00.00",
        "0.00",
        "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb",
        "testdata/sample_attestation_data/gpu/rubinAttestationReport.txt",
        "testdata/sample_attestation_data/gpu/rubinCertChain.txt"
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