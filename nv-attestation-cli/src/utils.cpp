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

#include "utils.h"

namespace nvattest {
    void add_evidence_collection_options(CLI::App* app, EvidenceCollectionOptions& options) {
        app->add_option("--nonce", options.nonce, "Nonce for the attestation (in hex format). If not provided, a nonce will be generated.")
            ->default_val("");
        app->add_option("--device", options.device, "Device to attest ('gpu', 'nvswitch')")
            ->check(CLI::IsMember({"gpu", "nvswitch"}))
            ->default_val("gpu");
    }

    void add_evidence_policy_options(CLI::App* app, EvidencePolicyOptions& options) {
    }

    void add_evidence_verification_options(CLI::App* app, EvidenceVerificationOptions& options) {
        app->add_option("--verifier", options.verifier, "Verifier type ('local' or 'remote')")
            ->check(CLI::IsMember({"local", "remote"}))
            ->default_val("local");
        app->add_option("--relying-party-policy", options.relying_party_policy, "Path to a local file which contains a Relying Party Rego policy")->default_val("");
        app->add_option("--rim-url", options.rim_url, "Base URL for the NVIDIA RIM service")->default_val("https://rim.attestation.nvidia.com");
        app->add_option("--ocsp-url", options.ocsp_url, "Base URL for the OCSP responder")->default_val("https://ocsp.ndis.nvidia.com");
        app->add_option("--nras-url", options.nras_url, "Base URL for the NVIDIA Remote Attestation Service")->default_val("https://nras.attestation.nvidia.com");
        app->add_option("--gpu-evidence", options.gpu_evidence, "Path to a local file which contains GPU evidence. Used instead of calling NVML")->default_val("");
        app->add_option("--switch-evidence", options.switch_evidence, "Path to a local file which contains Switch evidence. Used instead of calling NSCQ")->default_val("");
        app->add_option("--service-key", options.service_key, "Service key used to authenticate remote service calls to attestation services")->default_val("");
    }

    void add_common_options(CLI::App& app, CommonOptions& options) {
        app.add_option("--log-level", options.log_level, "Log level ('trace', 'debug', 'info', 'warn', 'error', 'off')")
            ->check(CLI::IsMember({"trace", "debug", "info", "warn", "error", "off"}))
            ->default_val("warn");
    }
}
