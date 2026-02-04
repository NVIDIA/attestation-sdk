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
#include "nvat.h"

namespace nvattest {

    struct EvidenceCollectionOptions {
        std::string nonce;
        std::string device; // gpu, nvswitch
        std::string gpu_evidence_source; // nvml, corelib, file
        std::string switch_evidence_source; // nscq, file
        std::string gpu_evidence_file;
        std::string switch_evidence_file;
        std::string gpu_architecture; // Required for corelib

        std::string pretty_device() const {
            if (device == "gpu") return "GPU";
            if (device == "nvswitch") return "NVSwitch";
            return device;
        }
    };

    struct EvidencePolicyOptions {
        bool verify_rim_signature = true;
        bool verify_rim_cert_chain = true;
    };

    struct EvidenceVerificationOptions {
        std::string verifier;
        std::string relying_party_policy;
        std::string rim_store; // remote, dir
        std::string rim_url; // if remote
        std::string rim_path; // if dir
        std::string ocsp_url;
        std::string nras_url;
        std::string service_key;
    };

    struct CommonOptions {
        std::string log_level_str;
        std::string format;

        nvat_log_level_t get_log_level() const;
    };

}
