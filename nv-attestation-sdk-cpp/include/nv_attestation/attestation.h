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

#include <cstdint>
#include <memory>
#include <nvat.h>
#include <vector>

#include "claims_evaluator.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/verify.h"
#include "rim.h"
#include "log.h"
#include "gpu/evidence.h"
#include "nv_http.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/gpu/verify.h"
#include "nv_attestation/switch/evidence.h"
#include "nv_attestation/switch/verify.h"

using namespace std;

namespace nvattestation {

using Nonce = vector<uint8_t>; // TODO(p2): find better place to declare these

class AttestationContext {
    private:
        VerifierType m_default_verifier_type;
        HttpOptions m_default_http_options;
        shared_ptr<IOcspHttpClient> m_default_ocsp_client;
        std::string m_default_ocsp_url;
        shared_ptr<IRimStore> m_default_rim_store;
        std::string m_default_rim_store_url;

        bool m_gpu_enabled; 
        shared_ptr<IGpuEvidenceSource> m_gpu_evidence_source;
        shared_ptr<IGpuVerifier> m_gpu_verifier;

        bool m_switch_enabled;
        shared_ptr<ISwitchEvidenceSource> m_switch_evidence_source;
        shared_ptr<ISwitchVerifier> m_switch_verifier;
        std::string m_default_nras_url;

        EvidencePolicy m_evidence_policy;
        shared_ptr<IClaimsEvaluator> m_claims_evaluator;

        Error ensure_init();
        Error attest_gpus(Nonce& nonce, ClaimsCollection& out_claims);
        Error attest_switches(Nonce& nonce, ClaimsCollection& out_claims);

    public:
        AttestationContext(nvat_devices_t devices) :
            nvattestation::AttestationContext(
                NVAT_DEVICE_IS_SET(devices, NVAT_DEVICE_GPU),
                NVAT_DEVICE_IS_SET(devices, NVAT_DEVICE_NVSWITCH)
            ) {}

        AttestationContext(bool enable_gpu, bool enable_switch) :
            m_default_verifier_type(VerifierType::Remote),
            m_default_http_options(HttpOptions{}),
            m_default_ocsp_client(nullptr),
            m_default_ocsp_url(""),
            m_default_rim_store(nullptr),
            m_default_rim_store_url(""),
            m_gpu_enabled(enable_gpu),
            m_gpu_evidence_source(nullptr),
            m_gpu_verifier(nullptr),
            m_switch_enabled(enable_switch),
            m_switch_evidence_source(nullptr),
            m_switch_verifier(nullptr),
            m_default_nras_url(""),
            m_evidence_policy(EvidencePolicy()),
            m_claims_evaluator(nullptr) {}


        ~AttestationContext() = default;

        void set_verifier_type(VerifierType verifier_type);
        void set_default_http_options(HttpOptions);
        void set_default_rim_store_url(const char* rim_store_url);
        void set_default_ocsp_url(const char* ocsp_url);
        void set_default_nras_url(const char* nras_url);
        void set_default_rim_store(shared_ptr<IRimStore> rim_store);
        void set_default_ocsp_client(shared_ptr<IOcspHttpClient> ocsp_client);
        void set_evidence_policy(EvidencePolicy policy);
        void set_claims_evaluator(shared_ptr<IClaimsEvaluator> claims_evaluator);
        void set_gpu_evidence_source(shared_ptr<IGpuEvidenceSource> evidence_source);
        void set_switch_evidence_source(shared_ptr<ISwitchEvidenceSource> evidence_source);
        Error set_gpu_evidence_source_json_file(const std::string& file_path);
        Error set_switch_evidence_source_json_file(const std::string& file_path);
        void set_gpu_verifier(shared_ptr<IGpuVerifier> verifier);
        void set_switch_verifier(shared_ptr<ISwitchVerifier> verifier);

        Error attest_system(
            Nonce nonce,
            ClaimsCollection& out_claims
        );
};
}
