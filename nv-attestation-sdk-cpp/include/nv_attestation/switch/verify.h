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

#include "nv_attestation/switch/evidence.h"
#include "nv_attestation/switch/claims.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/error.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/verify.h"

namespace nvattestation {

struct SwitchVerifyOptions {
    SwitchClaimsVersion requested_claims_version;
    OcspVerifyOptions ocsp_options;

    SwitchVerifyOptions(SwitchClaimsVersion requested_claims_version, OcspVerifyOptions ocsp_options) : requested_claims_version(requested_claims_version), ocsp_options(ocsp_options) {}
    SwitchVerifyOptions() : requested_claims_version(SwitchClaimsVersion::V3), ocsp_options(OcspVerifyOptions()) {}
};

class ISwitchVerifier {
    public:
        virtual ~ISwitchVerifier() = default;
        virtual Error verify_evidence(const std::vector<std::shared_ptr<SwitchEvidence>>& evidence, const EvidencePolicy& evidence_policy, ClaimsCollection& out_claims) = 0;
};

class LocalSwitchVerifier : public ISwitchVerifier {
    public:
        static Error create(LocalSwitchVerifier& out_verifier, const std::shared_ptr<IRimStore>& rim_store = nullptr, const std::shared_ptr<IOcspHttpClient>& ocsp_http_client = nullptr);
        Error verify_evidence(const std::vector<std::shared_ptr<SwitchEvidence>>& evidence, const EvidencePolicy& evidence_policy, ClaimsCollection& out_claims) override;
    private:
        std::shared_ptr<IRimStore> m_rim_store;
        std::shared_ptr<IOcspHttpClient> m_ocsp_http_client;

        Error generate_claims_v3(const std::vector<std::shared_ptr<SwitchEvidence>>& evidence, const EvidencePolicy& evidence_policy, ClaimsCollection& out_claims) const;
        static Error set_switch_evidence_claims(const SwitchEvidenceClaims& switch_evidence_claims, SerializableSwitchClaimsV3& out_serializable_claims);
        Error set_vbios_rim_claims(const RimDocument& vbios_rim, const EvidencePolicy& evidence_policy, SerializableSwitchClaimsV3& out_serializable_claims) const ;
        static Error generate_set_measurement_claims(const Measurements& golden_measurements, const SwitchEvidence::AttestationReport& attestation_report, SerializableSwitchClaimsV3& out_serializable_claims);
};

class NvRemoteSwitchVerifier : public ISwitchVerifier {
    public:
        static constexpr const char* DEFAULT_BASE_URL = "https://nras.attestation.nvidia.com";

        static Error init_from_env(NvRemoteSwitchVerifier& out_verifier, const char* nras_url=DEFAULT_BASE_URL, HttpOptions http_options = HttpOptions());
        Error verify_evidence(const std::vector<std::shared_ptr<SwitchEvidence>>& evidence, const EvidencePolicy& evidence_policy, ClaimsCollection& out_claims) override;
    private:
        std::string m_nras_url;
        std::string m_eat_issuer;
        NvHttpClient m_http_client;
        std::shared_ptr<JwkStore> m_jwk_store;
};

}