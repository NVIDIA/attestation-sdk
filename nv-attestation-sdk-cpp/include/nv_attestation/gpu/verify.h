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

#include "nv_attestation/claims.h"
#include "nv_attestation/claims_evaluator.h"
#include "nv_attestation/nv_jwt.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/verify.h"
#include "nv_attestation/nv_http.h"
#include "evidence.h"
#include <memory>

namespace nvattestation {

/**
 * @brief Contract of a GPU verifier.
 */
class IGpuVerifier {
    public:
        virtual ~IGpuVerifier() = default;

        /**
         * @brief Verifies GPU evidence and produces claims to indicate the attestation result.
         * 
         * On successful verification, a GpuClaims object is returned which contains the validated attestation claims
         * 
         * @param evidence Attestation evidence to be verified
         * @param evidence_policy Policy used to evaluate GPU evidence
         * @return GpuClaims
         */
        virtual Error verify_evidence(const std::vector<std::shared_ptr<GpuEvidence>>& evidence, const EvidencePolicy& evidence_policy, std::string* out_detached_eat, ClaimsCollection& out_claims) = 0;
    private: 


};

/**
 * @brief Verifies GPU evidence locally.
 * 
 * Verify GpuEvidence in the current process.
 * The local verifier should be used either in:
 * - a TEE connected to the attester (the GPU)
 * - a remote attestation service running in a secure cloud environment
 * 
 * Local verification outside of these use cases is not recommended
 * as the verification process can be compromised by malicious actors
 * with elevated privileges on the host, rendering the verification
 * results unreliable.
 */
class LocalGpuVerifier : public IGpuVerifier {
    public:
        LocalGpuVerifier() = default;

        static Error create(LocalGpuVerifier& out_verifier, const std::shared_ptr<IRimStore>& rim_store, const std::shared_ptr<IOcspHttpClient>& ocsp_http_client, const DetachedEATOptions& detached_eat_options);

        /**
         * @brief Verifies GPU evidence locally and produces claims to indicate the attestation result.
         * 
         * On successful verification, a GpuClaims object is returned which contains the validated attestation claims.
         * 
         * @param evidence GPU evidence to be verified
         * @param evidence_policy Policy used to evaluate GPU evidence
         * @return GpuClaims
         */
        Error verify_evidence(const std::vector<std::shared_ptr<GpuEvidence>>& evidence, const EvidencePolicy& evidence_policy, std::string* out_detached_eat, ClaimsCollection& out_claims) override;
        
    private:
        std::shared_ptr<IRimStore> m_rim_store;
        std::shared_ptr<IOcspHttpClient> m_ocsp_http_client;
        DetachedEATOptions m_detached_eat_options;
        
        Error generate_claims_v3(const std::vector<std::shared_ptr<GpuEvidence>>& evidence, const EvidencePolicy& policy, std::string* out_detached_eat, ClaimsCollection& out_claims) const;
        static Error set_gpu_evidence_claims(const GpuEvidenceClaims& gpu_evidence_claims, const EvidencePolicy& policy, SerializableGpuClaimsV3& out_serializable_claims);
        Error set_driver_rim_claims(const RimDocument& driver_rim_document, const EvidencePolicy& policy, SerializableGpuClaimsV3& out_serializable_claims) const;
        Error set_vbios_rim_claims(const RimDocument& vbios_rim_document, const EvidencePolicy& policy, SerializableGpuClaimsV3& out_serializable_claims) const;
        static Error generate_set_measurement_claims(const Measurements& golden_driver_measurements, const Measurements& golden_vbios_measurements, const GpuEvidence::AttestationReport& attestation_report, const EvidencePolicy& policy, SerializableGpuClaimsV3& out_serializable_claims);
};

/**
 * @brief Verifies GPU evidence using the [NVIDIA Remote Attestation Service](https://docs.nvidia.com/attestation/api-docs-nras/latest/nras_api.html).
 */
class NvRemoteGpuVerifier : public IGpuVerifier {
    public:
        static constexpr const char* DEFAULT_BASE_URL = "https://nras.attestation.nvidia.com";

        static Error init_from_env(NvRemoteGpuVerifier& out_verifier, const char* nras_url=DEFAULT_BASE_URL, HttpOptions http_options = HttpOptions());
        Error verify_evidence(const std::vector<std::shared_ptr<GpuEvidence>>& evidence, const EvidencePolicy& evidence_policy, std::string* out_detached_eat, ClaimsCollection& out_claims) override;

    private:
        std::string m_nras_url;
        std::string m_eat_issuer;
        NvHttpClient m_http_client;
        std::shared_ptr<JwkStore> m_jwk_store;
};

}