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

#include "nvat.h"
#include <string>
#include <vector>
#include <unordered_map>

#include "nv_attestation/error.h"
#include "nv_attestation/nv_jwt.h"
#include <nlohmann/json.hpp>
#include "nv_attestation/gpu/claims.h"
#include "nv_attestation/switch/claims.h"
#include "nv_attestation/nv_http.h"

namespace nvattestation
{
   enum class VerifierType {
      Local,
      Remote,
   };

   Error verifier_type_from_c(nvat_verifier_type_t c_type, VerifierType& out_type);
   std::string to_string(VerifierType verifier_type);

   class OcspVerifyOptions
   {
   private:
      bool m_nonce_enabled;
      bool m_allow_cert_hold;

   public:
      OcspVerifyOptions() : m_nonce_enabled(true), m_allow_cert_hold(false) {}
      void set_nonce_enabled(bool enabled);
      bool get_nonce_enabled() const;
      void set_allow_cert_hold(bool allow_cert_hold);
      bool get_allow_cert_hold() const;
   };

   class EvidencePolicy {
      public:
         EvidencePolicy(): 
             ocsp_options(OcspVerifyOptions()),
             gpu_claims_version(GpuClaimsVersion::V3),
             switch_claims_version(SwitchClaimsVersion::V3),
             verify_rim_signature(true) {}

         OcspVerifyOptions ocsp_options;
         GpuClaimsVersion gpu_claims_version;
         SwitchClaimsVersion switch_claims_version;
         bool verify_rim_signature;
   };

   class NRASAttestResponseV4 {
      public: 
         std::string overall_jwt_token;
         std::unordered_map<std::string, std::string> device_attest_responses;
   };

   Error validate_and_decode_EAT(
      const NRASAttestResponseV4& attest_response,
      std::shared_ptr<JwkStore>& jwk_store,
      std::string& eat_issuer,
      NvHttpClient& http_client,
      std::vector<uint8_t>& out_eat_nonce,
      std::unordered_map<std::string, std::string>& out_claims
   );

   class NRASAttestRequestV4 {
      public: 
         std::string nonce;
         std::string arch;
         std::string claims_version;
         // vector of evidence and certificate chain
         std::vector<std::pair<std::string, std::string>> evidence_list;
   };

   void from_json(const nlohmann::json& json, NRASAttestResponseV4& attest_response);

   void to_json(nlohmann::json& json, const NRASAttestRequestV4& attest_request);

}