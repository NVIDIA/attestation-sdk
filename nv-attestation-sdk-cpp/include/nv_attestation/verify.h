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

   public:
      OcspVerifyOptions() {}
   };

   class EvidencePolicy {
      public:
         EvidencePolicy(): 
             ocsp_options(OcspVerifyOptions()),
             gpu_claims_version(GpuClaimsVersion::V4),
             switch_claims_version(SwitchClaimsVersion::V3),
             verify_rim_signature(true),
             verify_rim_cert_chain(true) {}

         OcspVerifyOptions ocsp_options;
         GpuClaimsVersion gpu_claims_version;
         SwitchClaimsVersion switch_claims_version;
         bool verify_rim_signature;
         bool verify_rim_cert_chain;
   };

   Error validate_and_decode_EAT(
      const SerializableDetachedEAT& detached_eat,
      std::shared_ptr<JwkStore>& jwk_store,
      std::string& eat_issuer,
      NvHttpClient& http_client,
      const JwtValidationOptions& jwt_options,
      std::vector<uint8_t>& out_eat_nonce,
      std::unordered_map<std::string, std::string>& out_claims,
      bool& out_overall_result
   );

   // Maps the per-device claim payloads produced by validate_and_decode_EAT
   // (device_id -> claims-JSON string) into a typed ClaimsCollection, routing
   // each submod to its device-specific claims type. Network-free.
   Error map_submod_payloads_to_claims(
      const std::unordered_map<std::string, std::string>& device_claims_json,
      ClaimsCollection& out_claims
   );

   // Verifies a detached EAT (overall + per-device submod JWTs) against the
   // JWKS published at `nras_base_url`/.well-known/jwks.json, then maps the
   // verified payloads to a typed ClaimsCollection. The JWKS endpoint is public,
   // so `service_key` is optional; pass an empty string to send no credential.
   // When `expected_nonce` is non-empty, the token's overall eat_nonce must
   // equal it or Error::NonceMismatch is returned; an empty `expected_nonce`
   // skips the nonce check.
   Error verify_attestation_result(
      const std::string& detached_eat_json,
      const std::string& nras_base_url,
      const std::string& service_key,
      const HttpOptions& http_options,
      const JwtValidationOptions& jwt_options,
      const std::vector<uint8_t>& expected_nonce,
      ClaimsCollection& out_claims
   );

   Error verify_ear(
      const std::string& ear_jwt,
      const std::string& verifier_base_url,
      const std::string& service_key,
      const HttpOptions& http_options,
      const JwtValidationOptions& jwt_options,
      const std::vector<uint8_t>& expected_nonce,
      std::string& out_ear_json
   );

   class NRASAttestRequestV4 {
      public: 
         std::string nonce;
         std::string arch;
         std::string claims_version;
         // vector of evidence and certificate chain
         std::vector<std::pair<std::string, std::string>> evidence_list;
   };

   void to_json(nlohmann::json& json, const NRASAttestRequestV4& attest_request);

   Error handle_nras_error_claim(const nlohmann::json& nras_claims, nvat_devices_t device_type, const EvidencePolicy& evidence_policy);

}
