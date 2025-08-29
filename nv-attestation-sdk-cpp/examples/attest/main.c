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

#include <stdio.h>

#include <nvat.h>

nvat_rc_t attest(nvat_attestation_ctx_t*);

const char* REGO_RP_POLICY =
  "package policy\n"
  "import future.keywords.every\n"
  "default nv_match := false\n"
  "nv_match {\n"
  "  every result in input {\n"
  "    result[\"x-nvidia-device-type\"] == \"gpu\"\n"
  "    result.secboot\n"
  "    result.dbgstat == \"disabled\"\n"
  "  }\n"
  "}\n";

int main(void) {
  nvat_attestation_ctx_t ctx;
  nvat_rc_t rc = attest(&ctx);
  if (ctx != NULL) {
    nvat_attestation_ctx_free(&ctx);
  }
  nvat_sdk_shutdown();
  switch(rc) {
    case NVAT_RC_OK:
        return 0;
    case NVAT_RC_RP_POLICY_MISMATCH:
        fprintf(stderr, "attestation results did not match relying party policy (nvat code: %03d)\n", rc);
        return 2;
    default:
        fprintf(stderr, "system attestation failed: %s (nvat code: %03d)\n",
                nvat_rc_to_string(rc), rc);
        return 1;
  }
}

nvat_rc_t attest(nvat_attestation_ctx_t* ctx) {
  nvat_rc_t err;

  nvat_sdk_opts_t opts;
  err = nvat_sdk_opts_create(&opts);
  if (err != NVAT_RC_OK) {
      return err;
  }
  nvat_sdk_opts_set_enabled_device_drivers(opts, NVAT_DEVICE_GPU);

  err = nvat_sdk_init(&opts);
  if (err != NVAT_RC_OK) {
      nvat_sdk_opts_free(&opts);
      return err;
  }

  err = nvat_attestation_ctx_create(ctx, NVAT_DEVICE_GPU);
  if (err != NVAT_RC_OK) {
    return err;
  }

  nvat_relying_party_policy_t rp_policy;
  err = nvat_relying_party_policy_create_rego_from_str(&rp_policy, REGO_RP_POLICY);
  if (err != NVAT_RC_OK) {
    return err;
  }

  nvat_attestation_ctx_set_relying_party_policy(*ctx, rp_policy);
  nvat_relying_party_policy_free(&rp_policy);
  nvat_attestation_ctx_set_verifier_type(*ctx, NVAT_VERIFY_LOCAL);

  nvat_claims_collection_t claims;
  err = nvat_attest_system(*ctx, NULL, &claims);
  if (err != NVAT_RC_OK) {
    return err;
  }

  nvat_str_t json_str;
  err = nvat_claims_collection_serialize_json(claims, &json_str);
  nvat_claims_collection_free(&claims);
  if (err != NVAT_RC_OK) {
    return err;
  }
  char * buf = NULL;
  err = nvat_str_get_data(json_str, &buf);
  if (err != NVAT_RC_OK) {
    return err;
  }
  fprintf(stdout, "%s\n", buf);

  return NVAT_RC_OK;
}
