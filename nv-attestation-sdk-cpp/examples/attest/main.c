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

/*
The high level API to attest NVIDIA GPU and/or NVSwitches is `nvat_attest_device`. This examples uses that API to perform local attestation for a GPU. 

Using that API involves creating an attestation context (`nvat_attestation_ctx_t`), which can be used to configure the behavior of `nvat_attest_device`. 
Please refer to API documentation of `nvat_attestation_ctx_create` to see the default options that will be used, which can changed.

The `nvat_attest_device` function returns 3 things: the detached EAT produced as the result of attestation, the claims set (as a JSON string) that are part of the EAT, and the result of applying relying party policy to the claims set. 

The steps involved in this example are: 
* Create SDK options and initialize the SDK
* Create the attestation context and configure it: 
	* Set verifier type to local (if not set default is local)
	* Set the device(s) to be attested (if not set default is GPU)
	* Set the relying part policy (optional, see `nvat_attest_device` for more info)
* Call `nvat_attest_device`
* Print the detached EAT for inspection
*/

/*
This is a sample rego policy which is used to show how a custom relying party policy can be created using rego.
*/
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
    case NVAT_RC_OVERALL_RESULT_FALSE: 
        fprintf(stderr, "overall attestation result fail (nvat code: %03d)\n", rc);
        return 3;
    default:
        fprintf(stderr, "system attestation failed: %s (nvat code: %03d)\n",
                nvat_rc_to_string(rc), rc);
        return 1;
  }
}

/*
This is a helper function which is called from main. It creates the attestation context, sets some options on it to show how the context can be modified to configure the attestation process and then finally calls `nvat_attest_device` to perform the attestation. 
*/
nvat_rc_t attest(nvat_attestation_ctx_t* ctx) {
  nvat_rc_t err;
  char * buf = NULL;

  // Step 1: Create and configure SDK options
  nvat_sdk_opts_t opts;
  err = nvat_sdk_opts_create(&opts);
  if (err != NVAT_RC_OK) {
      return err;
  }

  // Step 2: Initialize the SDK with the options defined above.
  // This must be called before any other SDK operations to initialize global 
  // dependencies such as the logger
  err = nvat_sdk_init(opts);
  if (err != NVAT_RC_OK) {
      nvat_sdk_opts_free(&opts);
      return err;
  }

  // Step 3: Create attestation context for GPU devices.
  // This context holds configuration for evidence collection, verification, and policy evaluation
  err = nvat_attestation_ctx_create(ctx);
  if (err != NVAT_RC_OK) {
    nvat_sdk_opts_free(&opts);
    nvat_sdk_shutdown();
    return err;
  }
  
  // Set the devices to be attested. Default is GPU
  err = nvat_attestation_ctx_set_device_type(*ctx, NVAT_DEVICE_GPU);
  if (err != NVAT_RC_OK) {
    nvat_attestation_ctx_free(ctx);
    nvat_sdk_opts_free(&opts);
    nvat_sdk_shutdown();
    return err;
  }

  // Step 4: Define trust requirements by setting up a relying party policy.
  nvat_relying_party_policy_t rp_policy;
  err = nvat_relying_party_policy_create_rego_from_str(&rp_policy, REGO_RP_POLICY);
  if (err != NVAT_RC_OK) {
    nvat_attestation_ctx_free(ctx);
    nvat_sdk_opts_free(&opts);
    nvat_sdk_shutdown();
    return err;
  }

  // Set the context to use policy handle that we created above
  nvat_attestation_ctx_set_relying_party_policy(*ctx, rp_policy);
  
  // all the handles are opaque pointers, which are refcounted. So this needs to be 
  // free'ed by the client and when the ctx is free'ed, the relying party policy 
  // handle will finally be free'd
  nvat_relying_party_policy_free(&rp_policy);
  nvat_attestation_ctx_set_verifier_type(*ctx, NVAT_VERIFY_LOCAL);

  // Step 5: Perform system attestation
  // nvat_attest_device performs the complete attestation workflow - collecting evidence from GPUs,
  // verifying it against trusted references, and evaluating results against the relying party policy
  // returns NVAT_RC_OK is system is trustworthy according to RP policy or NVAT_RC_RP_POLICY_MISMATCH if the policy rejected the results. (if RP policy is not provided, this return code indicates that the overall result in the detached EAT is true)
  // it can also optionally return the claims set that is part of the EAT
  nvat_claims_collection_t claims;
  nvat_str_t detached_eat;
  err = nvat_attest_device(*ctx, NULL, &detached_eat, &claims);
  if (err != NVAT_RC_OK) {
    nvat_attestation_ctx_free(ctx);
    nvat_sdk_opts_free(&opts);
    nvat_sdk_shutdown();
    return err;
  }

  // Step 6: Serialize and display results
  // The detached EAT is a serialized JSON object. We will get the string data and print it 
  char * detached_buf = NULL;
  err = nvat_str_get_data(detached_eat, &detached_buf);
  if (err != NVAT_RC_OK) {
    nvat_attestation_ctx_free(ctx);
    nvat_sdk_opts_free(&opts);
    nvat_sdk_shutdown();
    nvat_claims_collection_free(&claims);
    nvat_str_free(&detached_eat);
    return err;
  }
  
  printf("Detached EAT: %s\n", detached_buf);
  nvat_str_free(&detached_eat);

  nvat_str_t json_str;
  err = nvat_claims_collection_serialize_json(claims, &json_str);
  if (err != NVAT_RC_OK) {
    nvat_attestation_ctx_free(ctx);
    nvat_sdk_opts_free(&opts);
    nvat_sdk_shutdown();
    nvat_claims_collection_free(&claims);
    return err;
  }
  err = nvat_str_get_data(json_str, &buf);
  if (err != NVAT_RC_OK) {
    nvat_attestation_ctx_free(ctx);
    nvat_sdk_opts_free(&opts);
    nvat_sdk_shutdown();
    nvat_claims_collection_free(&claims);
    nvat_str_free(&json_str);
    return err;
  }
  fprintf(stdout, "%s\n", buf);

  // Cleanup resources
  nvat_str_free(&json_str);
  nvat_attestation_ctx_free(ctx);
  nvat_sdk_opts_free(&opts);
  nvat_sdk_shutdown();
  nvat_claims_collection_free(&claims);

  return NVAT_RC_OK;
}
