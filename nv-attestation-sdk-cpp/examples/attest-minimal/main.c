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

/*
 * Minimal GPU Attestation Example
 * To run: gcc -o attest-minimal main.c -lnvat && ./attest-minimal
 */

int main(void) {
  nvat_sdk_opts_t opts=NULL;
  nvat_attestation_ctx_t ctx=NULL;
  nvat_str_t detached_eat=NULL;
  nvat_claims_collection_t claims=NULL;
  char *claims_data=NULL;
  char *detached_eat_data = NULL;
  nvat_str_t claims_json=NULL;
  nvat_str_t detached_eat_str=NULL;

  // Initialize SDK
  nvat_sdk_opts_create(&opts);
  nvat_sdk_init(opts);

  // Create attestation context
  nvat_attestation_ctx_create(&ctx);

  // Perform attestation
  if (nvat_attest_device(ctx, NULL, &detached_eat, &claims) != NVAT_RC_OK) {
    fprintf(stderr, "Attestation failed\n");
    // free opts and ctx
    return 1;
  }

  // Display claims
  // The return codes must be checked for errors and resources 
  // must be freed appropriately.
  nvat_claims_collection_serialize_json(claims, &claims_json);
  nvat_str_get_data(claims_json, &claims_data);
  printf("Claims: \n%s\n", claims_data);

  // Display detached EAT
  nvat_str_get_data(detached_eat, &detached_eat_data);
  printf("Detached EAT: \n%s\n", detached_eat_data);

  // Cleanup
  nvat_str_free(&claims_json);
  nvat_claims_collection_free(&claims);
  nvat_str_free(&detached_eat);
  nvat_attestation_ctx_free(&ctx);
  nvat_sdk_opts_free(&opts);
  nvat_sdk_shutdown();

  return 0;
}
