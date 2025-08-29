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
This struct is used in the example to make memory management easier. 
In case of an error, we can just call teardown with this struct which 
will always free all the elements, even if they have not been allocated 
yet. The free functions are no-op if the argument is NULL and we initialize 
them to NULL in main 
*/
typedef struct context {
    nvat_sdk_opts_t opts;
    nvat_logger_t logger;
    nvat_gpu_evidence_source_t evidence_source;
    nvat_nonce_t nonce;
    nvat_str_t nonce_str;
    nvat_gpu_evidence_t* evidence_collection;
    nvat_str_t evidence_str;
    size_t num_evidences;
    nvat_gpu_verifier_t verifier;
    nvat_evidence_policy_t evidence_policy;
    nvat_claims_collection_t claims;
    nvat_str_t claims_str;
    nvat_ocsp_client_t ocsp_client;
    nvat_rim_store_t rim_store;
    nvat_str_t detached_eat_str;
} context_t;

nvat_rc_t attest(void);
void teardown(context_t ctx);

int main(void) {
    nvat_rc_t rc = attest();
    if (rc != NVAT_RC_OK) {
        fprintf(stderr, "collect_gpu_evidence failed: %s (nvat code: %03d)\n", nvat_rc_to_string(rc), rc);
        return 1;
    }
    return 0;
}

nvat_rc_t attest(void) {
    context_t ctx = {0};
    nvat_rc_t err;
    
    // Step 1: Initialize SDK with logging
    // Similar to previous examples, but includes setting up an SPDLog logger for detailed 
    // debugging output during evidence collection and verification
    err = nvat_sdk_opts_create(&ctx.opts);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }

    err = nvat_logger_spdlog_create(&ctx.logger, "nvat_collect_evidence", NVAT_LOG_LEVEL_DEBUG);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }
    nvat_sdk_opts_set_logger(ctx.opts, ctx.logger);

    err = nvat_sdk_init(ctx.opts);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }

    // Step 2: Set up evidence source and nonce
    // nvat_gpu_evidence_source_nvml_create creates an evidence source that uses NVML 
    // to communicate with NVIDIA GPUs and collect hardware attestation data
    err = nvat_gpu_evidence_source_nvml_create(&ctx.evidence_source);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }

    // nvat_nonce_create generates a cryptographically secure random nonce (32 bytes) 
    // that gets included in the attestation evidence to prevent replay attacks
    err = nvat_nonce_create(&ctx.nonce, 32);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }

    err = nvat_nonce_to_hex_string(ctx.nonce, &ctx.nonce_str);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }
    char * buf = NULL;
    err = nvat_str_get_data(ctx.nonce_str, &buf);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }
    fprintf(stderr, "nonce is %s\n", buf);

    // Step 3: Collect GPU evidence
    // nvat_gpu_evidence_collect gathers attestation evidence from the GPU, including 
    // measurements, certificates, and other cryptographic proofs
    // The evidence is then serialized to JSON format for inspection
    err = nvat_gpu_evidence_collect(ctx.evidence_source, ctx.nonce, &ctx.evidence_collection, &ctx.num_evidences);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }

    err = nvat_gpu_evidence_serialize_json(ctx.evidence_collection, ctx.num_evidences, &ctx.evidence_str);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }
    buf = NULL;
    err = nvat_str_get_data(ctx.evidence_str, &buf);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }
    fprintf(stdout, "gpu evidence: %s\n", buf);
    
    // Step 4: Set up verification components
    // The code creates the components needed for local verification:
    // - nvat_rim_store_create_remote: Creates a RIM (Reference Integrity Measurements) store 
    //   that connects to NVIDIA's remote service
    // - nvat_ocsp_client_create_default: Sets up OCSP client for certificate revocation checking
    // - nvat_gpu_local_verifier_create: Combines RIM store and OCSP client into a local verifier
    err = nvat_rim_store_create_remote(&ctx.rim_store, NULL, NULL);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }

    err = nvat_ocsp_client_create_default(&ctx.ocsp_client, NULL, NULL);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }

    nvat_gpu_local_verifier_t local_verifier;
    err = nvat_gpu_local_verifier_create(&local_verifier, ctx.rim_store, ctx.ocsp_client, NULL);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }
    ctx.verifier = nvat_gpu_local_verifier_upcast(local_verifier);

    err = nvat_evidence_policy_create_default(&ctx.evidence_policy);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }

    // Step 5: Verify evidence and produce claims
    // nvat_verify_gpu_evidence verifies the collected evidence against trusted references 
    // and produces attestation claims. The verification process includes:
    // - Certificate chain validation
    // - Signature verification  
    // - Measurement comparison against RIMs
    // - Certificate revocation checking via OCSP
    // This produces a claims set, which will be used to create a detached EAT
    err = nvat_verify_gpu_evidence(ctx.verifier, ctx.evidence_collection, ctx.num_evidences, ctx.evidence_policy, &ctx.detached_eat_str, &ctx.claims);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }

    err = nvat_claims_collection_serialize_json(ctx.claims, &ctx.claims_str);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }
    buf = NULL;
    err = nvat_str_get_data(ctx.claims_str, &buf);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }
    fprintf(stdout, "claims: %s\n", buf);

    err = nvat_str_get_data(ctx.detached_eat_str, &buf);
    if (err != NVAT_RC_OK) {
        teardown(ctx);
        return err;
    }
    fprintf(stdout, "detached eat: %s\n", buf);

    teardown(ctx);
    return NVAT_RC_OK;
}

void teardown(context_t ctx) {
    nvat_sdk_opts_free(&ctx.opts);
    nvat_logger_free(&ctx.logger);
    nvat_gpu_evidence_source_free(&ctx.evidence_source);
    nvat_nonce_free(&ctx.nonce);
    nvat_gpu_evidence_array_free(&ctx.evidence_collection, ctx.num_evidences);
    nvat_gpu_verifier_free(&ctx.verifier);
    nvat_claims_collection_free(&ctx.claims);
    nvat_evidence_policy_free(&ctx.evidence_policy);
    nvat_rim_store_free(&ctx.rim_store);
    nvat_ocsp_client_free(&ctx.ocsp_client);
    nvat_sdk_shutdown();
}
