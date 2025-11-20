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


/*
To run this example, 
gcc main.c -o parallel-verification -pthread -lnvat
./parallel-verification
*/
#include <stdio.h>
#include <pthread.h>
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
    nvat_gpu_evidence_t* evidence_collection;
    size_t num_evidences;
    nvat_gpu_verifier_t verifier;
    nvat_claims_collection_t claims;
    nvat_ocsp_client_t ocsp_client;
    nvat_ocsp_client_t cached_ocsp_client;
    nvat_rim_store_t rim_store;
    nvat_rim_store_t cached_rim_store;
    nvat_str_t detached_eat_str;
} context_t;

/*
This struct is used for dividing the evidence verification
into multiple threads.
Each thread will take a subset of the total evidence and
verify it. 
It will populate the claims collection with the claims from the evidence
processed by the thread. It will also have the result of the verification.
*/
typedef struct {
    nvat_gpu_verifier_t verifier;
    nvat_gpu_evidence_t* evidences;
    size_t num_evidences;
    nvat_claims_collection_t claims;
    nvat_evidence_policy_t evidence_policy;
    nvat_rc_t result;
} thread_data_t;

/*
These functions are used to free the resources allocated for the context
and the thread data.
*/
void teardown(context_t ctx);
void thread_teardown(thread_data_t* data, int num_threads);

void print_nvat_rc(const char* msg, nvat_rc_t err) {
    printf("%s %s (nvat code: %03d)\n", msg, nvat_rc_to_string(err), err);
}

void* verify_thread_func(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    
    data->result = nvat_verify_gpu_evidence(
        data->verifier,
        data->evidences,
        data->num_evidences,
        data->evidence_policy,
        NULL,
        &data->claims
    );
    
    return NULL;
}

nvat_rc_t attest(void) {
    nvat_rc_t err;
    context_t ctx = {0};
    err = nvat_logger_spdlog_create(&ctx.logger, "parallel-verification", NVAT_LOG_LEVEL_ERROR);
    if (err != NVAT_RC_OK) {
        print_nvat_rc("nvat_logger_spdlog_create failed: ", err);
        teardown(ctx);
        return err;
    }
    err = nvat_sdk_opts_create(&ctx.opts);
    if (err != NVAT_RC_OK) {
        return err;
    }
    nvat_sdk_opts_set_logger(ctx.opts, ctx.logger);

    err = nvat_sdk_init(ctx.opts);
    if (err != NVAT_RC_OK) {
        print_nvat_rc("nvat_sdk_init failed: ", err);
        teardown(ctx);
        return err;
    }

    err = nvat_gpu_evidence_source_nvml_create(&ctx.evidence_source);
    if (err != NVAT_RC_OK) {
        print_nvat_rc("nvat_evidence_source_nvml_create failed: ", err);
        teardown(ctx);
        return err;
    }

    err = nvat_gpu_evidence_collect(ctx.evidence_source, NULL, &ctx.evidence_collection, &ctx.num_evidences);
    if (err != NVAT_RC_OK) {
        print_nvat_rc("nvat_gpu_evidence_collect failed: ", err);
        teardown(ctx);
        return err;
    }

    // URL can also be set using the NVAT_RIM_SERVICE_BASE_URL environment variable.
    err = nvat_rim_store_create_remote(&ctx.rim_store, NULL, NULL, NULL);
    if (err != NVAT_RC_OK) {
        print_nvat_rc("nvat_rim_store_create_remote failed: ", err);
        teardown(ctx);
        return err;
    }

    // URL can also be set using the NVAT_OCSP_RESPONSE_BASE_URL environment variable.
    err = nvat_ocsp_client_create_default(&ctx.ocsp_client, NULL, NULL, NULL);
    if (err != NVAT_RC_OK) {
        print_nvat_rc("nvat_ocsp_client_create_default failed: ", err);
        teardown(ctx);
        return err;
    }

    ctx.cached_rim_store = NULL;
    err = nvat_rim_store_create_cached(&ctx.cached_rim_store, ctx.rim_store, 1024*1024, 60*60);
    if (err != NVAT_RC_OK) {
        print_nvat_rc("nvat_rim_store_create_cached failed: ", err);
        teardown(ctx);
        return err;
    }

    ctx.cached_ocsp_client = NULL;
    err = nvat_ocsp_client_create_cached(&ctx.cached_ocsp_client, ctx.ocsp_client, 1024*1024, 60*60);
    if (err != NVAT_RC_OK) {
        print_nvat_rc("nvat_ocsp_client_create_cached failed: ", err);
        teardown(ctx);
        return err;
    }

    // this will not need to be free'd as we upcast it to the base GPU verifier type
    // and that will be free'd in the teardown
    nvat_gpu_local_verifier_t local_cached_verifier;
    err = nvat_gpu_local_verifier_create(&local_cached_verifier, ctx.cached_rim_store, ctx.cached_ocsp_client, NULL);
    if (err != NVAT_RC_OK) {
        print_nvat_rc("nvat_gpu_local_verifier_create failed: ", err);
        teardown(ctx);
        return err;
    }

    ctx.verifier = nvat_gpu_local_verifier_upcast(local_cached_verifier);
    if (ctx.verifier == NULL) {
        printf("nvat_gpu_local_verifier_upcast failed\n");
        teardown(ctx);
        return 1;
    }

    // divide the work between 4 threads and run them
    pthread_t threads[4];
    thread_data_t data[4];
    int num_threads = 4;
    int evidences_per_thread = ctx.num_evidences / num_threads;
    for (int i = 0; i < num_threads; i++) {
        data[i] = (thread_data_t){0};
        data[i].verifier = ctx.verifier;
        
        data[i].evidences = ctx.evidence_collection + i * evidences_per_thread;
        if (i == num_threads - 1) {
            data[i].num_evidences = ctx.num_evidences - i * evidences_per_thread;
        } else {
            data[i].num_evidences = evidences_per_thread;
        }
        data[i].claims = NULL;
        err = nvat_evidence_policy_create_default(&data[i].evidence_policy);
        if (err != NVAT_RC_OK) {
            print_nvat_rc("nvat_evidence_policy_create_default failed: ", err);
            thread_teardown(data, i);
            teardown(ctx);
            return 1;
        }
        data[i].result = NVAT_RC_INTERNAL_ERROR;
        pthread_create(&threads[i], NULL, verify_thread_func, &data[i]);
    }

    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
        if (data[i].result != NVAT_RC_OK) {
            print_nvat_rc("pthread_join failed: ", data[i].result);
            thread_teardown(data, 4);
            teardown(ctx);
            return 1;
        }
    }

    // combine the claims from all the threads - this is necessary 
    // to create a detached EAT that contains all the claims
    ctx.claims = data[0].claims;
    // setting this to NULL to avoid double free in thread_teardown and teardown
    // teardown frees ctx.claims and thread_teardown frees data[i].claims
    data[0].claims = NULL;
    for (int i = 1; i < 4; i++) {
        // data[i].claims is deep copied into ctx.claims, so it needs to be freed
        // along with ctx.claims. this is done in thread_teardown. so we will not 
        // set data[i].claims to NULL
        err = nvat_claims_collection_extend(ctx.claims, data[i].claims);
        if (err != NVAT_RC_OK) {
            print_nvat_rc("nvat_claims_collection_extend failed: ", err);
            thread_teardown(data, 4);
            teardown(ctx);
            return 1;
        }
    }

    err = nvat_get_detached_eat_es384(ctx.claims, NULL, &ctx.detached_eat_str);
    if (err != NVAT_RC_OK) {
        print_nvat_rc("nvat_get_detached_eat_es384 failed: ", err);
        thread_teardown(data, 4);
        teardown(ctx);
        return 1;
    }

    char* detached_eat_data = NULL;
    err = nvat_str_get_data(ctx.detached_eat_str, &detached_eat_data);
    if (err != NVAT_RC_OK) {
        print_nvat_rc("nvat_str_get_data failed: ", err);
        thread_teardown(data, 4);
        teardown(ctx);
        return 1;
    }

    printf("detached eat: %s\n", detached_eat_data);

    teardown(ctx);
    thread_teardown(data, 4);

    return 0;
}

void teardown(context_t ctx) {

    nvat_sdk_opts_free(&ctx.opts);
    nvat_logger_free(&ctx.logger);
    nvat_gpu_evidence_source_free(&ctx.evidence_source);
    nvat_gpu_evidence_array_free(&ctx.evidence_collection, ctx.num_evidences);
    nvat_gpu_verifier_free(&ctx.verifier);
    nvat_claims_collection_free(&ctx.claims);
    nvat_ocsp_client_free(&ctx.ocsp_client);
    nvat_rim_store_free(&ctx.rim_store);
    nvat_rim_store_free(&ctx.cached_rim_store);
    nvat_ocsp_client_free(&ctx.cached_ocsp_client);
    nvat_str_free(&ctx.detached_eat_str);
}

void thread_teardown(thread_data_t* data, int num_threads) {

    for (int i = 0; i < num_threads; i++) {
        nvat_claims_collection_free(&data[i].claims);
        nvat_evidence_policy_free(&data[i].evidence_policy);
    }
}

int main(int argc, char** argv) {
    nvat_rc_t err = attest();
    if (err != NVAT_RC_OK) {
        return 1;
    }
    return 0;
}

