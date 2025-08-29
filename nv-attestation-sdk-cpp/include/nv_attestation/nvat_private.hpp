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

// TODO(p2): Eventually move and other headers into src to be truly private
// TODO(p2): Better filename may be c_types?
#pragma once

#include "log.h"
#include "error.h"
#include "init.h"
#include "gpu/evidence.h"
#include "gpu/verify.h"
#include "nv_attestation/attestation.h"
#include "nv_attestation/claims_evaluator.h"
#include "nv_attestation/nv_http.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/verify.h"
#include "nvat.h"
#include "switch/evidence.h"
#include "switch/verify.h"
#include <memory>

using namespace nvattestation;

extern "C" {

/*
 * Static and reinterpret casting utilities for C to C++
 * forward-declared structures.
 * reinterpret_cast should only be used to cast C pointer
 * types to C++ pointer types (pointers will have the same size).
 */

// === Private Macro Definitions ===

#define NVAT_PTR_CONVERSION_FUNCTIONS(c_base, cpp_type) \
    inline cpp_type* nvat_##c_base##_to_cpp(nvat_##c_base##_t c_obj) { \
        return reinterpret_cast<cpp_type*>(c_obj); \
    } \
    inline nvat_##c_base##_t nvat_##c_base##_from_cpp(cpp_type* cpp_obj) { \
        return reinterpret_cast<nvat_##c_base##_t>(cpp_obj); \
    }

#define NVAT_FREE_FUNCTION(c_base, cpp_type) \
    void nvat_##c_base##_free(nvat_##c_base##_t* c_base) { \
        if (c_base == nullptr || *c_base == nullptr) { \
            return; \
        } \
        cpp_type* cpp_ptr = nvat_##c_base##_to_cpp(*c_base); \
        delete cpp_ptr; \
        *c_base = nullptr; \
    }

// === Exception Boundary Macros ===

#define NVAT_C_API_BEGIN \
    try {

#define NVAT_C_API_END \
    } catch (const std::bad_alloc& e) { \
        LOG_ERROR("Memory allocation failure: " << e.what()); \
        return NVAT_RC_ALLOC_FAILED; \
    } catch (const std::exception& e) { \
        LOG_ERROR("Unexpected exception caught: " << e.what()); \
        return NVAT_RC_INTERNAL_ERROR; \
    }

#define NVAT_C_API_END_VOID \
    } catch (const std::bad_alloc& e) { \
        LOG_ERROR("Memory allocation failure: " << e.what()); \
    } catch (const std::exception& e) { \
        LOG_ERROR("Unexpected exception caught: " << e.what()); \
    }



inline Error nvat_rc_to_cpp(nvat_rc_t c_rc) {
    return static_cast<Error>(c_rc);
}

inline nvat_rc_t nvat_rc_from_cpp(Error cpp_rc) {
    return static_cast<nvat_rc_t>(cpp_rc);
}

// === NVAT String ===
NVAT_PTR_CONVERSION_FUNCTIONS(str, std::string);

// === Core SDK ===
NVAT_PTR_CONVERSION_FUNCTIONS(sdk_opts, SdkOptions);
NVAT_PTR_CONVERSION_FUNCTIONS(logger, ILogger);
NVAT_PTR_CONVERSION_FUNCTIONS(http_options, HttpOptions);

// === Attestation ===

NVAT_PTR_CONVERSION_FUNCTIONS(evidence_policy, EvidencePolicy);
NVAT_PTR_CONVERSION_FUNCTIONS(relying_party_policy, std::shared_ptr<IClaimsEvaluator>);
NVAT_PTR_CONVERSION_FUNCTIONS(ocsp_client, std::shared_ptr<IOcspHttpClient>);
NVAT_PTR_CONVERSION_FUNCTIONS(rim_store, std::shared_ptr<IRimStore>);
NVAT_PTR_CONVERSION_FUNCTIONS(attestation_ctx, AttestationContext);

// === Evidence Collection ===

NVAT_PTR_CONVERSION_FUNCTIONS(nonce, std::vector<uint8_t>);
NVAT_PTR_CONVERSION_FUNCTIONS(gpu_evidence, GpuEvidence);
NVAT_PTR_CONVERSION_FUNCTIONS(gpu_evidence_source, std::shared_ptr<IGpuEvidenceSource>);
NVAT_PTR_CONVERSION_FUNCTIONS(gpu_evidence_collection, std::vector<GpuEvidence>);

NVAT_PTR_CONVERSION_FUNCTIONS(switch_evidence, SwitchEvidence);
NVAT_PTR_CONVERSION_FUNCTIONS(switch_evidence_source,  std::shared_ptr<ISwitchEvidenceSource>);
NVAT_PTR_CONVERSION_FUNCTIONS(switch_evidence_collection,  std::vector<SwitchEvidence>);

// === Evidence Verification ===

NVAT_PTR_CONVERSION_FUNCTIONS(claims, Claims);
NVAT_PTR_CONVERSION_FUNCTIONS(claims_collection, ClaimsCollection);

// === GPU Verifiers ===

NVAT_PTR_CONVERSION_FUNCTIONS(gpu_verifier,  IGpuVerifier);
NVAT_PTR_CONVERSION_FUNCTIONS(gpu_local_verifier,  LocalGpuVerifier);
NVAT_PTR_CONVERSION_FUNCTIONS(gpu_nras_verifier,  NvRemoteGpuVerifier);

// === Switch Verifiers ===

NVAT_PTR_CONVERSION_FUNCTIONS(switch_verifier,  ISwitchVerifier);
NVAT_PTR_CONVERSION_FUNCTIONS(switch_local_verifier,  LocalSwitchVerifier);
NVAT_PTR_CONVERSION_FUNCTIONS(switch_nras_verifier,  NvRemoteSwitchVerifier);

} // extern "C"