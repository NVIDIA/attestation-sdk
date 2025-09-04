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

#include <cassert>
#include <cstdlib>
#include <memory>
#include <utility>
#include <vector>

#include "nv_attestation/attestation.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/claims_evaluator.h"
#include "nv_attestation/error.h"
#include "nv_attestation/gpu/evidence.h"
#include "nv_attestation/gpu/verify.h"
#include "nv_attestation/log.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/switch/evidence.h"
#include "nv_attestation/switch/verify.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/verify.h"

namespace nvattestation {

Error AttestationContext::ensure_init() {
    Error err {};

    if (m_default_rim_store == nullptr) {
        NvRemoteRimStoreImpl rim_store;
        err = NvRemoteRimStoreImpl::init_from_env(rim_store, m_default_rim_store_url.c_str(), m_default_http_options);
        if (err != Error::Ok) {
            return err;
        }
        m_default_rim_store = make_shared<NvRemoteRimStoreImpl>(std::move(rim_store));
    }

    if (m_default_ocsp_client == nullptr) {
        NvHttpOcspClient ocsp_client;
        err = NvHttpOcspClient::init_from_env(ocsp_client, m_default_ocsp_url.c_str(), m_default_http_options);
        if (err != Error::Ok) {
            return err;
        }
        m_default_ocsp_client = make_shared<NvHttpOcspClient>(std::move(ocsp_client));
    }

    if (m_gpu_enabled) {
        LOG_DEBUG("GPU attestation is enabled");
        if (m_gpu_evidence_source == nullptr) {
            LOG_DEBUG("GPU evidence source not set. Will collect evidence using NVML.");
            m_gpu_evidence_source = make_shared<NvmlEvidenceCollector>();
        }
        if (m_gpu_verifier == nullptr) {
            LOG_DEBUG("GPU verifier not set. Creating a " << to_string(m_default_verifier_type) << " GPU verifier");
            switch (m_default_verifier_type) {
                case VerifierType::Local: {
                    LocalGpuVerifier l_verifier;
                    err = LocalGpuVerifier::create(l_verifier, m_default_rim_store, m_default_ocsp_client);
                    if (err != Error::Ok) {
                        return err;
                    }
                    m_gpu_verifier = make_shared<LocalGpuVerifier>(std::move(l_verifier));
                    break;
                }
                case VerifierType::Remote: {
                    NvRemoteGpuVerifier r_verifier;
                    err = NvRemoteGpuVerifier::init_from_env(r_verifier, m_default_nras_url.c_str(), m_default_http_options);
                    if (err != Error::Ok) {
                        return err;
                    }
                    m_gpu_verifier = make_shared<NvRemoteGpuVerifier>(std::move(r_verifier));
                    break;
                }
                default: return Error::InternalError;
            }
        }
    }

    if (m_switch_enabled) {
        LOG_DEBUG("switch attestation is enabled");
        if (m_switch_evidence_source == nullptr) {
            LOG_DEBUG("Switch evidence source not set. Will collect evidence using NSCQ.");
            m_switch_evidence_source = make_shared<NscqEvidenceCollector>();
        }
        if (m_switch_verifier == nullptr) {
            LOG_DEBUG("Switch verifier not set. Creating a " << to_string(m_default_verifier_type) << " switch verifier");
            switch (m_default_verifier_type) {
                case VerifierType::Local: {
                    LocalSwitchVerifier l_verifier;
                    err = LocalSwitchVerifier::create(l_verifier, m_default_rim_store, m_default_ocsp_client);
                    if (err != Error::Ok) {
                        return err;
                    }
                    m_switch_verifier = make_shared<LocalSwitchVerifier>(std::move(l_verifier));
                    break;
                }
                case VerifierType::Remote: {
                    NvRemoteSwitchVerifier r_verifier;
                    err = NvRemoteSwitchVerifier::init_from_env(r_verifier, m_default_nras_url.c_str(), m_default_http_options);
                    if (err != Error::Ok) {
                        return err;
                    }
                    m_switch_verifier = make_shared<NvRemoteSwitchVerifier>(std::move(r_verifier));
                    break;
                }
                default: return Error::InternalError;
            }
        }
    }

    return Error::Ok;
}

void AttestationContext::set_verifier_type(VerifierType verifier_type) {
    if (m_default_verifier_type != verifier_type) {
        // if verifier type changes, wipe out verifiers so that we can recreate
        // on next use
        m_gpu_verifier = nullptr;
        m_switch_verifier = nullptr;
    }
    m_default_verifier_type = verifier_type;
}

// NOLINTBEGIN(performance-unnecessary-value-param): Passing shared pointers by value is intentional

void AttestationContext::set_default_http_options(HttpOptions http_options) {
    m_default_http_options = http_options;
}

void AttestationContext::set_default_rim_store_url(const char* rim_store_url) {
    m_default_rim_store_url = rim_store_url;
}

void AttestationContext::set_default_ocsp_url(const char* ocsp_url) {
    m_default_ocsp_url = ocsp_url;
}

void AttestationContext::set_default_nras_url(const char* nras_url) {
    m_default_nras_url = nras_url;
}

void AttestationContext::set_default_rim_store(shared_ptr<IRimStore> rim_store) {
    m_default_rim_store = rim_store;
}

void AttestationContext::set_default_ocsp_client(shared_ptr<IOcspHttpClient> ocsp_client) {
    m_default_ocsp_client = ocsp_client;
}

void AttestationContext::set_evidence_policy(EvidencePolicy policy) {
    m_evidence_policy = policy;
}

void AttestationContext::set_claims_evaluator(shared_ptr<IClaimsEvaluator> evaluator) {
    m_claims_evaluator = evaluator;
}

void AttestationContext::set_gpu_evidence_source(shared_ptr<IGpuEvidenceSource> evidence_source) {
    m_gpu_evidence_source = evidence_source;
}

void AttestationContext::set_switch_evidence_source(shared_ptr<ISwitchEvidenceSource> evidence_source) {
    m_switch_evidence_source = evidence_source;
}

Error AttestationContext::set_gpu_evidence_source_json_file(const std::string& file_path) {
    GpuEvidenceSourceFromJsonFile gpu_evidence_source;
    Error err = GpuEvidenceSourceFromJsonFile::create(file_path, gpu_evidence_source);
    if (err != Error::Ok) {
        LOG_ERROR("failed to create GPU evidence source from JSON file");
        return err;
    }
    m_gpu_evidence_source = make_shared<GpuEvidenceSourceFromJsonFile>(std::move(gpu_evidence_source));
    return Error::Ok;
}

Error AttestationContext::set_switch_evidence_source_json_file(const std::string& file_path) {
    SwitchEvidenceSourceFromJsonFile switch_evidence_source;
    Error err = SwitchEvidenceSourceFromJsonFile::create(file_path, switch_evidence_source);
    if (err != Error::Ok) {
        LOG_ERROR("failed to create switch evidence source from JSON file");
        return err;
    }
    m_switch_evidence_source = make_shared<SwitchEvidenceSourceFromJsonFile>(std::move(switch_evidence_source));
    return Error::Ok;
}

void AttestationContext::set_gpu_verifier(shared_ptr<IGpuVerifier> verifier) {
    m_gpu_verifier = verifier;
}

void AttestationContext::set_switch_verifier(shared_ptr<ISwitchVerifier> verifier) {
    m_switch_verifier = verifier;
}

void AttestationContext::set_eat_private_key_pem(const std::string& private_key_pem) {
    m_eat_private_key_pem = private_key_pem;
}

void AttestationContext::set_eat_issuer(const std::string& issuer) {
    m_eat_issuer = issuer;
}

void AttestationContext::set_eat_kid(const std::string& kid) {
    m_eat_kid = kid;
}

// NOLINTEND(performance-unnecessary-value-param)

Error AttestationContext::attest_system(
    Nonce nonce,
    std::string& out_detached_eat, 
    ClaimsCollection& out_claims
) {
    Error err = ensure_init();
    if (err != Error::Ok) {
        return err;
    }

    if (nonce.empty()) {
        // TODO: choose a method for using one nonce across devices with varying nonce lengths
        assert(GPU_SPDM_REQ_NONCE_SIZE == SWITCH_SPDM_REQ_NONCE_SIZE);
        nonce.resize(GPU_SPDM_REQ_NONCE_SIZE);
        err = generate_nonce(nonce);
        if (err != Error::Ok) {
            return err;
        }
        LOG_DEBUG("Generated nonce for system attestation: " << to_hex_string(nonce));
    }

    // first pass at unified claims
    // TODO: determine final structure to pass to RP policy
    out_claims = ClaimsCollection();
    if (m_gpu_enabled) {
        ClaimsCollection claims {};
        err = attest_gpus(nonce, claims);
        if (err != Error::Ok) {
            return err;
        }
        out_claims.extend(claims);
    }
    if (m_switch_enabled) {
        ClaimsCollection claims {};
        err = attest_switches(nonce, claims);
        if (err != Error::Ok) {
            return err;
        }
        out_claims.extend(claims);
    }

    err = out_claims.get_detached_eat(out_detached_eat, m_eat_private_key_pem, m_eat_issuer, m_eat_kid);
    if (m_claims_evaluator == nullptr) {
        return err;
    }

    if (err != Error::Ok && err != Error::OverallResultFalse) {
        return err;
    }

    bool policy_match = false;
    err = m_claims_evaluator->evaluate_claims(out_claims, policy_match);
    if (err != Error::Ok) {
        return err;
    }
    if (!policy_match) {
        LOG_ERROR("Relying party policy REJECTED attestation results");
        return Error::RelyingPartyPolicyMismatch;
    }
    LOG_INFO("Relying party policy ACCEPTED attestation results");

    return Error::Ok;
}


Error AttestationContext::attest_gpus(Nonce& nonce, ClaimsCollection& out_claims) {
    Error err {};
    vector<std::shared_ptr<GpuEvidence>> evidence {};
    err = m_gpu_evidence_source->get_evidence(nonce, evidence);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to collect GPU evidence");
        return err;
    }
    err = m_gpu_verifier->verify_evidence(evidence, m_evidence_policy, out_claims);
    if (err != Error::Ok) {
        LOG_ERROR("Failed to verify GPU evidence");
        return err;
    }
    return Error::Ok;
}


Error AttestationContext::attest_switches(Nonce& nonce, ClaimsCollection& out_claims) {
    std::vector<std::shared_ptr<SwitchEvidence>> evidence {};
    Error error = m_switch_evidence_source->get_evidence(nonce, evidence);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to collect switch evidence");
        return error;
    }
    error = m_switch_verifier->verify_evidence(evidence, m_evidence_policy, out_claims);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to verify switch evidence");
        return error;
    }
    return Error::Ok;
}
}