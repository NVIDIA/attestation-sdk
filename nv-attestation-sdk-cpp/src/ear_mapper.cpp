/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "nv_attestation/ear_mapper.h"

#include <algorithm>
#include <ctime>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>
#include "jwt-cpp/traits/nlohmann-json/traits.h"

#include "nv_attestation/corim.h"
#include "nv_attestation/log.h"
#include "nv_attestation/corim_verify.h"
#include "nv_attestation/utils.h"
#include "nvat.h"

namespace nvattestation {

namespace {

// TODO(P1): make configurable. Emitted as iss, which also resolves the
// verifier's JWKS endpoint once results are signed.
constexpr const char* kVerifierDeveloper = "https://developer.nvidia.com/attestation";
// Pre-release EAR profiles are subject to change without compatibility guarantees.
constexpr const char* kTopLevelProfile =
    "tag:nvidia.com,2026:ear/profiles/composite/generic/pre-1.0.0";
// TODO(P1): hardcoded for GPUs, so switch evidence is mislabelled. The
// appraisal carries no device type to select on.
constexpr const char* kSubmodProfile =
    "tag:nvidia.com,2026-05:ear/profiles/gpu/1.0.0";
constexpr const char* kStatusAffirming      = "affirming";
constexpr const char* kStatusContraindicated = "contraindicated";
constexpr const char* kStatusWarning         = "warning";
// Validity window written into iat/nbf/exp. Will be enforced when EAR signing
// is implemented.
constexpr int64_t kDefaultTtlSeconds = 3600;
// Length of the random jti token, in bytes.
constexpr std::size_t kJtiByteLength = 32;

// Returns kStatusAffirming or kStatusContraindicated for one evidence item.
// TODO(P1): kStatusWarning is never produced, so the tri-state collapses to
// pass/fail. No derivation for the warning state is defined yet.
std::string derive_ear_status(const EvidenceItemAppraisal& item) {
    if (item.stage_error.has_error()) {
        return kStatusContraindicated;
    }
    if (!item.evidence.signature_verified) {
        return kStatusContraindicated;
    }
    // Warning-severity diagnostics must not fail the item; only errors do.
    if (std::any_of(item.match.diagnostics.begin(), item.match.diagnostics.end(),
                    [](const Diagnostic& diag) { return diag.isError(); })) {
        return kStatusContraindicated;
    }
    bool any_matched = false;
    for (const auto& outcome : item.match.outcomes) {
        if (outcome.mismatched()) {
            return kStatusContraindicated;
        }
        any_matched = any_matched || outcome.matched();
    }
    // Nothing in the root's subtree was corroborated, so there is nothing to
    // affirm even though no outcome failed.
    return any_matched ? kStatusAffirming : kStatusContraindicated;
}

// kStatusContraindicated < kStatusWarning < kStatusAffirming.
int status_rank(const std::string& status) {
    if (status == kStatusAffirming) {
        return 2;
    }
    if (status == kStatusWarning) {
        return 1;
    }
    return 0;
}

Error build_submod(const EvidenceItemAppraisal& item, nlohmann::json& out_submod) {
    nlohmann::json submod = nlohmann::json::object();
    submod["eat_profile"] = kSubmodProfile;
    submod["ear_status"]  = derive_ear_status(item);
    if (item.evidence_profile) {
        submod["evidence_profile"] =
            profile_value_to_string(*item.evidence_profile);
    }

    // TODO(P1): mandatory, but only emitted when the appraisal produced a
    // purpose. Needs a default or a doc change.
    if (item.match.purpose) {
        submod["ear_nvidia_purpose"] = *item.match.purpose;
    }

    // TODO(P1): ear_appraisal_policy_ids — no policy identity is threaded
    // through the verifier yet.

    if (!item.eat_nonce.empty()) {
        std::string encoded{};
        if (encode_base64url(item.eat_nonce, encoded) == Error::Ok) {
            submod["eat_nonce"] = std::move(encoded);
        } else {
            LOG_ERROR("Failed to base64url-encode eat_nonce for " << item.label
                      << "; claim omitted");
        }
    }

    // TODO(P1): ear_trustworthiness_vector — no mapping from CoRIM match
    // outcomes to the trustworthiness claims is defined yet; omit until it is.

    // ear_verifier_claims.ear_nvidia_evidence
    {
        auto ev = nlohmann::json(item.evidence); // uses existing to_json
        submod["ear_verifier_claims"]["ear_nvidia_evidence"] = std::move(ev);
    }

    // ear_verifier_claims.ear_nvidia_rims
    if (!item.corims.empty()) {
        submod["ear_verifier_claims"]["ear_nvidia_rims"] = item.corims; // uses existing to_json
    }

    // ear_verifier_claims.ear_nvidia_evidence_rim_cmp
    if (!item.match.outcomes.empty() || !item.match.unmatched_environments.empty()) {
        nlohmann::json cmp = nlohmann::json::object();
        nlohmann::json matched    = nlohmann::json::array();
        nlohmann::json mismatched = nlohmann::json::array();
        for (const auto& outcome : item.match.outcomes) {
            nlohmann::json env{};
            to_json(env, outcome.environment);
            if (outcome.matched()) {
                matched.push_back(std::move(env));
            } else if (outcome.mismatched()) {
                mismatched.push_back(std::move(env));
            }
        }
        cmp["matched_env"]    = std::move(matched);
        cmp["mismatched_env"] = std::move(mismatched);
        nlohmann::json unmatched = nlohmann::json::array();
        for (const auto& env : item.match.unmatched_environments) {
            nlohmann::json env_json{};
            to_json(env_json, env);
            unmatched.push_back(std::move(env_json));
        }
        cmp["unmatched_env"] = std::move(unmatched);

        if (item.cert_chain_dti_match) {
            cmp["cert_chain_dti_match"] = *item.cert_chain_dti_match;
        }

        submod["ear_verifier_claims"]["ear_nvidia_evidence_rim_cmp"] = std::move(cmp);
    }

    // Merged evidence claims, plus hwmodel from the cert when unasserted.
    // TODO(P1): oemid unsourced; dbgstat and driver/vbios are pass-through.
    nlohmann::json attester = nlohmann::json::object();
    for (const auto& kv : item.match.corroborated_evidence_claims) {
        attester[kv.first] = kv.second;
    }
    for (const auto& kv : item.match.uncorroborated_evidence_claims) {
        attester[kv.first] = kv.second;
    }
    if (!item.hwmodel.empty() && !attester.contains("hwmodel")) {
        attester["hwmodel"] = item.hwmodel;
    }
    if (!attester.empty()) {
        submod["ear_attester_claims"] = std::move(attester);
    }

    // ear_nvidia_error_details — an array, not a single object, so later
    // stages can contribute more entries without a breaking schema change.
    nlohmann::json errors = nlohmann::json::array();
    // Each failing locator reports its own reason; the stage error only carries
    // the first of them, so it is redundant once the specifics are listed.
    nlohmann::json rim_errors = nlohmann::json::array();
    for (const auto& corim : item.corims) {
        if (!corim.error.has_error()) {
            continue;
        }
        nlohmann::json entry(corim.error);
        if (!corim.locator.empty()) {
            entry["message"] = corim.error.message + ": " + corim.locator;
        }
        rim_errors.push_back(std::move(entry));
    }
    if (item.stage_error.has_error() && rim_errors.empty()) {
        errors.push_back(nlohmann::json(item.stage_error));
    }
    for (auto& entry : rim_errors) {
        errors.push_back(std::move(entry));
    }
    for (const auto& diag : item.match.diagnostics) {
        nlohmann::json entry = nlohmann::json::object();
        entry["code"] = diagnostic_public_code(diag.code);
        // Every diagnostic factory supplies a sentence; the kebab token from
        // to_string duplicates what `code` already identifies.
        entry["message"] = diag.detail;
        if (!diag.related_envs.empty()) {
            entry["related_envs"] = diag.related_envs;
        }
        errors.push_back(std::move(entry));
    }
    if (!errors.empty()) {
        submod["ear_nvidia_error_details"] = std::move(errors);
    }

    out_submod = std::move(submod);
    return Error::Ok;
}

} // namespace

Error map_to_ear_json(const CorimAttestationResult& result,
                      nlohmann::json& out_ear_json) {
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    const std::string build =
        std::string("corim-verifier/") + NVAT_VERSION_STRING;

    nlohmann::json ear = nlohmann::json::object();
    ear["eat_profile"]     = kTopLevelProfile;
    ear["iat"]             = now;
    ear["nbf"]             = now;
    ear["exp"]             = now + kDefaultTtlSeconds;
    // "iss" is optional per JWT/EAR and intentionally omitted here: some
    // validators auto-discover a JWKS endpoint from "iss" via the
    // well-known-URL convention, and kVerifierDeveloper doesn't serve one.
    // It's set only when the caller supplies a real issuer (see
    // LocalCorimVerifier::verify_cmw's ear_signing_options handling).
    ear["ear_verifier_id"] = {{"developer", kVerifierDeveloper},
                               {"build",     build}};

    // jti — unique token ID for log correlation (e.g. NRAS x-request-id fallback).
    // Not intended for revocation or DB tracking.
    std::vector<uint8_t> jti_bytes(kJtiByteLength);
    if (generate_nonce(jti_bytes) == Error::Ok) {
        ear["jti"] = to_hex_string(jti_bytes);
    } else {
        LOG_ERROR("Failed to generate jti; claim omitted from EAR");
    }

    // ear_nvidia_inputs.digests — from pre-computed input_digests in the result.
    // Algorithms and values are set by LocalCorimVerifier::m_default_hash_algorithms.
    if (!result.input_digests.empty()) {
        nlohmann::json digests_arr = nlohmann::json::array();
        for (const auto& digest : result.input_digests) {
            nlohmann::json entry{};
            to_json(entry, digest); // uses to_json(InputDigest) with error-checked base64url
            if (!entry.is_null() && entry.contains("alg")) {
                digests_arr.push_back(std::move(entry));
            }
        }
        if (!digests_arr.empty()) {
            ear["ear_nvidia_inputs"]["digests"] = std::move(digests_arr);
        }
    }

    // Echoed from the CMW collection nonce. Not verified; only the per-submod
    // eat_nonce is checked against the signed transcript.
    if (!result.input_nonce.empty()) {
        std::string encoded{};
        if (encode_base64url(result.input_nonce, encoded) != Error::Ok) {
            LOG_ERROR("Failed to base64url-encode the CMW input nonce; "
                      "claim omitted from EAR");
        } else {
            ear["eat_nonce"] = std::move(encoded);
        }
    }

    // Build submods and aggregate ear_status
    nlohmann::json submods = nlohmann::json::object();
    // An empty result corroborated nothing, so it must not affirm.
    std::string worst_status =
        result.items.empty() ? kStatusContraindicated : kStatusAffirming;
    for (const auto& item : result.items) {
        nlohmann::json submod{};
        build_submod(item, submod);
        const std::string& status =
            submod["ear_status"].get_ref<const std::string&>();
        if (status_rank(status) < status_rank(worst_status)) {
            worst_status = status;
        }
        submods[item.label] = std::move(submod);
    }
    ear["ear_status"] = worst_status;
    ear["submods"]    = std::move(submods);

    out_ear_json = std::move(ear);
    return Error::Ok;
}

Error sign_ear(const nlohmann::json& ear_json, const DetachedEATOptions& options,
               std::string& out_ear_jwt) {
    // jwt-cpp throws on construction/signing failure (e.g. a malformed key).
    // verify_cmw()'s contract is "returns Error, never throws" for every
    // caller, not just the C API boundary that happens to catch exceptions
    // — so this is caught and mapped locally rather than left to escape.
    try {
        auto token = jwt::create<jwt::traits::nlohmann_json>();
        for (auto it = ear_json.begin(); it != ear_json.end(); ++it) {
            token.set_payload_claim(it.key(), jwt::basic_claim<jwt::traits::nlohmann_json>(it.value()));
        }
        if (!options.m_kid.empty()) {
            token.set_header_claim("kid", jwt::basic_claim<jwt::traits::nlohmann_json>(options.m_kid));
        }
        if (options.m_private_key_pem.empty()) {
            out_ear_jwt = token.sign(jwt::algorithm::none{});
        } else {
            out_ear_jwt = token.sign(jwt::algorithm::es384("", options.m_private_key_pem, "", ""));
        }
        return Error::Ok;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to sign EAR JWT: " << e.what());
        return Error::EarSigningFailed;
    }
}

} // namespace nvattestation
