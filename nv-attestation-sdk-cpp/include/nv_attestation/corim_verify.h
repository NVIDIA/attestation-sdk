/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "nv_attestation/cmw.h"
#include "nv_attestation/corim.h"
#include "nv_attestation/corim_evidence/corim_store.h"
#include "nv_attestation/corim_evidence/evidence_handler_settings.h"
#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/nv_x509.h"

namespace nvattestation {

class DetachedEATOptions;

class Ect {
    EnvironmentMap m_environment;
    std::vector<MeasurementMap> m_claims;

  public:
    Ect() = default;
    Ect(EnvironmentMap environment, std::vector<MeasurementMap> claims)
        : m_environment(std::move(environment)), m_claims(std::move(claims)) {}
    Ect(Ect &&) = default;
    Ect &operator=(Ect &&) = default;
    Ect(const Ect &) = default;
    Ect &operator=(const Ect &) = default;

    const EnvironmentMap &getEnvironment() const { return m_environment; }
    const std::vector<MeasurementMap> &getClaims() const { return m_claims; }
};

struct MkeyMismatch;

// Empty struct == passing. failed_dependencies carries env identifiers
// only; per-trustee failure detail lives on the trustee's own outcome in
// VerificationResult::outcomes — avoids duplicating reason chains inside
// every dependent.
struct MismatchReason {
    bool no_evidence = false;
    std::vector<MkeyMismatch> mkey_mismatches;
    std::vector<EnvironmentMap> failed_dependencies;

    bool any() const;

    static MismatchReason noEvidence();
    static MismatchReason
    claimsMismatch(std::vector<MkeyMismatch> mismatches);
    static MismatchReason
    failedDependency(std::vector<EnvironmentMap> failures);
};

// Per-scalar-field mismatch detail. Strings are display projections of the
// reference and evidence values; "<absent>" denotes a missing field.
struct FieldMismatchInfo {
    bool mismatched = false;
    std::string reference;
    std::string evidence;
};

// Per-digest result for the digests-vector match.
struct DigestMatchEntry {
    enum class Reason {
        kAlgorithmNotInEvidence, // ref digest's algorithm not present on
                                 // evidence
        kValueDiffers,           // same algorithm found, value mismatched
        kDuplicateAlgorithmInReference, // reference has 2+ digests for same
                                        // algorithm (spec MUST fail)
        kDuplicateAlgorithmInEvidence,  // evidence has 2+ digests for same
                                        // algorithm (spec MUST fail)
    };
    Reason reason{Reason::kAlgorithmNotInEvidence};
    Digest reference;
    // Populated for kValueDiffers and kDuplicateAlgorithmInEvidence.
    std::unique_ptr<Digest> evidence;

    DigestMatchEntry() = default;
    DigestMatchEntry(Reason r, Digest ref, std::unique_ptr<Digest> ev)
        : reason(r), reference(std::move(ref)), evidence(std::move(ev)) {}
};

struct MeasurementValuesMismatch {
    FieldMismatchInfo version;
    FieldMismatchInfo svn;
    std::vector<DigestMatchEntry> digests;
    FieldMismatchInfo flags;
    FieldMismatchInfo
        raw_value; // mask (if any on reference) is applied during compare
    FieldMismatchInfo name;
    FieldMismatchInfo int_range; // reference may declare exact-int or range;
    // evidence is a value

    bool any() const;
    std::vector<std::string> fields() const;
};

// Per-mkey failure: either the mkey was absent from evidence, or the reference
// value did not match. `mismatch` is populated only when key_not_in_evidence
// is false.
struct MkeyMismatch {
    MeasurementMapKey mkey;
    bool key_not_in_evidence = false;
    MeasurementValuesMismatch mismatch;

    bool any() const { return key_not_in_evidence || mismatch.any(); }
};

/**
 * Wildcard match between a reference value and evidence.
 * Each unset field on `reference` accepts anything on `evidence`.
 * SVN respects kind: kMin requires evidence.svn >= reference.svn;
 * kExact requires evidence.svn == reference.svn.
 * int_range: reference may be exact-int or [min,max]; evidence must be a
 * simple int. Range-shaped evidence is treated as a mismatch — the spec
 * leaves this case implementation-defined.
 * Returns a struct with one bool per field; .any() == false ⇔ match.
 */
MeasurementValuesMismatch
match_measurement_values(const MeasurementValues &reference,
                         const MeasurementValues &evidence);

void to_json(nlohmann::json &json_out, const FieldMismatchInfo &info);
void to_json(nlohmann::json &json_out, const DigestMatchEntry &entry);
void to_json(nlohmann::json &json_out, const MeasurementValuesMismatch &mm);
void to_json(nlohmann::json &json_out, const MkeyMismatch &mm);

// Validation issue raised by verify(). All current codes are fatal:
// when any diagnostic is present, `outcomes` is empty. `related_envs`
// names the environments involved, if any.
struct Diagnostic {
    enum class Severity { kError, kWarning };
    enum class Code {
        kDependencyCycle,                    // fatal
        kNoReferenceEcts,                    // fatal
        kNoRootEnvironment,                  // fatal
        kMultipleRootEnvironments,           // fatal
        kRootEnvironmentMissingPurpose,      // fatal
        kDuplicateReferenceMkey,             // fatal
        kMergeableReferenceEcts,             // fatal
        kDuplicateEvidenceEnv,               // fatal
        kDuplicateEvidenceMkey,              // fatal
        kMissingReferenceForDependencyEnv,   // fatal
        kMalformedClaimsFromEvidenceEnv,     // fatal
        kNonUtf8EvidenceClaim,               // fatal
        kDuplicateEvidenceClaimKey,          // fatal
    };

    Severity severity = Severity::kError;
    Code code{};
    std::string detail;
    std::vector<EnvironmentMap> related_envs;

    Diagnostic() = default;
    Diagnostic(Severity s, Code c, std::string d,
               std::vector<EnvironmentMap> envs = {})
        : severity(s), code(c), detail(std::move(d)),
          related_envs(std::move(envs)) {}

    bool isError() const { return severity == Severity::kError; }

    static Diagnostic dependencyCycle();
    static Diagnostic noReferenceEcts();
    static Diagnostic noRootEnvironment();
    static Diagnostic multipleRootEnvironments(std::vector<EnvironmentMap> envs);
    static Diagnostic rootEnvironmentMissingPurpose(const EnvironmentMap &env);
    static Diagnostic duplicateReferenceMkey(const EnvironmentMap &env,
                                             const MeasurementMapKey &mkey);
    static Diagnostic mergeableReferenceEcts(const EnvironmentMap &env);
    static Diagnostic duplicateEvidenceEnv(const EnvironmentMap &env);
    static Diagnostic duplicateEvidenceMkey(const EnvironmentMap &env,
                                            const MeasurementMapKey &mkey);
    static Diagnostic
    missingReferenceForDependencyEnv(const EnvironmentMap &env);
    static Diagnostic
    malformedClaimsFromEvidenceEnv(const EnvironmentMap &env);
    static Diagnostic nonUtf8EvidenceClaim(const EnvironmentMap &env);
    static Diagnostic
    duplicateEvidenceClaimKey(const EnvironmentMap &env,
                              const std::string &key);
};

const char *to_string(Diagnostic::Severity severity);
const char *to_string(Diagnostic::Code code);

// Diagnostics occupy a reserved band above the nvat_rc_t ranges so both can
// share one code field without colliding.
int diagnostic_public_code(Diagnostic::Code code);

// One attempt per reference ECT for this environment. Multiple attempts exist
// when the reference carries alternative ECTs for the same environment.
// EnvOutcome::passed() returns true if any attempt passes.
struct EctAttempt {
    std::vector<Ect> matched_evidence_ects;
    MismatchReason reason;

    bool passed() const;
};

// `reference_claims[i]` is parallel to `attempts[i]`. Env-level `reason`
// carries propagated failures (typically `failed_dependencies`).
struct EnvOutcome {
    EnvironmentMap environment;
    std::vector<std::vector<MeasurementMap>> reference_claims;
    std::vector<EctAttempt> attempts;
    MismatchReason reason;
    // True when this env is the attested root or a transitive trustee of it.
    // Consumers (e.g. AR generation) select only reachable outcomes; outcomes
    // outside the root's subtree are retained but flagged false.
    bool reachable_from_root = false;

    bool passed() const;
    // In the attested root's subtree and passed / failed. Outcomes outside
    // that subtree are neither.
    bool matched() const;
    bool mismatched() const;
};

struct VerificationResult {
    // When `diagnostics` is non-empty, `outcomes` is empty (verify aborted).
    std::vector<Diagnostic> diagnostics;
    std::vector<EnvOutcome> outcomes;
    // Null unless a root env was corroborated and carried a purpose measurement.
    std::unique_ptr<std::string> purpose;
    // Claims-from-evidence envs (NVIDIA CoRIM arc, penultimate arc 2). EAR
    // target: corroborated -> ear_nvidia_evidence_rim_cmp, uncorroborated ->
    // ear_evidence_claims.
    std::map<std::string, std::string> corroborated_evidence_claims;
    std::map<std::string, std::string> uncorroborated_evidence_claims;
    // Evidence ECTs whose environment matched no reference ECT.
    std::vector<EnvironmentMap> unmatched_environments;
};

VerificationResult verify(const std::vector<Ect> &reference,
                          const std::vector<Ect> &evidence,
                          const std::vector<DependencyTriple> &dependencies);

/**
 * DFS-based reverse topological sort over the dependency graph. Edges run
 * from a domain to each of its trustees. On success, fills `out` with every
 * env in the graph (domains and trustee-only) in reverse topological order
 * — trustees before dependent domains (leaves first) — and returns true.
 * Returns false if the graph contains a cycle; `out` is then cleared.
 *
 * If `adj_out` is non-null, it is populated with the flattened
 * domain → trustees adjacency map (free byproduct of the sort).
 */
bool reverse_topological_sort(
    const std::vector<DependencyTriple> &dependencies,
    std::vector<EnvironmentMap> &out,
    std::map<EnvironmentMap, std::vector<EnvironmentMap>> *adj_out = nullptr);

void to_json(nlohmann::json &json_out, const Ect &ect);
void to_json(nlohmann::json &json_out, const MismatchReason &reason);
void to_json(nlohmann::json &json_out, const Diagnostic &diagnostic);
void to_json(nlohmann::json &json_out, const EctAttempt &attempt);
void to_json(nlohmann::json &json_out, const EnvOutcome &outcome);
void to_json(nlohmann::json &json_out, const VerificationResult &result);

// Why a stage could not run. `code` reuses the public nvat_rc_t numbering so a
// relying party reads the same values the C API returns.
struct StageError {
    Error code = Error::Ok;
    std::string message;
    std::string details;

    bool has_error() const { return code != Error::Ok; }
};

void to_json(nlohmann::json &json_out, const StageError &err);

// Result of fetching and processing one referenced CoRIM (rim-locator).
struct CorimResult {
    std::string locator;
    bool fetched = false;
    std::string id;
    bool signature_verified = false;
    std::unique_ptr<std::vector<PerCertStatus>> cert_chain; // null if unsigned
    bool coev_signature_verified = false;
    std::unique_ptr<std::vector<PerCertStatus>> coev_cert_chain; // null if unsigned
    // True once the CoRIM itself parsed; independent of a later CoEV failure
    // on this locator, which is reported via `error` instead.
    bool parsed = false;
    StageError error;
};

// Verifier claims from evidence validation, prior to reference comparison.
struct EvidenceClaims {
    bool signature_verified = false;
    bool parsed = false;
    // nonce_match is emitted only when the RP supplied a per-item nonce.
    bool nonce_supplied = false;
    bool nonce_match = false;
    std::unique_ptr<std::vector<PerCertStatus>> cert_chain; // null when unavailable
    // Device identity cert serial, decimal. Not serialized — see
    // to_json(EvidenceClaims).
    std::string device_cert_serial;
    // PEM key from the presented chain. `signature_verified` separately reports
    // whether the chain was anchored and the evidence signature validated.
    std::string akpub;
    // Serial from the end-entity cert's DMTF otherName; empty when absent.
    // Not serialized — see to_json(EvidenceClaims).
    std::string spdm_end_entity_othername_serial;
};

// Appraisal of one CMW evidence item. Every stage records its result here
// rather than aborting, so the caller can emit a rich attestation result and
// leave pass/fail to a policy/EAR layer. No field — including OCSP status —
// is treated as fatal. `stage_error` is set when a stage could not run
// (e.g. the cert chain did not anchor), in which case later fields stay at
// their defaults.
struct EvidenceItemAppraisal {
    std::string label;

    // Nonce extracted from the evidence (submods eat_nonce); set once parsed.
    std::vector<uint8_t> eat_nonce;

    // Profile of the source SPDM ToC or standalone CoEV. It identifies the
    // evidence claims emitted for this EAR submodule.
    std::unique_ptr<ProfileValue> evidence_profile;

    EvidenceClaims evidence;

    // One entry per referenced CoRIM (rim-locator), in locator order.
    std::vector<CorimResult> corims;

    // Reference-value (measurement) appraisal.
    VerificationResult match;

    StageError stage_error;

    // hwmodel from the end-entity cert's DMTF otherName product field, used
    // for ear_attester_claims when the evidence does not carry its own.
    std::string hwmodel;

    // EnvironmentMaps extracted from DiceTcbInfo extensions in the device cert
    // chain. Populated only when x509_chain_to_evidence_ects() succeeds.
    std::vector<EnvironmentMap> chain_ect_environments;

    // True when every chain DiceTcbInfo environment has a matching outcome.
    // Null when the chain yielded no ECTs, i.e. nothing to compare against.
    std::unique_ptr<bool> cert_chain_dti_match;
};

// One digest of the raw CMW input bytes, used to bind the EAR to the
// complete request. Serialized as base64url in ear_nvidia_inputs.digests.
struct InputDigest {
    HashAlgorithm alg{HashAlgorithm::Sha256};
    std::vector<uint8_t> val;
};

struct CorimAttestationResult {
    std::vector<EvidenceItemAppraisal> items;
    // One entry per requested algorithm, or per supported algorithm when the
    // request carried none.
    std::vector<InputDigest> input_digests;
    // Collection-level CMW nonce, echoed as the top-level eat_nonce.
    // Length-checked by the CMW parser; empty when absent.
    std::vector<uint8_t> input_nonce;
};

// True when every chain env has a matching outcome, using verify()'s wildcard
// rule: the outcome env is the reference side, so omitted fields accept any.
bool cert_chain_dti_matches(const std::vector<EnvironmentMap> &chain_envs,
                            const std::vector<EnvOutcome> &outcomes);

void to_json(nlohmann::json &json_out, const PerCertStatus &status);
void to_json(nlohmann::json &json_out, const CorimResult &result);
void to_json(nlohmann::json &json_out, const EvidenceClaims &evidence);
void to_json(nlohmann::json &json_out, const EvidenceItemAppraisal &item);
void to_json(nlohmann::json &json_out, const InputDigest &digest);
void to_json(nlohmann::json &json_out, const CorimAttestationResult &result);

// V2 local verifier entry point. Parses a CMW input collection and, per
// evidence item, anchors its cert chain to the trust store, verifies the
// evidence signature, fetches and parses the referenced CoRIMs, then runs
// verify(). Returns a CorimAttestationResult carrying the per-item appraisal
// (anchoring, signature, CoRIM signing chains, and the match outcome).
//
// TODO(v2): take an EvidencePolicy once RP policy is wired.
class LocalCorimVerifier {
  public:
    // The CoRIM store (RIM fetching) and OCSP client are collaborators the
    // caller configures (URL rewrites, service key, AIA) and injects. A null
    // OCSP client means no revocation checking. The verifier itself only holds
    // appraisal policy (trusted roots, signature/revocation toggles).
    explicit LocalCorimVerifier(
        CorimStore corim_store,
        std::shared_ptr<IOcspHttpClient> ocsp_client = nullptr);

    // Append a root CA PEM to the device-identity trust store. The chain
    // on each CMW evidence item must anchor to one of these roots.
    Error add_device_identity_trust_root_pem(std::string pem);

    // When disabled, the injected OCSP client is not consulted and chains are
    // treated as not revoked.
    void set_verify_revocation(bool enabled);

    // When false the verifier accepts tampered signed CoRIMs and unsigned
    // CoRIMs — for development against unsigned fixtures, never production.
    void set_verify_rim_signature(bool enabled);

    // Same as set_verify_rim_signature, but for fetched CoEVs; independent
    // since CoEV signing can lag CoRIM signing in a given deployment.
    void set_verify_coev_signature(bool enabled);

    // Overrides the CoRIM/CoEV signing trust anchor. Test-only — never call
    // this in production; it accepts whatever root you hand it.
    void set_rim_signing_root_for_testing(std::string root_cert_pem);

    // When false, unauthenticated evidence and all claims available from a
    // parseable, untrusted chain (including DTI ECTs and akpub) are retained
    // for diagnostics, but the appraisal remains contraindicated. Disable
    // only for development fixtures.
    void set_verify_evidence_signature(bool enabled);

    // Fallback CoEV blob (#6.570 SpdmToc or #6.571 ConciseEvidence); used when
    // SPDM evidence yields no ECTs. Returns BadArgument on parse failure.
    Error set_backup_spdm_coev(const uint8_t* data, std::size_t len);

    // Append a fallback RIM locator URI; used when evidence yields no
    // rim-locator URLs.
    void add_backup_rim_locator(std::string uri);

    // Used when the request carries no ars.digest-algos. Empty disables digest
    // computation entirely.
    void set_default_hash_algorithms(std::vector<HashAlgorithm> algs);

    // Appraise a CMW input collection. Populates out_result with one entry
    // per evidence item — cert chain details, OCSP, signature, and the
    // measurement match — collecting rather than enforcing. Returns an error
    // only when the input itself cannot be processed (null/parse failure);
    // per-item appraisal outcomes live in out_result.
    //
    // Both out_ear_jwt/out_ear_json null skips EAR mapping entirely. Signing
    // (ear_signing_options) only affects out_ear_jwt; out_ear_json is always
    // the unsigned EAR, so callers can read claims without decoding the JWT.
    Error verify_cmw(const uint8_t *cmw_data, std::size_t cmw_len,
                     CmwFormat format, CorimAttestationResult &out_result,
                     const DetachedEATOptions *ear_signing_options = nullptr,
                     std::string *out_ear_jwt = nullptr,
                     std::string *out_ear_json = nullptr) const;

  private:
    EvidenceItemAppraisal
    appraise_item(const std::string &label, const CmwEvidenceItem &item) const;

    // Validate a device-identity cert chain against the configured roots.
    Error anchor_device_chain(const std::string &chain_pem,
                              X509CertChain &out_chain) const;

    // Verify a fetched CoEV's COSE_Sign1 signature and return its payload.
    Error verify_coev_signature(const std::vector<uint8_t> &coev_bytes,
                                const std::shared_ptr<IOcspHttpClient> &ocsp_client,
                                std::vector<uint8_t> &out_payload,
                                std::vector<PerCertStatus> &out_cert_claims) const;

    CorimStore m_corim_store;
    std::shared_ptr<IOcspHttpClient> m_ocsp_client;

    // Device-identity roots, kept separate from CoRIM signing roots so evidence
    // and CoRIM signed by different vendors can't be confused.
    // TODO(p2): parse these to X509 once on init instead of per appraisal.
    std::vector<std::string> m_device_identity_roots;

    bool m_verify_rim_signature = true;
    bool m_verify_coev_signature = true;
    bool m_verify_revocation = true;
    std::string m_rim_signing_root;
    EvidenceHandlerSettings m_evidence_handler_settings;
    std::vector<std::string> m_backup_rim_locators;
    std::vector<HashAlgorithm> m_default_hash_algorithms{HashAlgorithm::Sha256};
};

} // namespace nvattestation
