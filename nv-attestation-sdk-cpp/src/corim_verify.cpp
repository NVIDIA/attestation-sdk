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

#include "nv_attestation/corim_verify.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/corim.h"
#include "nv_attestation/ear_mapper.h"
#include "nv_attestation/corim_evidence/coev.h"
#include "nv_attestation/corim_evidence/coev_to_ect.h"
#include "nv_attestation/corim_evidence/corim_store.h"
#include "nv_attestation/corim_evidence/dice_tcb_info_to_ect.h"
#include "nv_attestation/corim_evidence/evidence_handler.h"
#include "nv_attestation/cose.h"
#include "nv_attestation/gpu/blackwell_fsp.h"
#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/verify.h"

#include "internal/certs.h"
#include "internal/corim_decoders.h"

#include <algorithm>
#include <limits>
#include <cstring>
#include <ctime>
#include <functional>
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <utility>
#include <vector>

namespace nvattestation {

MismatchReason MismatchReason::noEvidence() {
    MismatchReason out;
    out.no_evidence = true;
    return out;
}

MismatchReason
MismatchReason::claimsMismatch(std::vector<MkeyMismatch> mismatches) {
    MismatchReason out;
    out.mkey_mismatches = std::move(mismatches);
    return out;
}

MismatchReason
MismatchReason::failedDependency(std::vector<EnvironmentMap> failures) {
    MismatchReason out;
    out.failed_dependencies = std::move(failures);
    return out;
}

bool MismatchReason::any() const {
    return no_evidence || !mkey_mismatches.empty() ||
           !failed_dependencies.empty();
}

bool MeasurementValuesMismatch::any() const {
    return version.mismatched || svn.mismatched || !digests.empty() ||
           flags.mismatched || raw_value.mismatched || name.mismatched ||
           int_range.mismatched;
}

std::vector<std::string> MeasurementValuesMismatch::fields() const {
    std::vector<std::string> out;
    if (version.mismatched) {
        out.emplace_back("version");
    }
    if (svn.mismatched) {
        out.emplace_back("svn");
    }
    if (!digests.empty()) {
        out.emplace_back("digests");
    }
    if (flags.mismatched) {
        out.emplace_back("flags");
    }
    if (raw_value.mismatched) {
        out.emplace_back("raw_value");
    }
    if (name.mismatched) {
        out.emplace_back("name");
    }
    if (int_range.mismatched) {
        out.emplace_back("int_range");
    }
    return out;
}

namespace {
template <typename T> std::string display(const T *ptr) {
    if (ptr == nullptr) {
        return "<absent>";
    }
    return safe_json_dump(*ptr);
}

inline std::string display_string(const std::string *ptr) {
    if (ptr == nullptr) {
        return "<absent>";
    }
    return *ptr;
}

std::string display_svn(const Svn *ptr) {
    if (ptr == nullptr) {
        return "<absent>";
    }
    return (ptr->kind == SvnKind::kMin ? "min:" : "exact:") +
           std::to_string(ptr->value);
}

template <typename T>
FieldMismatchInfo compare_ptr_field(const T *ref, const T *ev) {
    FieldMismatchInfo info;
    if (ref == nullptr) {
        return info;
    }
    if (ev == nullptr || *ref != *ev) {
        info.mismatched = true;
        info.reference = display(ref);
        info.evidence = display(ev);
    }
    return info;
}

// raw_value: if reference carries a mask, mask is applied to both sides
// before bytewise compare. Otherwise strict bytewise equality.
FieldMismatchInfo compare_raw_value(const ByteString *ref_v,
                                    const ByteString *ref_m,
                                    const ByteString *ev_v) {
    FieldMismatchInfo info;
    if (ref_v == nullptr) {
        return info;
    }
    bool ok = false;
    if (ev_v != nullptr) {
        if (ref_m == nullptr) {
            ok = (*ref_v == *ev_v);
        } else if (ref_v->size() == ev_v->size() &&
                   ref_m->size() == ref_v->size()) {
            ok = true;
            for (size_t i = 0; i < ref_v->size(); i++) {
                if ((ref_v->data()[i] & ref_m->data()[i]) !=
                    (ev_v->data()[i] & ref_m->data()[i])) {
                    ok = false;
                    break;
                }
            }
        }
    }
    if (!ok) {
        info.mismatched = true;
        info.reference = ref_m == nullptr ? display(ref_v)
                                          : "value=" + display(ref_v) +
                                                " mask=" + display(ref_m);
        info.evidence = display(ev_v);
    }
    return info;
}

// Range-shaped evidence is treated as a mismatch — the spec leaves this case
// implementation-defined.
FieldMismatchInfo compare_int_range(const IntRange *ref, const IntRange *ev) {
    FieldMismatchInfo info;
    if (ref == nullptr) {
        return info;
    }
    bool ok = false;
    std::string ref_display;
    int32_t ref_simple = 0;
    bool has_min = false;
    bool has_max = false;
    int32_t rmin = 0;
    int32_t rmax = 0;
    if (ref->isSimpleInt(ref_simple)) {
        ref_display = "exact:" + std::to_string(ref_simple);
        int32_t ev_simple = 0;
        ok = ev != nullptr && ev->isSimpleInt(ev_simple) &&
             ev_simple == ref_simple;
    } else if (ref->isRange(has_min, rmin, has_max, rmax)) {
        ref_display =
            "range:[" + (has_min ? std::to_string(rmin) : std::string("-inf")) +
            "," + (has_max ? std::to_string(rmax) : std::string("+inf")) + "]";
        int32_t ev_simple = 0;
        if (ev != nullptr && ev->isSimpleInt(ev_simple)) {
            ok = (!has_min || ev_simple >= rmin) &&
                 (!has_max || ev_simple <= rmax);
        }
    }
    if (!ok) {
        info.mismatched = true;
        info.reference = ref_display;
        info.evidence = display(ev);
    }
    return info;
}

FieldMismatchInfo compare_name(const std::string *ref, const std::string *ev) {
    FieldMismatchInfo info;
    if (ref == nullptr) {
        return info;
    }
    if (ev == nullptr || *ref != *ev) {
        info.mismatched = true;
        info.reference = display_string(ref);
        info.evidence = display_string(ev);
    }
    return info;
}

FieldMismatchInfo compare_flags(const FlagsMap *ref, const FlagsMap *ev) {
    FieldMismatchInfo info;
    if (ref == nullptr || ref->empty()) {
        return info;
    }
    struct Entry {
        const char *name;
        const bool *(FlagsMap::*get)() const;
    };
    static const Entry kEntries[] = {
        {"configured",              &FlagsMap::getConfigured},
        {"secure",                  &FlagsMap::getSecure},
        {"recovery",                &FlagsMap::getRecovery},
        {"debug",                   &FlagsMap::getDebug},
        {"replay_protected",        &FlagsMap::getReplayProtected},
        {"integrity_protected",     &FlagsMap::getIntegrityProtected},
        {"runtime_meas",            &FlagsMap::getRuntimeMeas},
        {"immutable",               &FlagsMap::getImmutable},
        {"tcb",                     &FlagsMap::getTcb},
        {"confidentiality_protected", &FlagsMap::getConfidentialityProtected},
    };
    nlohmann::json ref_diffs = nlohmann::json::object();
    nlohmann::json ev_diffs = nlohmann::json::object();
    for (const auto &entry : kEntries) {
        const bool *ref_val = (ref->*entry.get)();
        if (ref_val == nullptr) {
            continue;
        }
        const bool *ev_val = ev == nullptr ? nullptr : (ev->*entry.get)();
        if (ev_val == nullptr || *ev_val != *ref_val) {
            info.mismatched = true;
            ref_diffs[entry.name] = *ref_val;
            if (ev_val != nullptr) {
                ev_diffs[entry.name] = *ev_val;
            } else {
                ev_diffs[entry.name] = "<absent>";
            }
        }
    }
    if (info.mismatched) {
        info.reference = safe_json_dump(ref_diffs);
        info.evidence = safe_json_dump(ev_diffs);
    }
    return info;
}

FieldMismatchInfo compare_svn(const Svn *ref, const Svn *ev) {
    FieldMismatchInfo info;
    if (ref == nullptr) {
        return info;
    }
    bool ok =
        ev != nullptr && (ref->kind == SvnKind::kMin ? ev->value >= ref->value
                                                     : ev->value == ref->value);
    if (!ok) {
        info.mismatched = true;
        info.reference = display_svn(ref);
        info.evidence = display_svn(ev);
    }
    return info;
}

int find_duplicate_alg(const std::vector<Digest> &digests) {
    for (size_t i = 0; i < digests.size(); i++) {
        for (size_t j = i + 1; j < digests.size(); j++) {
            if (digests[i].sameAlgorithm(digests[j])) {
                return static_cast<int>(j);
            }
        }
    }
    return -1;
}

// Reference digests are alternatives over the same artifact (different
// hash algorithms). Algorithms missing on either side are tolerated
// — but every algorithm common to both ref and ev MUST match in value.
// Any common-algorithm value mismatch fails the claim, even if some
// other alt happens to match. At least one common algorithm must
// exist (otherwise the ref can't be corroborated at all).
// Duplicate algorithms on either side are a spec-level error.
std::vector<DigestMatchEntry> compare_digests(const std::vector<Digest> &ref,
                                              const std::vector<Digest> &ev) {
    std::vector<DigestMatchEntry> out;
    int ref_dup = find_duplicate_alg(ref);
    if (ref_dup >= 0) {
        out.push_back({DigestMatchEntry::Reason::kDuplicateAlgorithmInReference,
                       ref[ref_dup], nullptr});
    }
    int ev_dup = find_duplicate_alg(ev);
    if (ev_dup >= 0) {
        DigestMatchEntry entry;
        entry.reason = DigestMatchEntry::Reason::kDuplicateAlgorithmInEvidence;
        entry.evidence.reset(new Digest(ev[ev_dup]));
        out.push_back(std::move(entry));
    }
    if (ref_dup >= 0 || ev_dup >= 0 || ref.empty()) {
        return out;
    }

    // Walk every (ref, ev) pair sharing an algorithm. Don't early-
    // return on a match — a later common-alg pair may differ and that
    // taints the whole claim. Track first differs for diagnostics.
    bool any_common = false;
    const Digest *differs_ref = nullptr;
    const Digest *differs_ev = nullptr;
    for (const auto &ref_d : ref) {
        for (const auto &ev_d : ev) {
            if (!ref_d.sameAlgorithm(ev_d)) {
                continue;
            }
            any_common = true;
            if (ref_d.getValue() != ev_d.getValue() && differs_ref == nullptr) {
                differs_ref = &ref_d;
                differs_ev = &ev_d;
            }
            break; // duplicates already excluded; at most one ev_d per ref_d
        }
    }
    if (differs_ref != nullptr) {
        out.push_back({DigestMatchEntry::Reason::kValueDiffers, *differs_ref,
                       std::unique_ptr<Digest>(new Digest(*differs_ev))});
    } else if (!any_common) {
        out.push_back({DigestMatchEntry::Reason::kAlgorithmNotInEvidence,
                       ref.front(), nullptr});
    }
    return out;
}
} // namespace

MeasurementValuesMismatch
match_measurement_values(const MeasurementValues &reference,
                         const MeasurementValues &evidence) {
    MeasurementValuesMismatch mm;
    mm.version =
        compare_ptr_field(reference.getVersion(), evidence.getVersion());
    mm.flags = compare_flags(reference.getFlags(), evidence.getFlags());
    mm.raw_value =
        compare_raw_value(reference.getRawValue(), reference.getRawValueMask(),
                          evidence.getRawValue());
    mm.int_range =
        compare_int_range(reference.getIntRange(), evidence.getIntRange());
    mm.name = compare_name(reference.getName(), evidence.getName());
    mm.svn = compare_svn(reference.getSvn(), evidence.getSvn());
    mm.digests = compare_digests(reference.getDigests(), evidence.getDigests());
    return mm;
}

void to_json(nlohmann::json &json_out, const FieldMismatchInfo &info) {
    json_out = nlohmann::json::object();
    json_out["mismatched"] = info.mismatched;
    if (info.mismatched) {
        json_out["reference"] = info.reference;
        json_out["evidence"] = info.evidence;
    }
}

void to_json(nlohmann::json &json_out, const DigestMatchEntry &entry) {
    json_out = nlohmann::json::object();
    switch (entry.reason) {
    case DigestMatchEntry::Reason::kAlgorithmNotInEvidence:
        json_out["reason"] = "algorithm-not-in-evidence";
        break;
    case DigestMatchEntry::Reason::kValueDiffers:
        json_out["reason"] = "value-differs";
        break;
    case DigestMatchEntry::Reason::kDuplicateAlgorithmInReference:
        json_out["reason"] = "duplicate-algorithm-in-reference";
        break;
    case DigestMatchEntry::Reason::kDuplicateAlgorithmInEvidence:
        json_out["reason"] = "duplicate-algorithm-in-evidence";
        break;
    }
    json_out["reference"] = entry.reference;
    if (entry.evidence) {
        json_out["evidence"] = *entry.evidence;
    }
}

void to_json(nlohmann::json &json_out, const MeasurementValuesMismatch &mm) {
    json_out = nlohmann::json::object();
    if (mm.version.mismatched) {
        json_out["version"] = mm.version;
    }
    if (mm.svn.mismatched) {
        json_out["svn"] = mm.svn;
    }
    if (!mm.digests.empty()) {
        json_out["digests"] = mm.digests;
    }
    if (mm.flags.mismatched) {
        json_out["flags"] = mm.flags;
    }
    if (mm.raw_value.mismatched) {
        json_out["raw_value"] = mm.raw_value;
    }
    if (mm.name.mismatched) {
        json_out["name"] = mm.name;
    }
    if (mm.int_range.mismatched) {
        json_out["int_range"] = mm.int_range;
    }
}

void to_json(nlohmann::json &json_out, const MkeyMismatch &mm) {
    json_out = nlohmann::json::object();
    json_out["mkey"] = mm.mkey;
    if (mm.key_not_in_evidence) {
        json_out["key_not_in_evidence"] = true;
    } else if (mm.mismatch.any()) {
        json_out["mismatch"] = mm.mismatch;
    }
}

namespace {

constexpr char kOidNvidia[] = "1.3.6.1.4.1.5703"; // NVIDIA Private Enterprise Number
constexpr char kOidCorim[] = ".1300";             // CoRIM sub-arc
// NVIDIA CoRIM arc.
const std::string &nvidia_corim_arc() {
    static const std::string arc = std::string(kOidNvidia) + kOidCorim;
    return arc;
}

// Dotted OID body of env's class-id if it is an OID under the NVIDIA CoRIM arc.
bool nvidia_corim_class_oid(const EnvironmentMap &env, std::string &out) {
    const ClassMap *cls = env.getClass();
    if (cls == nullptr) {
        return false;
    }
    const ClassId *id = cls->getClassId();
    if (id == nullptr || id->getKind() != ClassId::Kind::kOid) {
        return false;
    }
    const ByteString &value = id->getValue();
    std::string oid = oid_dotted_body(value.data(), value.size());
    if (!oid_has_arc_prefix(oid, nvidia_corim_arc())) {
        return false;
    }
    out = std::move(oid);
    return true;
}

// A root environment for NVIDIA as RVP has a class-id OID under the NVIDIA
// CoRIM arc whose penultimate arc is 1 (the leaf node sits under a parent arc
// of value 1).
bool is_root_env(const EnvironmentMap &env) {
    std::string oid;
    return nvidia_corim_class_oid(env, oid) &&
           oid_penultimate_arc_equals(oid, "1");
}

// Claims-from-evidence env: under the NVIDIA CoRIM arc with penultimate arc 2.
bool is_claims_from_evidence_env(const EnvironmentMap &env) {
    std::string oid;
    return nvidia_corim_class_oid(env, oid) &&
           oid_penultimate_arc_equals(oid, "2");
}

class AnyProfileMatcher : public ProfileMatcher {
  public:
    bool matches(const ProfileValue & /*got*/) const override { return true; }
};

// Pointers into `evidence`; lifetime tied to the caller's vector.
std::vector<const EnvironmentMap *>
find_root_environments(const std::vector<Ect> &evidence) {
    std::vector<const EnvironmentMap *> matches;
    for (const auto &ect : evidence) {
        if (is_root_env(ect.getEnvironment())) {
            matches.push_back(&ect.getEnvironment());
        }
    }
    return matches;
}

// WAR: synthetic default root env for parts/CoRIMs that don't carry one.
// TODO: the root OID should be derived from the device configuration (e.g.
// chip family / stepping) rather than being a fixed constant.
constexpr uint8_t kDefaultRootOidContent[] = {
    0x2B, 0x06, 0x01, 0x04, 0x01, 0xAC, 0x47, 0x8A, 0x14, 0x87, 0x67, 0x01, 0x01};
constexpr char kDefaultPurpose[] = "DEFAULT";

Ect make_default_root_ect() {
    auto class_id = std::unique_ptr<ClassId>(new ClassId(
        ClassId::Kind::kOid,
        ByteString(kDefaultRootOidContent, sizeof(kDefaultRootOidContent))));
    auto cls = std::unique_ptr<ClassMap>(
        new ClassMap(std::move(class_id), nullptr, nullptr, nullptr, nullptr));
    EnvironmentMap env(std::move(cls), nullptr, nullptr);

    MeasurementValues purpose_vals(
        nullptr, nullptr, nullptr, nullptr,
        std::unique_ptr<std::string>(new std::string(kDefaultPurpose)), nullptr,
        nullptr, {});
    std::vector<MeasurementMap> claims;
    claims.emplace_back(MeasurementMapKey::ofString("purpose"),
                        std::move(purpose_vals));
    return Ect(std::move(env), std::move(claims));
}

std::set<EnvironmentMap> collect_reachable(
    std::vector<EnvironmentMap> anchors,
    const std::map<EnvironmentMap, std::vector<EnvironmentMap>> &trustees_of) {
    std::set<EnvironmentMap> reached;
    while (!anchors.empty()) {
        EnvironmentMap env = std::move(anchors.back());
        anchors.pop_back();
        if (!reached.insert(env).second) {
            continue;
        }
        auto it = trustees_of.find(env);
        if (it != trustees_of.end()) {
            anchors.insert(anchors.end(), it->second.begin(),
                           it->second.end());
        }
    }
    return reached;
}

std::unique_ptr<std::string>
parse_purpose(const std::vector<MeasurementMap> &claims) {
    const MeasurementMapKey purpose_key = MeasurementMapKey::ofString("purpose");
    for (const auto &claim : claims) {
        if (claim.getKey() == purpose_key) {
            const std::string *name = claim.getValues().getName();
            if (name != nullptr) {
                return std::unique_ptr<std::string>(new std::string(*name));
            }
        }
    }
    return nullptr;
}

std::vector<Ect const *>
find_ev_ects_by_env(const EnvironmentMap &rv_environment,
                    const std::vector<Ect> &evidence) {
    std::vector<Ect const *> found;
    for (const auto &ev : evidence) {
        if (rv_environment.matches(ev.getEnvironment())) {
            found.push_back(&ev);
        }
    }
    return found;
}

const MeasurementValues *find_ev_values(const Ect &ev_ect,
                                        const MeasurementMapKey &mkey) {
    for (const auto &ev_claim : ev_ect.getClaims()) {
        if (ev_claim.getKey() == mkey) {
            return &ev_claim.getValues();
        }
    }
    return nullptr;
}

// True if the two reference ECTs have at least one shared mkey where the
// values are non-equivalent. Checks both directions so the result is
// order-independent: a wildcard field in one ECT that is constrained in the
// other still counts as a conflict.
bool have_conflicting_mkey(const Ect &lhs, const Ect &rhs) {
    return std::any_of(
        lhs.getClaims().begin(), lhs.getClaims().end(),
        [&rhs](const MeasurementMap &claim) {
            const MeasurementValues *rhs_values =
                find_ev_values(rhs, claim.getKey());
            if (rhs_values == nullptr) {
                return false;
            }
            return match_measurement_values(claim.getValues(), *rhs_values)
                       .any() ||
                   match_measurement_values(*rhs_values, claim.getValues())
                       .any();
        });
}

// Compare one reference ECT against one evidence ECT. Each mkey in the
// reference must appear exactly once (caller validates this). Returns one
// MkeyMismatch per failing mkey; empty == match.
std::vector<MkeyMismatch> compare_ects(const Ect &rv_ect, const Ect &ev_ect) {
    std::vector<MkeyMismatch> failures;
    for (const auto &rv_claim : rv_ect.getClaims()) {
        const auto &mkey = rv_claim.getKey();
        const MeasurementValues *ev_values = find_ev_values(ev_ect, mkey);
        MkeyMismatch failure;
        failure.mkey = mkey;
        if (ev_values == nullptr) {
            failure.key_not_in_evidence = true;
            failures.push_back(std::move(failure));
            continue;
        }
        auto mm = match_measurement_values(rv_claim.getValues(), *ev_values);
        if (mm.any()) {
            failure.mismatch = std::move(mm);
            failures.push_back(std::move(failure));
        }
    }
    return failures;
}

struct EvidenceClaim {
    std::string key;
    std::string value;
};

// dump() throws on invalid UTF-8; reused as the validator (no extra dep).
bool is_valid_utf8(const std::string &value) {
    try {
        (void)nlohmann::json(value).dump();
    } catch (const nlohmann::json::type_error &) {
        return false;
    }
    return true;
}

// Extract the single claim, or false if the ECT is malformed (not one
// string-keyed measurement with exactly one of name/raw-value/version).
// Raw-value is taken as UTF-8; version uses Version::getValue() verbatim.
bool extract_evidence_claim(const Ect &ect, EvidenceClaim &out) {
    const std::vector<MeasurementMap> &claims = ect.getClaims();
    if (claims.size() != 1) {
        return false;
    }
    const MeasurementMapKey &mkey = claims[0].getKey();
    if (mkey.type != MeasurementMapKey::Type::kString) {
        return false;
    }
    const MeasurementValues &values = claims[0].getValues();
    const std::string *name = values.getName();
    const ByteString *raw = values.getRawValue();
    const Version *ver = values.getVersion();
    int set_count = (name != nullptr ? 1 : 0) + (raw != nullptr ? 1 : 0) +
                    (ver != nullptr ? 1 : 0);
    if (set_count != 1) {
        return false;
    }
    out.key = mkey.str_value;
    if (name != nullptr) {
        out.value = *name;
    } else if (raw != nullptr) {
        out.value.assign(reinterpret_cast<const char *>(raw->data()),
                         raw->size());
    } else {
        out.value = ver->getValue();
    }
    return true;
}

} // namespace

bool reverse_topological_sort(
    const std::vector<DependencyTriple> &dependencies,
    std::vector<EnvironmentMap> &out,
    std::map<EnvironmentMap, std::vector<EnvironmentMap>> *adj_out) {
    std::map<EnvironmentMap, std::vector<EnvironmentMap>> adj;
    for (const auto &dep : dependencies) {
        auto &out_edges = adj[dep.getDomainId()];
        out_edges.insert(out_edges.end(), dep.getTrustees().begin(),
                         dep.getTrustees().end());
    }

    enum class Mark { kNone, kTemporary, kPermanent };
    std::map<EnvironmentMap, Mark> marks;
    out.clear();
    bool cycle = false;

    // Recursive lambda via std::function (a lambda can't name itself).
    std::function<void(const EnvironmentMap &)> visit =
        [&](const EnvironmentMap &n) {
            if (cycle) {
                return;
            }
            Mark &mk = marks[n];
            if (mk == Mark::kPermanent) {
                return;
            }
            if (mk == Mark::kTemporary) {
                cycle = true;
                return;
            }
            mk = Mark::kTemporary;
            auto it = adj.find(n);
            if (it != adj.end()) {
                for (const auto &trustee : it->second) {
                    visit(trustee);
                    if (cycle) {
                        return;
                    }
                }
            }
            mk = Mark::kPermanent;
            out.push_back(n);
        };

    for (const auto &dep : dependencies) {
        visit(dep.getDomainId());
        if (cycle) {
            out.clear();
            return false;
        }
    }

    // DFS post-order is reverse topological order (trustees before domains).
    if (adj_out != nullptr) {
        *adj_out = std::move(adj);
    }
    return true;
}

VerificationResult verify(const std::vector<Ect> &reference,
                          const std::vector<Ect> &evidence,
                          const std::vector<DependencyTriple> &dependencies) {
    VerificationResult result;

    LOG_TRACE("verify(): reference ECTs: " << safe_json_dump(reference));
    LOG_TRACE("verify(): evidence ECTs: " << safe_json_dump(evidence));

    // Nothing to appraise the evidence against.
    if (reference.empty()) {
        result.diagnostics.push_back(Diagnostic::noReferenceEcts());
        return result;
    }

    std::vector<EnvironmentMap> rev_topo_sort;
    std::map<EnvironmentMap, std::vector<EnvironmentMap>> trustees_of;
    if (!reverse_topological_sort(dependencies, rev_topo_sort, &trustees_of)) {
        result.diagnostics.push_back(Diagnostic::dependencyCycle());
        return result;
    }

    // Evidence must carry exactly one root env: appraisal is anchored on it.
    const auto evidence_roots = find_root_environments(evidence);
    if (evidence_roots.empty()) {
        result.diagnostics.push_back(Diagnostic::noRootEnvironment());
        return result;
    }
    if (evidence_roots.size() > 1) {
        std::vector<EnvironmentMap> root_envs;
        root_envs.reserve(evidence_roots.size());
        for (const auto *env : evidence_roots) {
            if (std::find(root_envs.begin(), root_envs.end(), *env) ==
                root_envs.end()) {
                root_envs.push_back(*env);
            }
        }
        result.diagnostics.push_back(
            Diagnostic::multipleRootEnvironments(std::move(root_envs)));
        return result;
    }

    // Reference shape: duplicate mkeys within an ECT are fatal — each reference
    // ECT must carry at most one value per mkey. Duplicate environments across
    // ECTs are valid and represent alternative configurations.
    for (const auto &rv_ect : reference) {
        const auto &env = rv_ect.getEnvironment();
        std::set<MeasurementMapKey> seen_mkeys;
        for (const auto &claim : rv_ect.getClaims()) {
            if (!seen_mkeys.emplace(claim.getKey()).second) {
                result.diagnostics.push_back(
                    Diagnostic::duplicateReferenceMkey(env, claim.getKey()));
                return result;
            }
        }
    }

    // Any two reference ECTs for the same environment must have at least one
    // shared mkey with conflicting values. ECTs without a conflict are rejected
    // until the semantics of combining compatible ECTs are defined.
    {
        std::map<EnvironmentMap, std::vector<const Ect *>> ects_by_env;
        for (const auto &rv_ect : reference) {
            ects_by_env[rv_ect.getEnvironment()].push_back(&rv_ect);
        }
        for (const auto &entry : ects_by_env) {
            const auto &ects = entry.second;
            for (size_t i = 0; i < ects.size(); ++i) {
                for (size_t j = i + 1; j < ects.size(); ++j) {
                    if (!have_conflicting_mkey(*ects[i], *ects[j])) {
                        result.diagnostics.push_back(
                            Diagnostic::mergeableReferenceEcts(entry.first));
                        return result;
                    }
                }
            }
        }
    }

    // Evidence shape: duplicate envs across ECTs and duplicate mkeys
    // within one ECT are both fatal (ambiguous merge).
    std::set<EnvironmentMap> ev_envs_seen;
    for (const auto &ev_ect : evidence) {
        const auto &env = ev_ect.getEnvironment();
        if (!ev_envs_seen.emplace(env).second) {
            result.diagnostics.push_back(
                Diagnostic::duplicateEvidenceEnv(env));
            return result;
        }
        std::set<MeasurementMapKey> seen_mkeys;
        for (const auto &claim : ev_ect.getClaims()) {
            if (!seen_mkeys.emplace(claim.getKey()).second) {
                result.diagnostics.push_back(
                    Diagnostic::duplicateEvidenceMkey(env, claim.getKey()));
                return result;
            }
        }
    }

    // Group reference ECTs by environment. Multiple ECTs for the same
    // environment are alternatives: the env passes if any one matches evidence.
    std::vector<EnvOutcome> outcomes;
    std::map<EnvironmentMap, size_t> outcome_idx_by_env;

    for (const auto &rv_ect : reference) {
        const auto &env = rv_ect.getEnvironment();
        auto ins = outcome_idx_by_env.emplace(env, outcomes.size());
        if (ins.second) {
            EnvOutcome eo;
            eo.environment = env;
            outcomes.push_back(std::move(eo));
        }
        EnvOutcome &eo = outcomes[ins.first->second];

        EctAttempt attempt;
        const auto matching = find_ev_ects_by_env(env, evidence);
        if (matching.empty()) {
            attempt.reason.no_evidence = true;
        }
        for (const auto *ev_ect : matching) {
            auto mismatches = compare_ects(rv_ect, *ev_ect);
            if (mismatches.empty()) {
                attempt.matched_evidence_ects.push_back(*ev_ect);
            } else {
                auto &dst = attempt.reason.mkey_mismatches;
                dst.insert(dst.end(),
                           std::make_move_iterator(mismatches.begin()),
                           std::make_move_iterator(mismatches.end()));
            }
        }
        eo.reference_claims.push_back(rv_ect.getClaims());
        eo.attempts.push_back(std::move(attempt));
    }

    for (const auto &env : ev_envs_seen) {
        bool covered = std::any_of(
            outcome_idx_by_env.begin(), outcome_idx_by_env.end(),
            [&env](const auto &kv) { return kv.first.matches(env); });
        if (!covered) {
            result.unmatched_environments.push_back(env);
        }
    }

    // Every dep-graph env must be backed by a ref ECT — an unbacked env
    // contributes nothing to appraisal and would silently pass.
    for (const auto &env : rev_topo_sort) {
        if (outcome_idx_by_env.find(env) == outcome_idx_by_env.end()) {
            result.diagnostics.push_back(
                Diagnostic::missingReferenceForDependencyEnv(env));
            return result;
        }
    }

    // Propagate trustee failures up the graph. Reverse-topo order
    // finalizes each trustee before its domain, so passed() reads
    // fully-populated failed_dependencies.
    for (const auto &env : rev_topo_sort) {
        auto adj_it = trustees_of.find(env);
        if (adj_it == trustees_of.end()) {
            continue;
        }
        auto &eo = outcomes[outcome_idx_by_env[env]];
        for (const auto &trustee : adj_it->second) {
            if (!outcomes[outcome_idx_by_env[trustee]].passed()) {
                eo.reason.failed_dependencies.push_back(trustee);
            }
        }
    }

    const EnvironmentMap &root_ev = *evidence_roots[0];
    std::vector<EnvironmentMap> anchors;
    for (const auto &eo : outcomes) {
        // Cheap field compare before the OID parse in is_root_env.
        if (!eo.environment.matches(root_ev) || !is_root_env(eo.environment)) {
            continue;
        }
        anchors.push_back(eo.environment);
        const bool own_attempt_passed = std::any_of(
            eo.attempts.begin(), eo.attempts.end(),
            [](const EctAttempt &at) { return at.passed(); });
        if (result.purpose != nullptr || !own_attempt_passed) {
            continue;
        }
        // Every passing alternative must declare a purpose in both reference
        // and evidence. A purposeless valid state is unacceptable for a root
        // environment.
        std::unique_ptr<std::string> runtime_purpose;
        for (size_t i = 0; i < eo.attempts.size(); ++i) {
            if (!eo.attempts[i].passed()) {
                continue;
            }
            if (parse_purpose(eo.reference_claims[i]) == nullptr) {
                result.diagnostics.push_back(
                    Diagnostic::rootEnvironmentMissingPurpose(eo.environment));
                return result;
            }
            // kDuplicateEvidenceEnv guarantees at most one evidence ECT per
            // env, so matched_evidence_ects always has exactly one entry here.
            assert(eo.attempts[i].matched_evidence_ects.size() == 1);
            auto ev_purpose = parse_purpose(
                eo.attempts[i].matched_evidence_ects[0].getClaims());
            if (ev_purpose == nullptr) {
                result.diagnostics.push_back(
                    Diagnostic::rootEnvironmentMissingPurpose(eo.environment));
                return result;
            }
            if (runtime_purpose == nullptr) {
                runtime_purpose = std::move(ev_purpose);
            }
        }
        if (runtime_purpose == nullptr) {
            result.diagnostics.push_back(
                Diagnostic::rootEnvironmentMissingPurpose(eo.environment));
            return result;
        }
        result.purpose = std::move(runtime_purpose);
    }

    // Mark the in-scope set (the root plus its transitive trustees) so
    // consumers can select only the references reachable from the attested
    // root. Outcomes outside the subtree are retained but flagged false rather
    // than dropped.
    const std::set<EnvironmentMap> in_scope =
        collect_reachable(std::move(anchors), trustees_of);
    for (auto &eo : outcomes) {
        eo.reachable_from_root = in_scope.count(eo.environment) != 0;
    }

    // Corroboration reuses each env's outcome: a passing attempt means
    // corroborated. Maps commit after the loop so a malformed env aborts clean.
    std::map<std::string, std::string> corroborated;
    std::map<std::string, std::string> uncorroborated;
    for (const auto &ev_ect : evidence) {
        const EnvironmentMap &env = ev_ect.getEnvironment();
        if (!is_claims_from_evidence_env(env)) {
            continue;
        }
        EvidenceClaim claim;
        if (!extract_evidence_claim(ev_ect, claim)) {
            result.diagnostics.push_back(
                Diagnostic::malformedClaimsFromEvidenceEnv(env));
            return result;
        }
        if (!is_valid_utf8(claim.value)) {
            result.diagnostics.push_back(Diagnostic::nonUtf8EvidenceClaim(env));
            return result;
        }
        if (corroborated.count(claim.key) != 0 ||
            uncorroborated.count(claim.key) != 0) {
            result.diagnostics.push_back(
                Diagnostic::duplicateEvidenceClaimKey(env, claim.key));
            return result;
        }
        bool is_corroborated = false;
        for (const auto &eo : outcomes) {
            if (eo.environment.matches(env) &&
                std::any_of(eo.attempts.begin(), eo.attempts.end(),
                            [](const EctAttempt &attempt) {
                                return attempt.passed();
                            })) {
                is_corroborated = true;
                break;
            }
        }
        if (is_corroborated) {
            corroborated[claim.key] = claim.value;
        } else {
            uncorroborated[claim.key] = claim.value;
        }
    }
    result.corroborated_evidence_claims = std::move(corroborated);
    result.uncorroborated_evidence_claims = std::move(uncorroborated);

    result.outcomes = std::move(outcomes);
    return result;
}

bool EctAttempt::passed() const {
    return !matched_evidence_ects.empty() && !reason.any();
}

bool cert_chain_dti_matches(const std::vector<EnvironmentMap> &chain_envs,
                            const std::vector<EnvOutcome> &outcomes) {
    return std::all_of(
        chain_envs.begin(), chain_envs.end(),
        [&outcomes](const EnvironmentMap &chain_env) {
            return std::any_of(
                outcomes.begin(), outcomes.end(),
                [&chain_env](const EnvOutcome &outcome) {
                    return outcome.matched() &&
                           outcome.environment.matches(chain_env);
                });
        });
}

bool EnvOutcome::matched() const { return reachable_from_root && passed(); }

bool EnvOutcome::mismatched() const {
    return reachable_from_root && !passed();
}

bool EnvOutcome::passed() const {
    if (!reason.failed_dependencies.empty()) {
        return false;
    }
    return std::any_of(
        attempts.begin(), attempts.end(),
        [](const EctAttempt &attempt) { return attempt.passed(); });
}

void to_json(nlohmann::json &json_out, const Ect &ect) {
    json_out = nlohmann::json::object();
    json_out["environment"] = ect.getEnvironment();
    json_out["claims"] = ect.getClaims();
}

void to_json(nlohmann::json &json_out, const MismatchReason &reason) {
    json_out = nlohmann::json::object();
    if (reason.no_evidence) {
        json_out["no_evidence"] = true;
    }
    if (!reason.mkey_mismatches.empty()) {
        json_out["mkey_mismatches"] = reason.mkey_mismatches;
    }
    if (!reason.failed_dependencies.empty()) {
        json_out["failed_dependencies"] = reason.failed_dependencies;
    }
}

Diagnostic Diagnostic::dependencyCycle() {
    return {Severity::kError, Code::kDependencyCycle,
            "dependency graph contains a cycle"};
}

Diagnostic Diagnostic::noReferenceEcts() {
    return {Severity::kError, Code::kNoReferenceEcts,
            "no reference ECTs to appraise the evidence against"};
}

Diagnostic Diagnostic::noRootEnvironment() {
    return {Severity::kError, Code::kNoRootEnvironment,
            "no evidence ECT carries the root class id"};
}

Diagnostic
Diagnostic::multipleRootEnvironments(std::vector<EnvironmentMap> envs) {
    return {Severity::kError, Code::kMultipleRootEnvironments,
            "evidence carries multiple ECTs with the root class id "
            "(exactly one required)", std::move(envs)};
}

Diagnostic Diagnostic::rootEnvironmentMissingPurpose(const EnvironmentMap &env) {
    return {Severity::kError, Code::kRootEnvironmentMissingPurpose,
            "root environment does not declare a purpose measurement", {env}};
}

Diagnostic Diagnostic::duplicateReferenceMkey(const EnvironmentMap &env,
                                              const MeasurementMapKey &mkey) {
    return {Severity::kError, Code::kDuplicateReferenceMkey,
            "reference ECT carries duplicate mkey " + mkey.toDisplayString(),
            {env}};
}

Diagnostic Diagnostic::mergeableReferenceEcts(const EnvironmentMap &env) {
    return {Severity::kError, Code::kMergeableReferenceEcts,
            "two reference ECTs for the same environment have no conflicting "
            "mkey; compatible ECTs are not supported", {env}};
}

Diagnostic Diagnostic::duplicateEvidenceEnv(const EnvironmentMap &env) {
    return {Severity::kError, Code::kDuplicateEvidenceEnv,
            "evidence carries two ECTs for the same environment", {env}};
}

Diagnostic Diagnostic::duplicateEvidenceMkey(const EnvironmentMap &env,
                                             const MeasurementMapKey &mkey) {
    return {Severity::kError, Code::kDuplicateEvidenceMkey,
            "evidence ECT carries duplicate mkey " + mkey.toDisplayString(),
            {env}};
}

Diagnostic
Diagnostic::missingReferenceForDependencyEnv(const EnvironmentMap &env) {
    return {Severity::kError, Code::kMissingReferenceForDependencyEnv,
            "environment in dependency graph has no reference ECT", {env}};
}

Diagnostic
Diagnostic::malformedClaimsFromEvidenceEnv(const EnvironmentMap &env) {
    return {Severity::kError, Code::kMalformedClaimsFromEvidenceEnv,
            "claims-from-evidence environment must carry exactly one "
            "string-keyed measurement with a single name, raw-value, or version",
            {env}};
}

Diagnostic Diagnostic::nonUtf8EvidenceClaim(const EnvironmentMap &env) {
    return {Severity::kError, Code::kNonUtf8EvidenceClaim,
            "claims-from-evidence value is not valid UTF-8", {env}};
}

Diagnostic
Diagnostic::duplicateEvidenceClaimKey(const EnvironmentMap &env,
                                      const std::string &key) {
    return {Severity::kError, Code::kDuplicateEvidenceClaimKey,
            "duplicate claims-from-evidence claim key " + key, {env}};
}

const char *to_string(Diagnostic::Severity severity) {
    switch (severity) {
    case Diagnostic::Severity::kError:
        return "error";
    case Diagnostic::Severity::kWarning:
        return "warning";
    }
    return "unknown";
}

const char *to_string(Diagnostic::Code code) {
    switch (code) {
    case Diagnostic::Code::kDependencyCycle:
        return "dependency-cycle";
    case Diagnostic::Code::kNoReferenceEcts:
        return "no-reference-ects";
    case Diagnostic::Code::kNoRootEnvironment:
        return "no-root-environment";
    case Diagnostic::Code::kMultipleRootEnvironments:
        return "multiple-root-environments";
    case Diagnostic::Code::kRootEnvironmentMissingPurpose:
        return "root-environment-missing-purpose";
    case Diagnostic::Code::kDuplicateReferenceMkey:
        return "duplicate-reference-mkey";
    case Diagnostic::Code::kMergeableReferenceEcts:
        return "mergeable-reference-ects";
    case Diagnostic::Code::kDuplicateEvidenceEnv:
        return "duplicate-evidence-env";
    case Diagnostic::Code::kDuplicateEvidenceMkey:
        return "duplicate-evidence-mkey";
    case Diagnostic::Code::kMissingReferenceForDependencyEnv:
        return "missing-reference-for-dependency-env";
    case Diagnostic::Code::kMalformedClaimsFromEvidenceEnv:
        return "malformed-claims-from-evidence-env";
    case Diagnostic::Code::kNonUtf8EvidenceClaim:
        return "non-utf8-evidence-claim";
    case Diagnostic::Code::kDuplicateEvidenceClaimKey:
        return "duplicate-evidence-claim-key";
    }
    return "unknown";
}

// The codes are the public values themselves; naming them would only duplicate
// the case labels they sit against.
// NOLINTBEGIN(readability-magic-numbers)
int diagnostic_public_code(Diagnostic::Code code) {
    switch (code) {
    case Diagnostic::Code::kDependencyCycle:                  return 1000;
    case Diagnostic::Code::kNoReferenceEcts:                  return 1001;
    case Diagnostic::Code::kNoRootEnvironment:                return 1002;
    case Diagnostic::Code::kMultipleRootEnvironments:         return 1003;
    case Diagnostic::Code::kRootEnvironmentMissingPurpose:    return 1004;
    case Diagnostic::Code::kDuplicateReferenceMkey:           return 1005;
    case Diagnostic::Code::kMergeableReferenceEcts:           return 1006;
    case Diagnostic::Code::kDuplicateEvidenceEnv:             return 1007;
    case Diagnostic::Code::kDuplicateEvidenceMkey:            return 1008;
    case Diagnostic::Code::kMissingReferenceForDependencyEnv: return 1009;
    case Diagnostic::Code::kMalformedClaimsFromEvidenceEnv:   return 1010;
    case Diagnostic::Code::kNonUtf8EvidenceClaim:             return 1011;
    case Diagnostic::Code::kDuplicateEvidenceClaimKey:        return 1012;
    }
    return 1999;
}
// NOLINTEND(readability-magic-numbers)

void to_json(nlohmann::json &json_out, const Diagnostic &diagnostic) {
    json_out = nlohmann::json::object();
    json_out["severity"] = to_string(diagnostic.severity);
    json_out["code"] = to_string(diagnostic.code);
    if (!diagnostic.detail.empty()) {
        json_out["detail"] = diagnostic.detail;
    }
    if (!diagnostic.related_envs.empty()) {
        json_out["related_envs"] = diagnostic.related_envs;
    }
}

void to_json(nlohmann::json &json_out, const EctAttempt &attempt) {
    json_out = nlohmann::json::object();
    json_out["passed"] = attempt.passed();
    if (!attempt.matched_evidence_ects.empty()) {
        json_out["matched_evidence_ects"] = attempt.matched_evidence_ects;
    }
    if (attempt.reason.any()) {
        json_out["reason"] = attempt.reason;
    }
}

void to_json(nlohmann::json &json_out, const EnvOutcome &outcome) {
    json_out = nlohmann::json::object();
    json_out["passed"] = outcome.passed();
    json_out["reachable_from_root"] = outcome.reachable_from_root;
    json_out["environment"] = outcome.environment;
    json_out["reference_claims"] = outcome.reference_claims;
    json_out["attempts"] = outcome.attempts;
    if (outcome.reason.any()) {
        json_out["reason"] = outcome.reason;
    }
}

void to_json(nlohmann::json &json_out, const VerificationResult &result) {
    json_out = nlohmann::json::object();
    if (!result.diagnostics.empty()) {
        json_out["diagnostics"] = result.diagnostics;
    }
    json_out["outcomes"] = result.outcomes;
    if (result.purpose != nullptr) {
        json_out["purpose"] = *result.purpose;
    }
    if (!result.corroborated_evidence_claims.empty()) {
        json_out["corroborated_evidence_claims"] =
            result.corroborated_evidence_claims;
    }
    if (!result.uncorroborated_evidence_claims.empty()) {
        json_out["uncorroborated_evidence_claims"] =
            result.uncorroborated_evidence_claims;
    }
    if (!result.unmatched_environments.empty()) {
        json_out["unmatched_environments"] = result.unmatched_environments;
    }
}

Error LocalCorimVerifier::anchor_device_chain(const std::string &chain_pem,
                                              X509CertChain &out_chain) const {
    std::vector<nv_unique_ptr<X509>> anchors;
    std::vector<X509 *> anchor_ptrs;
    for (const auto &root : m_device_identity_roots) {
        nv_unique_ptr<X509> cert = x509_from_cert_string(root);
        if (!cert) {
            continue;
        }
        anchor_ptrs.push_back(cert.get());
        anchors.push_back(std::move(cert));
    }
    if (anchor_ptrs.empty()) {
        return Error::CertChainVerificationFailure;
    }
    nv_unique_ptr<X509_STORE> store = create_trust_store(anchor_ptrs);
    if (!store) {
        return Error::CertChainVerificationFailure;
    }
    Error build = X509CertChain::create_from_cert_chain_str(
        CertificateChainType::GENERIC, std::move(store), chain_pem, out_chain);
    if (build != Error::Ok) {
        return build;
    }
    return out_chain.verify();
}

Error LocalCorimVerifier::verify_coev_signature(
    const std::vector<uint8_t> &coev_bytes,
    const std::shared_ptr<IOcspHttpClient> &ocsp_client,
    std::vector<uint8_t> &out_payload,
    std::vector<PerCertStatus> &out_cert_claims) const {
    CoseSign1VerifyOptions cose_opts;
    cose_opts.root_cert_pem = m_rim_signing_root;
    cose_opts.verify_ocsp = (ocsp_client != nullptr);
    NvHttpOcspClient ocsp_placeholder;
    IOcspHttpClient &ocsp_ref =
        ocsp_client ? *ocsp_client
                    : static_cast<IOcspHttpClient &>(ocsp_placeholder);
    CoseSign1Result cose_result;
    Error err = verify_cose_sign1(coev_bytes, cose_opts, ocsp_ref, cose_result);
    // Propagate cert-chain claims even on failure: verify_cose_sign1 may
    // have populated them before rejecting the chain (e.g. for revocation),
    // and the caller needs that diagnostic data regardless of outcome.
    out_cert_claims = std::move(cose_result.cert_chain_claims);
    if (err != Error::Ok) {
        return err;
    }
    out_payload = std::move(cose_result.payload);
    return Error::Ok;
}

LocalCorimVerifier::LocalCorimVerifier(
    CorimStore corim_store, std::shared_ptr<IOcspHttpClient> ocsp_client)
    : m_corim_store(std::move(corim_store)),
      m_ocsp_client(std::move(ocsp_client)) {
    // TODO(v2): replace with operator-supplied per-device RoT registry.
    m_device_identity_roots.emplace_back(DEVICE_ROOT_CERT);
    m_rim_signing_root = RIM_ROOT_CERT_CA001;
}

Error LocalCorimVerifier::add_device_identity_trust_root_pem(std::string pem) {
    if (pem.empty()) {
        LOG_ERROR("device-identity trust root PEM is empty");
        return Error::BadArgument;
    }
    m_device_identity_roots.push_back(std::move(pem));
    return Error::Ok;
}

void LocalCorimVerifier::set_verify_revocation(bool enabled) {
    m_verify_revocation = enabled;
}

void LocalCorimVerifier::set_verify_rim_signature(bool enabled) {
    m_verify_rim_signature = enabled;
}

void LocalCorimVerifier::set_verify_coev_signature(bool enabled) {
    m_verify_coev_signature = enabled;
}

void LocalCorimVerifier::set_rim_signing_root_for_testing(std::string root_cert_pem) {
    m_rim_signing_root = std::move(root_cert_pem);
}

void LocalCorimVerifier::set_verify_evidence_signature(bool enabled) {
    m_evidence_handler_settings.m_verify_evidence_signature = enabled;
}

Error LocalCorimVerifier::set_backup_spdm_coev(const uint8_t* data, std::size_t len) {
    if (data == nullptr || len == 0) {
        LOG_ERROR("backup CoEV data is null or empty");
        return Error::BadArgument;
    }
    m_evidence_handler_settings.m_backup_coev.assign(data, data + len);
    return Error::Ok;
}

void LocalCorimVerifier::add_backup_rim_locator(std::string uri) {
    m_corim_store.m_allowed_prefixes.push_back(uri);
    m_backup_rim_locators.push_back(std::move(uri));
}

void LocalCorimVerifier::set_default_hash_algorithms(std::vector<HashAlgorithm> algs) {
    m_default_hash_algorithms = std::move(algs);
}

void to_json(nlohmann::json &json_out, const PerCertStatus &status) {
    json_out = nlohmann::json::object();
    json_out["expired"] = status.expired;
    json_out["expiration_date"] = status.expiration_date;
    if (status.ocsp) {
        json_out["ocsp_response_status"] = status.ocsp->response_valid;
        if (!status.ocsp->response_produced_at.empty()) {
            json_out["ocsp_response_produced_at"] = status.ocsp->response_produced_at;
        }
        json_out["ocsp_crl_status"] = to_string(status.ocsp->crl_status);
        if (status.ocsp->revocation_reason && !status.ocsp->revocation_reason->empty()) {
            json_out["revocation_reason"] = *status.ocsp->revocation_reason;
        }
        if (!status.ocsp->response_revoked_at.empty()) {
            json_out["ocsp_response_revoked_at"] = status.ocsp->response_revoked_at;
        }
        json_out["ocsp_nonce_matches"] = status.ocsp->nonce_matches;
        json_out["ocsp_crl_response_expired"] = status.ocsp->response_expired;
        if (!status.ocsp->response_expiration_date.empty()) {
            json_out["ocsp_crl_response_expiration_date"] = status.ocsp->response_expiration_date;
        }
    }
    json_out["cert_check_status"] = to_string(status.cert_check_status);
}

void to_json(nlohmann::json &json_out, const CorimResult &result) {
    json_out = nlohmann::json::object();
    json_out["fetched"] = result.fetched;
    json_out["locator"] = result.locator;
    json_out["parsed"] = result.parsed;
    if (result.fetched) {
        json_out["signature_verified"] = result.signature_verified;
        if (!result.id.empty()) {
            json_out["id"] = result.id;
        }
        if (result.cert_chain) {
            json_out["cert_chain"] = *result.cert_chain;
        }
    }
    if (result.error.has_error()) {
        json_out["error"] = result.error;
    }
}

void to_json(nlohmann::json &json_out, const EvidenceClaims &evidence) {
    json_out = nlohmann::json::object();
    json_out["signature_verified"] = evidence.signature_verified;
    json_out["parsed"] = evidence.parsed;
    if (evidence.nonce_supplied) {
        json_out["nonce_match"] = evidence.nonce_match;
    }
    if (evidence.cert_chain) {
        json_out["cert_chain"] = *evidence.cert_chain;
    }
    // PEM is a tagged-pkix-base64-key-type, one of the CoRIM
    // $crypto-key-type-choice alternatives.
    if (!evidence.akpub.empty()) {
        json_out["akpub"] = evidence.akpub;
    }
    // Both identify an individual device, so releasing either lets an RP
    // correlate attestations back to one part.
    // TODO(P1): enable once the authorization model is settled.
    // if (!evidence.device_cert_serial.empty()) {
    //     json_out["device_cert_serial"] = evidence.device_cert_serial;
    // }
    // if (!evidence.spdm_end_entity_othername_serial.empty()) {
    //     json_out["spdm_end_entity_othername_serial"] =
    //         evidence.spdm_end_entity_othername_serial;
    // }
}

void to_json(nlohmann::json &json_out, const StageError &err) {
    json_out = nlohmann::json::object();
    json_out["code"] = static_cast<int>(err.code);
    json_out["message"] = err.message;
    if (!err.details.empty()) {
        json_out["details"] = err.details;
    }
}

void to_json(nlohmann::json &json_out, const EvidenceItemAppraisal &item) {
    json_out = nlohmann::json::object();
    json_out["label"] = item.label;
    if (!item.eat_nonce.empty()) {
        std::string encoded;
        if (encode_base64(item.eat_nonce, encoded) == Error::Ok) {
            json_out["eat_nonce"] = encoded;
        }
    }
    json_out["evidence"] = item.evidence;
    if (!item.corims.empty()) {
        json_out["corims"] = item.corims;
    }
    json_out["match"] = item.match;
    if (item.stage_error.has_error()) {
        json_out["stage_error"] = item.stage_error;
    }
    if (!item.chain_ect_environments.empty()) {
        json_out["chain_ect_environments"] = item.chain_ect_environments;
    }
}

void to_json(nlohmann::json &json_out, const InputDigest &digest) {
    json_out = nlohmann::json::object();
    std::string val_b64url;
    if (encode_base64url(digest.val, val_b64url) != Error::Ok) {
        LOG_ERROR("Failed to base64url-encode input digest for alg: "
                  << to_algorithm_name(digest.alg));
        return;
    }
    json_out["alg"] = to_algorithm_name(digest.alg);
    json_out["val"] = std::move(val_b64url);
}

void to_json(nlohmann::json &json_out, const CorimAttestationResult &result) {
    json_out = nlohmann::json::object();
    json_out["evidence_items"] = result.items;
    if (!result.input_digests.empty()) {
        json_out["input_digests"] = result.input_digests;
    }
}

namespace {
std::vector<PerCertStatus>
collect_per_cert_status(const X509CertChain &chain,
                        const std::shared_ptr<IOcspHttpClient> &ocsp_client) {
    std::vector<PerCertStatus> statuses;
    if (chain.generate_per_cert_status(OcspVerifyOptions(), ocsp_client.get(), statuses) != Error::Ok) {
        LOG_WARN("OCSP collection failed; per-cert OCSP data will be absent");
    }
    return statuses;
}

// item.hints is untrusted; a missing hint or fwversion key is not a fault
// (out_fw_version stays empty) -- only malformed JSON errors.
Error extract_firmware_version_hint(const CmwEvidenceItem &item,
                                    std::string &out_fw_version) {
    out_fw_version.clear();
    if (!item.hints) {
        return Error::Ok;
    }
    nlohmann::json hints_json;
    try {
        hints_json = nlohmann::json::parse(item.hints->value.begin(),
                                           item.hints->value.end());
    } catch (const nlohmann::json::exception &e) {
        LOG_ERROR("hints record is not valid JSON: " << e.what());
        return Error::EvidenceMalformed;
    }
    if (!hints_json.is_object()) {
        LOG_ERROR("hints record is not a JSON object");
        return Error::EvidenceMalformed;
    }
    auto fwversion = hints_json.find("fwversion");
    if (fwversion != hints_json.end()) {
        if (!fwversion->is_string()) {
            LOG_ERROR("hints.fwversion is not a string");
            return Error::EvidenceMalformed;
        }
        out_fw_version = fwversion->get<std::string>();
    }
    return Error::Ok;
}

// #6.570-tagged SpdmToc vs. a bare #6.571-tagged ConciseEvidence (TCG DICE
// §6.3.1) -- same sniff as evidence_handler.cpp's backup-CoEV handling.
constexpr uint8_t kSpdmTocCborTagBytes[3] = {0xD9, 0x02, 0x3A};

// Converts a RIM-service-fetched CoEV payload into ECTs. out_stage names
// the failed step, for logging.
Error convert_fetched_coev_to_ects(
    const std::vector<uint8_t> &coev_bytes,
    const SpdmMeasurementRecordParser *measurement_records,
    int32_t measurement_hash_algorithm_id,
    std::vector<Ect> &out_ects,
    std::unique_ptr<ProfileValue> &out_profile,
    const char *&out_stage) {
    const bool is_toc = coev_bytes.size() >= sizeof(kSpdmTocCborTagBytes) &&
        coev_bytes[0] == kSpdmTocCborTagBytes[0] &&
        coev_bytes[1] == kSpdmTocCborTagBytes[1] &&
        coev_bytes[2] == kSpdmTocCborTagBytes[2];
    if (is_toc) {
        SpdmToc toc;
        Error err = parse_spdm_toc(coev_bytes, toc);
        if (err != Error::Ok) {
            out_stage = "SpdmToc parse";
            return err;
        }
        if (toc.getProfile() != nullptr) {
            out_profile = std::make_unique<ProfileValue>(*toc.getProfile());
        }
        if (measurement_records == nullptr) {
            out_stage = "SpdmToc requires SPDM measurement records, none available";
            return Error::BadArgument;
        }
        // The toc's own rim-locators go unused: rim_locator_urls is
        // already resolved by the time this runs.
        std::vector<CorimLocatorMap> unused_locators;
        err = spdm_toc_to_ects(toc, *measurement_records,
                               measurement_hash_algorithm_id, out_ects,
                               unused_locators);
        if (!unused_locators.empty()) {
            LOG_WARN("fetched CoEV's SpdmToc carries " << unused_locators.size()
                     << " rim-locator(s); ignored, rim_locator_urls was "
                        "already resolved");
        }
        if (err != Error::Ok) {
            out_stage = "SpdmToc -> ECT mapping";
        }
        return err;
    }
    ConciseEvidence ce;
    Error err = parse_concise_evidence(coev_bytes, ce);
    if (err != Error::Ok) {
        out_stage = "ConciseEvidence parse";
        return err;
    }
    if (ce.getProfile() != nullptr) {
        out_profile = std::make_unique<ProfileValue>(*ce.getProfile());
    }
    err = (measurement_records != nullptr)
        ? concise_evidence_to_ects(ce, *measurement_records,
                                   measurement_hash_algorithm_id, out_ects)
        : concise_evidence_to_ects(ce, out_ects);
    if (err != Error::Ok) {
        out_stage = "ConciseEvidence -> ECT mapping";
    }
    return err;
}

// A CoEV fetched alongside the CoRIM is reference data from the RIM service,
// not something the attester sent, so it must not read as bad evidence.
Error fetched_coev_error(Error err) {
    return err == Error::EvidenceMalformed ? Error::RimInvalidSchema : err;
}
} // namespace

EvidenceItemAppraisal LocalCorimVerifier::appraise_item(
    const std::string &label, const CmwEvidenceItem &item) const {
    EvidenceItemAppraisal appraisal;
    appraisal.label = label;

    // Revocation gates the injected client; disabled => not consulted.
    const std::shared_ptr<IOcspHttpClient> ocsp_client =
        m_verify_revocation ? m_ocsp_client : nullptr;

    const IEvidenceHandler *handler =
        find_evidence_handler(item.evidence.media_type);
    if (handler == nullptr) {
        appraisal.stage_error = {
            Error::EvidenceMalformed,
            "no evidence handler for media type: " + item.evidence.media_type,
            ""};
        LOG_ERROR("[" << label << "] " << appraisal.stage_error.message);
        return appraisal;
    }

    std::vector<uint8_t> chain_pem;
    if (handler->extract_cert_chain(item, m_evidence_handler_settings, chain_pem) !=
        Error::Ok) {
        appraisal.stage_error = {Error::EvidenceMalformed,
                                 "cert chain extraction failed", ""};
        LOG_WARN("[" << label << "] " << appraisal.stage_error.message);
        return appraisal;
    }
    X509CertChain device_chain;
    bool chain_available = false;
    bool chain_anchored = false;
    if (chain_pem.empty()) {
        LOG_INFO("[" << label << "] no device-identity chain for this item "
                     "(unsigned evidence)");
    } else {
        std::string chain_str(chain_pem.begin(), chain_pem.end());
        Error anchor = anchor_device_chain(chain_str, device_chain);
        chain_available = device_chain.size() != 0;
        if (anchor != Error::Ok) {
            if (m_evidence_handler_settings.m_verify_evidence_signature) {
                appraisal.stage_error = {Error::CertChainVerificationFailure,
                                         "cert chain does not anchor to a known root", ""};
                LOG_ERROR("[" << label << "] " << appraisal.stage_error.message);
                return appraisal;
            }
            LOG_WARN("[" << label << "] cert chain does not anchor to a known "
                         "root; continuing because evidence-signature "
                         "verification is disabled");
        } else {
            chain_anchored = true;
            LOG_INFO("[" << label << "] cert chain anchored to known root");
        }

        if (chain_available) {
            DmtfDeviceInfo device_info;
            if (device_chain.get_end_entity_dmtf_device_info(device_info) ==
                Error::Ok) {
                appraisal.evidence.spdm_end_entity_othername_serial =
                    device_info.serial;
                appraisal.hwmodel = device_info.product;
            } else {
                LOG_DEBUG("[" << label
                              << "] no DMTF otherName in end-entity cert");
            }

            appraisal.evidence.cert_chain =
                std::make_unique<std::vector<PerCertStatus>>(
                    collect_per_cert_status(device_chain, ocsp_client));
            LOG_INFO("[" << label << "] device cert chain: "
                         << appraisal.evidence.cert_chain->size() << " certs");
        }
    }

    EvidenceVerification verification;
    Error extract_err = handler->verify_and_extract_ects(
        item, device_chain, m_evidence_handler_settings, verification);
    bool cert_chain_trusted = !appraisal.evidence.cert_chain ||
        all_certs_trusted(*appraisal.evidence.cert_chain);
    appraisal.evidence.signature_verified =
        chain_anchored && verification.signature_valid && cert_chain_trusted;
    appraisal.evidence.parsed = verification.parsed;
    appraisal.eat_nonce = std::move(verification.eat_nonce);
    appraisal.evidence_profile = std::move(verification.evidence_profile);
    appraisal.evidence.nonce_supplied = !item.nonce.empty();
    appraisal.evidence.nonce_match = verification.nonce_matches;
    if (extract_err != Error::Ok) {
        appraisal.stage_error = {extract_err,
                                 verification.nonce_matches
                                     ? "evidence -> ECT mapping failed"
                                     : "evidence payload malformed",
                                 ""};
        LOG_ERROR("[" << label << "] " << appraisal.stage_error.message);
        return appraisal;
    }
    if (!verification.signature_valid) {
        if (m_evidence_handler_settings.m_verify_evidence_signature) {
            appraisal.stage_error = {Error::EvidenceInvalidSignature,
                                     "evidence signature verification failed", ""};
            LOG_ERROR("[" << label << "] " << appraisal.stage_error.message);
            return appraisal;
        }
        LOG_WARN("[" << label << "] evidence signature verification failed; "
                     "continuing because verification is disabled");
    }
    if (chain_available && device_chain.get_end_entity_public_key_pem(
                               appraisal.evidence.akpub) != Error::Ok) {
        LOG_WARN("[" << label << "] could not export end-entity public key");
    }
    if (!item.nonce.empty() && !verification.nonce_matches) {
        appraisal.stage_error = {Error::EvidenceNonceMismatch,
                                 "evidence nonce mismatch", ""};
        LOG_ERROR("[" << label << "] " << appraisal.stage_error.message);
        return appraisal;
    }
    std::vector<Ect> evidence_ects = std::move(verification.ects);
    std::vector<std::string> rim_locator_urls =
        std::move(verification.rim_locator_urls);
    const bool evidence_has_backup_coev = verification.used_backup_coev;
    LOG_INFO("[" << label << "] evidence payload yielded "
                 << evidence_ects.size() << " ECT(s) and "
                 << rim_locator_urls.size() << " rim-locator URL(s)");

    const bool is_fsp_responder =
        chain_available && is_blackwell_fsp_responder(device_chain, appraisal.hwmodel);

    // Last resort after both CoEV-discovery mechanisms above find nothing.
    // Tracks whether this path supplied the locator, for the loop below.
    std::string rim_synthesized_locator;
    // Kept so the terminal check below can report why synthesis failed rather
    // than a generic "not found".
    Error locator_error = Error::Ok;
    std::string locator_failure_reason;
    if (is_fsp_responder && rim_locator_urls.empty()) {
        std::string fw_version;
        Error hint_err = extract_firmware_version_hint(item, fw_version);
        if (hint_err != Error::Ok) {
            appraisal.stage_error = {Error::EvidenceMalformed,
                                     "malformed hints record", ""};
            LOG_ERROR("[" << label << "] " << appraisal.stage_error.message);
            return appraisal;
        }
        std::string synthesized_locator;
        locator_error = build_vbios_rim_locator(
            appraisal.hwmodel, verification.device_identifier_measurement,
            fw_version, synthesized_locator, locator_failure_reason);
        if (locator_error == Error::Ok) {
            rim_synthesized_locator = synthesized_locator;
            rim_locator_urls.push_back(std::move(synthesized_locator));
            LOG_INFO("[" << label << "] workaround synthesized a RIM "
                         "locator (hwmodel=" << appraisal.hwmodel
                         << ") from evidence + hints");
        }
    }
    if (rim_locator_urls.empty() && !m_backup_rim_locators.empty()) {
        rim_locator_urls = m_backup_rim_locators;
        LOG_INFO("[" << label << "] injected " << rim_locator_urls.size()
                     << " backup RIM locator(s)");
    }
    if (rim_locator_urls.empty() && is_fsp_responder) {
        appraisal.stage_error =
            locator_error != Error::Ok
                ? StageError{locator_error,
                             "could not build a RIM locator for FSP responder: " +
                                 locator_failure_reason,
                             ""}
                : StageError{Error::RimNotFound,
                             "no RIM locator available for FSP responder", ""};
        CorimResult cr;
        cr.error = appraisal.stage_error;
        appraisal.corims.push_back(std::move(cr));
        LOG_ERROR("[" << label << "] " << appraisal.stage_error.message);
        return appraisal;
    }

    if (chain_available) {
        std::vector<Ect> chain_ects;
        std::vector<std::size_t> chain_dti_indices;
        Error dice_err = x509_chain_to_evidence_ects(
            device_chain, /*ueid_fallback=*/nullptr, chain_ects,
            &chain_dti_indices);
        if (dice_err != Error::Ok) {
            appraisal.stage_error = {Error::EvidenceMalformed,
                                     "Cert chain -> ECT mapping failed", ""};
            LOG_ERROR("[" << label << "] " << appraisal.stage_error.message);
            return appraisal;
        }
        LOG_INFO("[" << label << "] cert chain yielded " << chain_ects.size()
                     << " ECT(s)");

        std::size_t device_cert_index = 0;
        if (find_device_cert_index(chain_dti_indices, device_chain.size(),
                                   device_cert_index) != Error::Ok) {
            LOG_WARN("[" << label << "] no device identity cert in chain; "
                         << "device cert serial unavailable");
        } else if (device_chain.get_cert_serial(
                       device_cert_index,
                       appraisal.evidence.device_cert_serial) != Error::Ok) {
            LOG_WARN("[" << label << "] could not read device cert serial");
        }
        for (auto &ect : chain_ects) {
            appraisal.chain_ect_environments.push_back(ect.getEnvironment());
            evidence_ects.push_back(std::move(ect));
        }
    }

    std::vector<Ect> reference_ects;
    std::vector<DependencyTriple> dependencies;
    // Attempt every RIM; each failure is recorded per-CoRIM (not overwritten by
    // a later success) and aborts verify() below without dropping results.
    Error rim_error = Error::Ok;
    auto record_rim_error = [&rim_error](Error err) {
        if (rim_error == Error::Ok) {
            rim_error = err;
        }
    };
    for (const auto &url : rim_locator_urls) {
        CorimResult cr;
        cr.locator = url;

        std::vector<uint8_t> rim_bytes;
        std::vector<uint8_t> coev_bytes;
        bool coev_present = false;
        std::string coev_sha256;
        std::string effective_url;
        Error fetch_err = m_corim_store.fetch_with_coev(
            url, rim_bytes, coev_bytes, coev_present, coev_sha256,
            &effective_url);
        if (fetch_err != Error::Ok) {
            LOG_ERROR("[" << label << "] RIM fetch failed: raw URL=" << url
                          << " effective URL=" << effective_url);
            cr.error = {fetch_err, "RIM fetch failed", ""};
            appraisal.corims.push_back(std::move(cr));
            record_rim_error(fetch_err);
            continue;
        }
        cr.fetched = true;
        LOG_INFO("[" << label << "] fetched RIM: raw URL=" << url
                     << " effective URL=" << effective_url << " ("
                     << rim_bytes.size() << " bytes, coev="
                     << (coev_present ? "present" : "absent") << ")");

        // Relies on url never being rewritten between the
        // rim_synthesized_locator assignment above and this comparison.
        const bool is_rim_synthesized_locator =
            !rim_synthesized_locator.empty() &&
            url == rim_synthesized_locator;

        // Fatal only for the synthesized locator, and only absent a backup
        // CoEV fallback; other locators no-op.
        if (!coev_present && is_rim_synthesized_locator &&
            !evidence_has_backup_coev) {
            LOG_ERROR("[" << label << "] RIM fetched but required CoEV is "
                         "absent (effective URL=" << effective_url << ")");
            cr.error = {Error::RimInvalidSchema, "required CoEV is absent", ""};
            appraisal.corims.push_back(std::move(cr));
            record_rim_error(Error::RimInvalidSchema);
            continue;
        }

        // When signatures are required, validate COSE_Sign1 against the
        // built-in CoRIM signing root; the signing chain's cert/OCSP claims
        // are collected. Otherwise accept the unsigned-corim payload as-is.
        CorimMap parsed;
        CorimParseOptions parse_options;
        // TODO: replace with VersionedUriMatcher instances once profile URIs
        // for fetched CoRIMs (Rubin, etc.) are defined.
        parse_options.accepted_profiles.push_back(
            std::make_shared<AnyProfileMatcher>());
        if (m_verify_rim_signature) {
            CoseSign1VerifyOptions cose_opts;
            cose_opts.root_cert_pem = m_rim_signing_root;
            cose_opts.verify_ocsp = (ocsp_client != nullptr);
            // parse_signed_corim takes the client by reference; when OCSP is
            // off, verify_ocsp is false and this stand-in is never consulted.
            NvHttpOcspClient ocsp_placeholder;
            IOcspHttpClient &ocsp_ref =
                ocsp_client ? *ocsp_client
                            : static_cast<IOcspHttpClient &>(ocsp_placeholder);
            std::vector<PerCertStatus> cert_claims;
            Error parse_err =
                parse_signed_corim(rim_bytes, cose_opts, ocsp_ref, parsed,
                                   cert_claims, parse_options);
            // Retain cert-chain claims even on failure (e.g. a revoked
            // signer), so the EAR still shows which cert was at fault.
            if (!cert_claims.empty()) {
                cr.cert_chain = std::make_unique<std::vector<PerCertStatus>>(std::move(cert_claims));
            }
            if (parse_err != Error::Ok) {
                LOG_ERROR("[" << label << "] signed CoRIM parse failed");
                cr.error = {parse_err, "signed CoRIM parse failed", ""};
                appraisal.corims.push_back(std::move(cr));
                record_rim_error(parse_err);
                continue;
            }
            cr.signature_verified = true;
        } else {
            std::vector<uint8_t> cose_payload;
            const std::vector<uint8_t>& corim_payload =
                (extract_cose_sign1_payload(rim_bytes, cose_payload) == Error::Ok)
                    ? cose_payload : rim_bytes;
            Error parse_err =
                parse_unsigned_corim(corim_payload, parsed, parse_options);
            if (parse_err != Error::Ok) {
                LOG_ERROR("[" << label << "] CoRIM parse failed");
                cr.error = {parse_err, "CoRIM parse failed", ""};
                appraisal.corims.push_back(std::move(cr));
                record_rim_error(parse_err);
                continue;
            }
        }
        cr.id = parsed.getId();
        cr.parsed = true;

        // Same asymmetry as the missing-CoEV check above: fatal only for
        // the synthesized locator, warn-and-skip otherwise.
        if (coev_present) {
            Error coev_err = Error::Ok;
            const char *coev_stage = "unknown";
            std::vector<uint8_t> coev_payload = coev_bytes;
            if (m_verify_coev_signature) {
                std::vector<PerCertStatus> coev_cert_claims;
                coev_err = verify_coev_signature(coev_bytes, ocsp_client,
                                                 coev_payload, coev_cert_claims);
                // Retain cert-chain claims even on failure (e.g. a revoked
                // signer), so the EAR still shows which cert was at fault.
                if (!coev_cert_claims.empty()) {
                    cr.coev_cert_chain = std::make_unique<std::vector<PerCertStatus>>(
                        std::move(coev_cert_claims));
                }
                if (coev_err == Error::Ok) {
                    cr.coev_signature_verified = true;
                } else {
                    coev_stage = "signature verification";
                }
            } else {
                std::vector<uint8_t> unwrapped;
                if (extract_cose_sign1_payload(coev_bytes, unwrapped) == Error::Ok) {
                    coev_payload = std::move(unwrapped);
                }
            }
            std::vector<Ect> coev_ects;
            std::unique_ptr<ProfileValue> coev_profile;
            if (coev_err == Error::Ok) {
                coev_err = convert_fetched_coev_to_ects(
                    coev_payload, verification.measurement_records.get(),
                    verification.measurement_hash_algorithm_id, coev_ects,
                    coev_profile, coev_stage);
            }
            if (!appraisal.evidence_profile && coev_profile) {
                appraisal.evidence_profile = std::move(coev_profile);
            }
            if (coev_err != Error::Ok) {
                if (is_rim_synthesized_locator) {
                    LOG_ERROR("[" << label << "] fetched CoEV " << coev_stage
                                 << " failed (effective URL=" << effective_url
                                 << ")");
                    cr.error = {fetched_coev_error(coev_err),
                               std::string("fetched CoEV ") + coev_stage + " failed", ""};
                    appraisal.corims.push_back(std::move(cr));
                    record_rim_error(fetched_coev_error(coev_err));
                    continue;
                }
                LOG_WARN("[" << label << "] fetched CoEV " << coev_stage
                             << " failed on a non-synthesized locator; "
                             "skipping its ECTs (effective URL="
                             << effective_url << ")");
            } else {
                LOG_INFO("[" << label << "] fetched CoEV yielded "
                             << coev_ects.size() << " ECT(s)");
                for (auto &ect : coev_ects) {
                    evidence_ects.push_back(std::move(ect));
                }
            }
        }
        appraisal.corims.push_back(std::move(cr));

        std::size_t ref_count_before = reference_ects.size();
        std::size_t dep_count_before = dependencies.size();
        for (const auto &tag : parsed.getCoMidTags()) {
            for (const auto &triple : tag.getReferenceTriples()) {
                reference_ects.emplace_back(triple.getEnvironment(),
                                            triple.getMeasurements());
            }
            for (const auto &dep : tag.getDependencyTriples()) {
                dependencies.push_back(dep);
            }
        }
        LOG_INFO("[" << label << "] CoRIM contributed "
                     << (reference_ects.size() - ref_count_before)
                     << " reference ECT(s) and "
                     << (dependencies.size() - dep_count_before)
                     << " dependency triple(s)");
    }
    if (rim_error != Error::Ok) {
        appraisal.stage_error = {rim_error,
                                 "one or more RIMs failed to fetch or parse", ""};
        LOG_ERROR("[" << label << "] " << appraisal.stage_error.message);
        return appraisal;
    }
    // No reference values reached appraisal: either the evidence named no RIM
    // locators, or every CoRIM parsed but carried none.
    if (reference_ects.empty()) {
        appraisal.stage_error = {Error::RimMeasurementNotFound,
                                 "no RIM reference values to appraise against", ""};
        LOG_ERROR("[" << label << "] " << appraisal.stage_error.message);
        return appraisal;
    }

    // WAR: no root env on either side — inject a synthetic default root that
    // depends on every reference env so verify() anchors and pulls them into
    // scope. Trustees must be reference envs (an evidence-only one has no
    // backing ref ECT and trips missingReferenceForDependencyEnv).
    if (find_root_environments(evidence_ects).empty() &&
        find_root_environments(reference_ects).empty()) {
        Ect root = make_default_root_ect();
        std::vector<EnvironmentMap> trustees;
        trustees.reserve(reference_ects.size());
        for (const auto &ect : reference_ects) {
            trustees.push_back(ect.getEnvironment());
        }
        dependencies.emplace_back(root.getEnvironment(), std::move(trustees));
        evidence_ects.push_back(root);
        reference_ects.push_back(std::move(root));
        LOG_INFO("[" << label << "] WAR: injected synthetic default root env "
                     << "depending on "
                     << dependencies.back().getTrustees().size()
                     << " reference env(s)");
    }

    appraisal.match = verify(reference_ects, evidence_ects, dependencies);
    for (const auto &outcome : appraisal.match.outcomes) {
        if (outcome.mismatched()) {
            LOG_TRACE("[" << label << "] CoRIM mismatch: "
                          << safe_json_dump(outcome));
        }
    }
    for (const auto &diagnostic : appraisal.match.diagnostics) {
        LOG_TRACE("[" << label << "] CoRIM diagnostic: "
                      << safe_json_dump(diagnostic));
    }
    LOG_INFO("[" << label << "] verify(): " << evidence_ects.size()
                 << " evidence ECT(s), " << reference_ects.size()
                 << " reference ECT(s), " << appraisal.match.outcomes.size()
                 << " outcome(s), " << appraisal.match.diagnostics.size()
                 << " diagnostic(s)");

    if (!appraisal.chain_ect_environments.empty()) {
        appraisal.cert_chain_dti_match.reset(new bool(cert_chain_dti_matches(
            appraisal.chain_ect_environments, appraisal.match.outcomes)));
    }

    return appraisal;
}

namespace {

// ars.digest-algos: NI registry IDs or hash names the client wants in
// ear_nvidia_inputs.digests. False = key absent, so the caller falls back.
bool requested_digest_algorithms(const std::vector<uint8_t> &settings,
                                 std::vector<HashAlgorithm> &out_algs) {
    if (settings.empty()) {
        return false;
    }
    auto root = nlohmann::json::parse(settings.begin(), settings.end(), nullptr,
                                      /*allow_exceptions=*/false);
    if (root.is_discarded() || !root.is_object()) {
        LOG_WARN("appraisal-settings is not a JSON object; ignoring");
        return false;
    }
    auto ars = root.find("ars");
    if (ars == root.end() || !ars->is_object()) {
        return false;
    }
    auto algos = ars->find("digest-algos");
    if (algos == ars->end() || !algos->is_array()) {
        return false;
    }

    std::vector<HashAlgorithm> algs;
    for (const auto &entry : *algos) {
        HashAlgorithm alg{};
        Error err = Error::BadArgument;
        if (entry.is_number_integer()) {
            // Range-check before narrowing: a value outside int32_t would wrap
            // and could land on a valid registry ID.
            const int64_t value = entry.get<int64_t>();
            if (value >= std::numeric_limits<int32_t>::min() &&
                value <= std::numeric_limits<int32_t>::max()) {
                err = hash_algorithm_from_ni_id(static_cast<int32_t>(value), alg);
            }
        } else if (entry.is_string()) {
            err = hash_algorithm_from_name(entry.get<std::string>(), alg);
        }
        if (err != Error::Ok) {
            LOG_WARN("ars.digest-algos names an unsupported algorithm: "
                     << safe_json_dump(entry));
            continue;
        }
        if (std::find(algs.begin(), algs.end(), alg) == algs.end()) {
            algs.push_back(alg);
        }
    }
    out_algs = std::move(algs);
    return true;
}

} // namespace

Error LocalCorimVerifier::verify_cmw(const uint8_t *cmw_data,
                                     std::size_t cmw_len, CmwFormat format,
                                     CorimAttestationResult &out_result,
                                     const DetachedEATOptions *ear_signing_options,
                                     std::string *out_ear_jwt,
                                     std::string *out_ear_json) const {
    out_result = CorimAttestationResult();
    if (cmw_data == nullptr) {
        LOG_ERROR("verify_cmw called with null cmw_data");
        return Error::BadArgument;
    }

    CmwCollection cmw;
    Error err = CmwCollection::parse(cmw_data, cmw_len, format, cmw);
    if (err != Error::Ok) {
        return err;
    }

    out_result.input_nonce = cmw.nonce();

    // The client's ars.digest-algos wins when present; otherwise use the
    // algorithms this verifier is configured to support.
    std::vector<HashAlgorithm> hash_algorithms = m_default_hash_algorithms;
    std::vector<HashAlgorithm> requested;
    if (requested_digest_algorithms(cmw.appraisal_settings(), requested)) {
        hash_algorithms = std::move(requested);
    }

    // Digests cover the exact bytes submitted. Stage results to a temp vector
    // so a mid-loop failure leaks no partial state.
    if (!hash_algorithms.empty()) {
        const std::vector<uint8_t> cmw_vec(cmw_data, cmw_data + cmw_len);
        std::vector<InputDigest> digests;
        digests.reserve(hash_algorithms.size());
        for (HashAlgorithm alg : hash_algorithms) {
            InputDigest digest;
            digest.alg = alg;
            Error derr = compute_digest(cmw_vec, alg, digest.val);
            if (derr != Error::Ok) {
                LOG_ERROR("Failed to compute input digest for alg: "
                          << to_algorithm_name(alg));
                return derr;
            }
            digests.push_back(std::move(digest));
        }
        out_result.input_digests = std::move(digests);
    }

    for (const auto &labelled : cmw.evidence_items()) {
        out_result.items.push_back(
            appraise_item(labelled.first, labelled.second));
    }

    if (out_ear_jwt != nullptr || out_ear_json != nullptr) {
        nlohmann::json ear_json{};
        Error map_err = map_to_ear_json(out_result, ear_json);
        if (map_err != Error::Ok) {
            return map_err;
        }

        // Matches DetachedEATOptions's default m_issuer (claims.h). Anything
        // else is an explicit caller override of the EAR's "iss" claim.
        if (ear_signing_options != nullptr &&
            !ear_signing_options->m_issuer.empty() &&
            ear_signing_options->m_issuer != kDefaultEatIssuer) {
            ear_json["iss"] = ear_signing_options->m_issuer;
        }

        if (out_ear_json != nullptr) {
            *out_ear_json = ear_json.dump();
        }

        if (out_ear_jwt != nullptr) {
            DetachedEATOptions signing_options;
            if (ear_signing_options != nullptr) {
                signing_options = *ear_signing_options;
            }
            Error sign_err = sign_ear(ear_json, signing_options, *out_ear_jwt);
            if (sign_err != Error::Ok) {
                return sign_err;
            }
        }
    }

    return Error::Ok;
}

} // namespace nvattestation
