/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "relying_party_policy_v2.h"
#include <ostream>

namespace nvattest {
namespace {
constexpr char kBuiltinSelectorPrefix[] = "builtin:";

constexpr char kPolicyHeader[] = R"rego(package policy

import future.keywords.every
import future.keywords.in

default nv_match := false

nv_match {
    startswith(input.eat_profile, "tag:nvidia.com,2026:ear/profiles/composite/generic/pre-1.")
    input.ear_status == "affirming"
    count(input.submods) > 0
    every submod in input.submods {
        validate_submod_by_profile(submod)
    }
}

)rego";

constexpr char kPolicyRules[] = R"rego(
validate_submod_by_profile(submod) {
    # GPU 1.x claims
    startswith(submod.eat_profile, "tag:nvidia.com,2026-05:ear/profiles/gpu/1.")
    submod.ear_status == "affirming"
    submod.ear_nvidia_purpose in gpu_purposes
    submod.ear_verifier_claims.ear_nvidia_evidence.nonce_match == true
}

)rego";

struct BuiltinPolicy {
    const char* name;
    std::string source;
};

const auto& builtin_policies() {
    static const BuiltinPolicy policies[] = {
        {"cc-bounce-buffer",
         std::string(kPolicyHeader) + "gpu_purposes := {\"CC SPT\", \"CC MPT\"}\n" + kPolicyRules},
        {"cc-tdisp",
         std::string(kPolicyHeader) + "gpu_purposes := {\"TDISP\"}\n" + kPolicyRules},
    };
    return policies;
}

const char* find_builtin_relying_party_policy_v2(const std::string& name,
                                                  std::string::size_type offset = 0) {
    for (const auto& policy : builtin_policies()) {
        if (name.compare(offset, name.size() - offset, policy.name) == 0)
            return policy.source.c_str();
    }
    return nullptr;
}

} // namespace

const char* builtin_relying_party_policy_v2(const std::string& name) {
    return find_builtin_relying_party_policy_v2(name);
}
void print_builtin_relying_party_policy_v2_names(std::ostream& output) {
    for (const auto& policy : builtin_policies())
        output << policy.name << '\n';
}

RelyingPartyPolicyV2Selector resolve_relying_party_policy_v2_selector(
    const std::string& selector) {
    if (selector.empty()) return {RelyingPartyPolicyV2SelectorKind::kMissing, nullptr};

    constexpr auto prefix_length = sizeof(kBuiltinSelectorPrefix) - 1;
    if (selector.compare(0, prefix_length, kBuiltinSelectorPrefix) != 0)
        return {RelyingPartyPolicyV2SelectorKind::kFile, nullptr};

    const char* source = find_builtin_relying_party_policy_v2(selector, prefix_length);
    return source == nullptr
        ? RelyingPartyPolicyV2Selector{RelyingPartyPolicyV2SelectorKind::kUnknownBuiltin, nullptr}
        : RelyingPartyPolicyV2Selector{RelyingPartyPolicyV2SelectorKind::kBuiltin, source};
}
} // namespace nvattest
