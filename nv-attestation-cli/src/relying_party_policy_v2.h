/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <iosfwd>
#include <string>

namespace nvattest {

// Returns nullptr for unknown names; register new policies in relying_party_policy_v2.cpp.
const char* builtin_relying_party_policy_v2(const std::string& name);
void print_builtin_relying_party_policy_v2_names(std::ostream& output);

enum class RelyingPartyPolicyV2SelectorKind {
    kMissing,
    kFile,
    kBuiltin,
    kUnknownBuiltin,
};

struct RelyingPartyPolicyV2Selector {
    RelyingPartyPolicyV2SelectorKind kind;
    const char* builtin_source; // Non-null only for kBuiltin.
};

RelyingPartyPolicyV2Selector resolve_relying_party_policy_v2_selector(
    const std::string& selector);

} // namespace nvattest
