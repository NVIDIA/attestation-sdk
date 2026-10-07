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
#pragma once

#include <stdexcept>
#include <string>
#include <cstdint>
#include <cstddef>

#include "corim_decode_types.h"
#include "nv_attestation/corim.h"
#include "nv_attestation/corim_evidence/coev.h"  // CorimLocatorMap

namespace nvattestation {

// Selects strict (CoRIM reference-value parsing) vs permissive (CoEV evidence
// parsing) behaviour in helpers that diverge on unsupported fields. Strict
// throws UnsupportedCorimFeatureException; Permissive emits a LOG_WARN and
// skips the field.
enum class Strictness { Strict, Permissive };

// Thrown by the helpers below in Strict mode when an unsupported feature is
// encountered. Callers convert it into Error::BadArgument at the parser
// boundary.
class UnsupportedCorimFeatureException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// zcbor struct -> owned C++ wrapper conversions. Defined in src/corim.cpp.
// Shared between the CoRIM parser (Strict) and the CoEV evidence parser
// (Permissive). All helpers are pure with respect to the parsed zcbor struct
// pointer.
std::string format_uuid(const uint8_t* data, size_t len);
std::string oid_dotted_body(const uint8_t* data, size_t len);
std::string oid_to_string(const uint8_t* data, size_t len);

// Arc-aligned prefix test on a dotted OID body: true iff `oid` equals `prefix`
// or extends it past a dot boundary (so "1.2.3" prefixes "1.2.3.4" but not
// "1.2.34"). Both arguments are bare dotted bodies (no "oid:" tag).
bool oid_has_arc_prefix(const std::string& oid, const std::string& prefix);
// True iff the penultimate (second-to-last) arc of the dotted OID body equals
// `arc`.
bool oid_penultimate_arc_equals(const std::string& oid, const std::string& arc);

Digest make_digest(const digest* ptr);
FlagsMap make_flags_map(const flags_map* ptr);
Version make_version(const version_map* ptr);
IntRange make_int_range(const int_range_type_choice* ptr);

ClassMap make_class_map(const class_map* ptr);
InstanceId make_instance_id(const instance_id_type_choice& id);
GroupId make_group_id(const group_id_type_choice& id);
EnvironmentMap make_environment_map(const environment_map* ptr);

MeasurementMapKey make_measurement_map_key(const measurement_map* ptr);
MeasurementValues make_measurement_values(const measurement_values_map* ptr, Strictness strict);
MeasurementMap make_measurement_map(const measurement_map* ptr, Strictness strict);

ProfileValue make_profile(const profile_type_choice* ptr);

// --- Shadowed-member detection -------------------------------------------
//
// zcbor wraps every optional map member in zcbor_present_decode(), which
// backtracks and reports the member as absent when its value does not match
// the schema. The trailing extension entry (`* int => any`, or
// `* extension-key => any` on CoRIM maps) then consumes the key/value pair, so
// a member that was sent but malformed decodes exactly like one that was never
// sent at all — both leave *_present false. Recover the distinction by looking
// for a key our CDDL defines among the extension entries.
//
// Only optional members can be shadowed. A mandatory one is decoded with an
// expect rather than a present_decode, so a malformed value fails the whole map
// decode instead of backtracking.

// A key defined by our CDDL, paired with its spec name for diagnostics.
struct SchemaKey {
    int32_t key;
    const char* name;
};

// Takes the table by reference so its length comes from the type, keeping the
// count and the data impossible to get out of step.
template <size_t N>
const SchemaKey* find_schema_key(int32_t key, const SchemaKey (&schema)[N]) {
    for (size_t i = 0; i < N; ++i) {
        if (schema[i].key == key) {
            return &schema[i];
        }
    }
    return nullptr;
}

// zcbor names the extension-array field after its enclosing map, so reading the
// key back needs one accessor per map type. Overloads rather than a callback:
// the compiler picks by entry type, and each body is the field name it reads.
// Returns false when the entry carries no integer key to compare.
inline bool intany_key(const ev_triples_map_intany_r& entry, int32_t& out_key) {
    out_key = entry.ev_triples_map_intany_key;
    return true;
}

inline bool intany_key(const spdm_toc_map_intany_r& entry, int32_t& out_key) {
    out_key = entry.spdm_toc_map_intany_key;
    return true;
}

inline bool intany_key(const concise_evidence_map_intany_r& entry, int32_t& out_key) {
    out_key = entry.concise_evidence_map_intany_key;
    return true;
}

inline bool intany_key(const eat_claims_map_intany_r& entry, int32_t& out_key) {
    out_key = entry.eat_claims_map_intany_key;
    return true;
}

inline bool intany_key(const spdm_indirect_map_intany_r& entry, int32_t& out_key) {
    out_key = entry.spdm_indirect_map_intany_key;
    return true;
}

// CoRIM maps key their extension entries `int / tstr`. Only the int form can
// collide with a schema key; a text key is always a genuine extension.
inline bool intany_key(const corim_map_extension_key_r& entry, int32_t& out_key) {
    const extension_key& key = entry.corim_map_extension_key_key;
    if (key.extension_key_choice != extension_key::extension_key_int_c) {
        return false;
    }
    out_key = key.extension_key_int;
    return true;
}


// Defined in src/corim.cpp to keep the logging macros out of this header.
void log_shadowed_key(const char* dialect, const char* map_name,
                      const SchemaKey& culprit);

// Any schema key found in the extension array is a member whose value failed
// validation. `dialect` names the artefact for the log line ("CoRIM" / "CoEV").
// Returns true if any entry was ours.
template <typename EntryT, size_t N>
bool report_shadowed_keys(const char* dialect, const char* map_name,
                          const EntryT* entries, size_t count,
                          const SchemaKey (&schema)[N]) {
    bool found = false;
    for (size_t i = 0; i < count; ++i) {
        int32_t key = 0;
        if (!intany_key(entries[i], key)) {
            continue;  // text-keyed entry: never one of ours
        }
        const SchemaKey* culprit = find_schema_key(key, schema);
        if (culprit == nullptr) {
            continue;  // a genuinely unknown extension key
        }
        log_shadowed_key(dialect, map_name, *culprit);
        found = true;
    }
    return found;
}

// corim-locator-map -> CorimLocatorMap (corim-href URI single/list + optional
// corim-thumbprint). Defined in src/corim_evidence/coev.cpp; shared by the
// CoEV and EAT parsers.
Error make_corim_locator(const corim_locator_map* loc, CorimLocatorMap& out_locator);

}  // namespace nvattestation
