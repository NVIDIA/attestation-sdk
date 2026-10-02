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

#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <string>
#include <chrono>
#include <functional>
#include <regex>

#include "nv_attestation/error.h"
#include "nv_attestation/cose.h"
#include "nv_attestation/spdm_indirect_map.h"  // MeasurementValues holds std::unique_ptr<SpdmIndirectMap>

namespace nvattestation {

class ByteString {
    std::vector<uint8_t> m_data;
public:
    ByteString() = default;
    ByteString(const uint8_t* data, size_t len) : m_data(data, data + len) {}
    explicit ByteString(std::vector<uint8_t> data) : m_data(std::move(data)) {}
    std::string toBase64() const;
    std::vector<uint8_t> toVector() const;
    const uint8_t* data() const { return m_data.data(); }
    size_t size() const { return m_data.size(); }
    bool empty() const { return m_data.empty(); }

    bool operator==(const ByteString& other) const {
        return m_data == other.m_data;
    }
    bool operator!=(const ByteString& other) const { return !(*this == other); }
    bool operator<(const ByteString& other) const {
        return m_data < other.m_data;
    }
};

class ClassId {
public:
    enum class Kind { kOid, kUuid, kBytes };
private:
    Kind m_kind = Kind::kBytes;
    ByteString m_value;
public:
    ClassId() = default;
    ClassId(Kind kind, ByteString value)
        : m_kind(kind), m_value(std::move(value)) {}

    Kind getKind() const { return m_kind; }
    const ByteString& getValue() const { return m_value; }

    bool operator==(const ClassId& other) const {
        return m_kind == other.m_kind && m_value == other.m_value;
    }
    bool operator!=(const ClassId& other) const { return !(*this == other); }
    bool operator<(const ClassId& other) const {
        if (m_kind != other.m_kind) {
            return static_cast<int>(m_kind) < static_cast<int>(other.m_kind);
        }
        return m_value < other.m_value;
    }
};

class InstanceId {
public:
    enum class Kind { kUeid, kUuid, kBytes };
private:
    Kind m_kind = Kind::kBytes;
    ByteString m_value;
public:
    InstanceId() = default;
    InstanceId(Kind kind, ByteString value)
        : m_kind(kind), m_value(std::move(value)) {}

    Kind getKind() const { return m_kind; }
    const ByteString& getValue() const { return m_value; }

    bool operator==(const InstanceId& other) const {
        return m_kind == other.m_kind && m_value == other.m_value;
    }
    bool operator!=(const InstanceId& other) const { return !(*this == other); }
    bool operator<(const InstanceId& other) const {
        if (m_kind != other.m_kind) {
            return static_cast<int>(m_kind) < static_cast<int>(other.m_kind);
        }
        return m_value < other.m_value;
    }
};

class GroupId {
public:
    enum class Kind { kUuid, kBytes };
private:
    Kind m_kind = Kind::kBytes;
    ByteString m_value;
public:
    GroupId() = default;
    GroupId(Kind kind, ByteString value)
        : m_kind(kind), m_value(std::move(value)) {}

    Kind getKind() const { return m_kind; }
    const ByteString& getValue() const { return m_value; }

    bool operator==(const GroupId& other) const {
        return m_kind == other.m_kind && m_value == other.m_value;
    }
    bool operator!=(const GroupId& other) const { return !(*this == other); }
    bool operator<(const GroupId& other) const {
        if (m_kind != other.m_kind) {
            return static_cast<int>(m_kind) < static_cast<int>(other.m_kind);
        }
        return m_value < other.m_value;
    }
};

class Digest {
public:
    enum class AlgKind { kInt, kString };
private:
    AlgKind m_alg_kind = AlgKind::kInt;
    int32_t m_alg_int = 0;
    std::string m_alg_str;
    ByteString m_value;
public:
    Digest() = default;
    Digest(int32_t algorithm, ByteString value)
        : m_alg_kind(AlgKind::kInt), m_alg_int(algorithm), m_value(std::move(value)) {}
    Digest(std::string algorithm, ByteString value)
        : m_alg_kind(AlgKind::kString), m_alg_str(std::move(algorithm)), m_value(std::move(value)) {}
    bool getAlgorithm(int32_t& out) const;
    bool getAlgorithm(std::string& out) const;
    ByteString getValue() const { return m_value; }

    bool sameAlgorithm(const Digest& o) const {
        if (m_alg_kind != o.m_alg_kind) { return false; }
        return m_alg_kind == AlgKind::kInt
            ? m_alg_int == o.m_alg_int
            : m_alg_str == o.m_alg_str;
    }
};

// Per-bit optional. Absent = "no claim"; present = exact boolean value.
class FlagsMap {
    std::unique_ptr<bool> m_configured;
    std::unique_ptr<bool> m_secure;
    std::unique_ptr<bool> m_recovery;
    std::unique_ptr<bool> m_debug;
    std::unique_ptr<bool> m_replay_protected;
    std::unique_ptr<bool> m_integrity_protected;
    std::unique_ptr<bool> m_runtime_meas;
    std::unique_ptr<bool> m_immutable;
    std::unique_ptr<bool> m_tcb;
    std::unique_ptr<bool> m_confidentiality_protected;

    static bool ptrEq(const std::unique_ptr<bool>& a, const std::unique_ptr<bool>& b) {
        if (!a && !b) { return true; }
        if (!a || !b) { return false; }
        return *a == *b;
    }
public:
    FlagsMap() = default;
    FlagsMap(FlagsMap&&) = default;
    FlagsMap& operator=(FlagsMap&&) = default;
    FlagsMap(const FlagsMap& o) {
        if (o.m_configured)                { setConfigured(*o.m_configured); }
        if (o.m_secure)                    { setSecure(*o.m_secure); }
        if (o.m_recovery)                  { setRecovery(*o.m_recovery); }
        if (o.m_debug)                     { setDebug(*o.m_debug); }
        if (o.m_replay_protected)          { setReplayProtected(*o.m_replay_protected); }
        if (o.m_integrity_protected)       { setIntegrityProtected(*o.m_integrity_protected); }
        if (o.m_runtime_meas)              { setRuntimeMeas(*o.m_runtime_meas); }
        if (o.m_immutable)                 { setImmutable(*o.m_immutable); }
        if (o.m_tcb)                       { setTcb(*o.m_tcb); }
        if (o.m_confidentiality_protected) { setConfidentialityProtected(*o.m_confidentiality_protected); }
    }
    FlagsMap& operator=(const FlagsMap& o) {
        if (this != &o) { FlagsMap tmp(o); *this = std::move(tmp); }
        return *this;
    }

    void setConfigured(bool v)              { m_configured.reset(new bool(v)); }
    void setSecure(bool v)                  { m_secure.reset(new bool(v)); }
    void setRecovery(bool v)                { m_recovery.reset(new bool(v)); }
    void setDebug(bool v)                   { m_debug.reset(new bool(v)); }
    void setReplayProtected(bool v)         { m_replay_protected.reset(new bool(v)); }
    void setIntegrityProtected(bool v)      { m_integrity_protected.reset(new bool(v)); }
    void setRuntimeMeas(bool v)             { m_runtime_meas.reset(new bool(v)); }
    void setImmutable(bool v)               { m_immutable.reset(new bool(v)); }
    void setTcb(bool v)                     { m_tcb.reset(new bool(v)); }
    void setConfidentialityProtected(bool v){ m_confidentiality_protected.reset(new bool(v)); }

    const bool* getConfigured() const              { return m_configured.get(); }
    const bool* getSecure() const                  { return m_secure.get(); }
    const bool* getRecovery() const                { return m_recovery.get(); }
    const bool* getDebug() const                   { return m_debug.get(); }
    const bool* getReplayProtected() const         { return m_replay_protected.get(); }
    const bool* getIntegrityProtected() const      { return m_integrity_protected.get(); }
    const bool* getRuntimeMeas() const             { return m_runtime_meas.get(); }
    const bool* getImmutable() const               { return m_immutable.get(); }
    const bool* getTcb() const                     { return m_tcb.get(); }
    const bool* getConfidentialityProtected() const{ return m_confidentiality_protected.get(); }

    bool empty() const {
        return !m_configured && !m_secure && !m_recovery && !m_debug
            && !m_replay_protected && !m_integrity_protected && !m_runtime_meas
            && !m_immutable && !m_tcb && !m_confidentiality_protected;
    }

    bool operator==(const FlagsMap& o) const {
        return ptrEq(m_configured, o.m_configured) && ptrEq(m_secure, o.m_secure)
            && ptrEq(m_recovery, o.m_recovery) && ptrEq(m_debug, o.m_debug)
            && ptrEq(m_replay_protected, o.m_replay_protected)
            && ptrEq(m_integrity_protected, o.m_integrity_protected)
            && ptrEq(m_runtime_meas, o.m_runtime_meas)
            && ptrEq(m_immutable, o.m_immutable) && ptrEq(m_tcb, o.m_tcb)
            && ptrEq(m_confidentiality_protected, o.m_confidentiality_protected);
    }
    bool operator!=(const FlagsMap& o) const { return !(*this == o); }
};

class Version {
public:
    enum class SchemeKind { kAbsent, kInt, kText, kBinary };
private:
    std::string m_value;
    SchemeKind m_scheme_kind = SchemeKind::kAbsent;
    int32_t m_scheme_int = 0;
    std::string m_scheme_text;
public:
    Version() = default;
    explicit Version(std::string value) : m_value(std::move(value)) {}
    Version(std::string value, int32_t scheme)
        : m_value(std::move(value)), m_scheme_kind(SchemeKind::kInt), m_scheme_int(scheme) {}
    static Version withTextScheme(std::string value, std::string scheme_text) {
        Version v(std::move(value));
        v.m_scheme_kind = SchemeKind::kText;
        v.m_scheme_text = std::move(scheme_text);
        return v;
    }
    // Binary version-scheme (CoRIM/CoSWID scheme 5): value holds the base64url-decoded
    // bytes; getValue() returns raw bytes for this kind.
    static Version withBinaryScheme(std::string decoded_value) {
        Version v(std::move(decoded_value));
        v.m_scheme_kind = SchemeKind::kBinary;
        v.m_scheme_int = 5;
        return v;
    }
    const std::string& getValue() const { return m_value; }
    SchemeKind getSchemeKind() const { return m_scheme_kind; }
    const int32_t* getScheme() const {
        return m_scheme_kind == SchemeKind::kInt ? &m_scheme_int : nullptr;
    }
    const std::string* getSchemeText() const {
        return m_scheme_kind == SchemeKind::kText ? &m_scheme_text : nullptr;
    }

    bool operator==(const Version& o) const {
        if (m_value != o.m_value || m_scheme_kind != o.m_scheme_kind) { return false; }
        switch (m_scheme_kind) {
            case SchemeKind::kAbsent: return true;
            case SchemeKind::kInt:    return m_scheme_int == o.m_scheme_int;
            case SchemeKind::kText:   return m_scheme_text == o.m_scheme_text;
            case SchemeKind::kBinary: return true;  // decoded bytes compared above
        }
        return false;
    }
    bool operator!=(const Version& o) const { return !(*this == o); }
};

class IntRange {
public:
    enum class Kind { kSimpleInt, kRange };
private:
    Kind m_kind = Kind::kSimpleInt;
    int32_t m_simple_value = 0;
    bool m_has_min = false;
    int32_t m_min = 0;
    bool m_has_max = false;
    int32_t m_max = 0;
public:
    IntRange() = default;
    static IntRange simpleInt(int32_t value);
    static IntRange range(bool has_min, int32_t min_val, bool has_max, int32_t max_val);
    bool isSimpleInt(int32_t& out) const;
    bool isRange(bool& has_min, int32_t& min_out, bool& has_max, int32_t& max_out) const;
};

enum class SvnKind { kExact, kMin };

struct Svn {
    SvnKind kind = SvnKind::kExact;
    uint32_t value = 0;

    Svn() = default;
    Svn(SvnKind k, uint32_t v) : kind(k), value(v) {}
};

class MeasurementValues {
    std::unique_ptr<Version> m_version;
    std::unique_ptr<FlagsMap> m_flags;
    std::unique_ptr<ByteString> m_raw_value;
    std::unique_ptr<ByteString> m_raw_value_mask;
    std::unique_ptr<std::string> m_name;
    std::unique_ptr<IntRange> m_int_range;
    std::unique_ptr<Svn> m_svn;
    std::vector<Digest> m_digests;
    // TCG DICE Concise Evidence Binding for SPDM v1.1 §7.1 — populated only by
    // the evidence parser when measurement-values-map carries spdm-indirect
    // (key 12). The reference-value (CoRIM) parser leaves this nullptr.
    std::unique_ptr<SpdmIndirectMap> m_spdm_indirect;
public:
    MeasurementValues();
    // All special members are out-of-line because m_spdm_indirect holds a
    // forward-declared type (SpdmIndirectMap); the destruction path needs the
    // complete type. Their bodies live in corim.cpp.
    MeasurementValues(MeasurementValues&& other) noexcept;
    MeasurementValues& operator=(MeasurementValues&& other) noexcept;
    MeasurementValues(
        std::unique_ptr<Version> version,
        std::unique_ptr<FlagsMap> flags,
        std::unique_ptr<ByteString> raw_value,
        std::unique_ptr<ByteString> raw_value_mask,
        std::unique_ptr<std::string> name,
        std::unique_ptr<IntRange> int_range,
        std::unique_ptr<Svn> svn,
        std::vector<Digest> digests,
        std::unique_ptr<SpdmIndirectMap> spdm_indirect = nullptr
    );
    MeasurementValues(const MeasurementValues& other);
    MeasurementValues& operator=(const MeasurementValues& other);
    ~MeasurementValues();
    const Version* getVersion() const { return m_version.get(); }
    const Svn* getSvn() const { return m_svn.get(); }
    const std::vector<Digest>& getDigests() const { return m_digests; }
    const FlagsMap* getFlags() const { return m_flags.get(); }
    const ByteString* getRawValue() const { return m_raw_value.get(); }
    const ByteString* getRawValueMask() const { return m_raw_value_mask.get(); }
    const std::string* getName() const { return m_name.get(); }
    const IntRange* getIntRange() const { return m_int_range.get(); }
    const SpdmIndirectMap* getSpdmIndirect() const { return m_spdm_indirect.get(); }
};

struct MeasurementMapKey {
    enum class Type { kString, kUint, kOid, kUuid, kAbsent };
    Type type = Type::kAbsent;
    std::string str_value;
    uint32_t uint_value = 0;

    static MeasurementMapKey ofAbsent() { return {}; }
    static MeasurementMapKey ofString(std::string value) {
        MeasurementMapKey k;
        k.type = Type::kString;
        k.str_value = std::move(value);
        return k;
    }
    static MeasurementMapKey ofUint(uint32_t value) {
        MeasurementMapKey k;
        k.type = Type::kUint;
        k.uint_value = value;
        return k;
    }
    // Caller passes the prefix-tagged display form ("oid:1.2.3.4"), matching the
    // wrapper's existing storage convention for parsed OID/UUID keys.
    static MeasurementMapKey ofOid(std::string oid_display) {
        MeasurementMapKey k;
        k.type = Type::kOid;
        k.str_value = std::move(oid_display);
        return k;
    }
    static MeasurementMapKey ofUuid(std::string uuid_display) {
        MeasurementMapKey k;
        k.type = Type::kUuid;
        k.str_value = std::move(uuid_display);
        return k;
    }

    bool isAbsent() const { return type == Type::kAbsent; }
    bool asString(std::string& out) const;
    bool asUint(uint32_t& out) const;

    /** Human-readable display. kOid/kUuid keep their existing prefix tagging. */
    std::string toDisplayString() const;

    bool operator==(const MeasurementMapKey& other) const;
    bool operator!=(const MeasurementMapKey& other) const { return !(*this == other); }
    bool operator<(const MeasurementMapKey& other) const;
};

class MeasurementMap {
    MeasurementMapKey m_key;
    MeasurementValues m_values;
public:
    MeasurementMap() = default;
    MeasurementMap(MeasurementMapKey key, MeasurementValues values)
        : m_key(std::move(key)), m_values(std::move(values)) {}
    MeasurementMap(MeasurementMap&&) = default;
    MeasurementMap& operator=(MeasurementMap&&) = default;
    MeasurementMap(const MeasurementMap&) = default;
    MeasurementMap& operator=(const MeasurementMap&) = default;
    MeasurementMapKey getKey() const { return m_key; }
    const MeasurementValues& getValues() const { return m_values; }
};

class ClassMap {
    std::unique_ptr<ClassId> m_class_id;
    std::unique_ptr<std::string> m_vendor;
    std::unique_ptr<std::string> m_model;
    std::unique_ptr<uint32_t> m_layer;
    std::unique_ptr<uint32_t> m_index;
public:
    ClassMap() = default;
    ClassMap(std::unique_ptr<ClassId> class_id,
             std::unique_ptr<std::string> vendor,
             std::unique_ptr<std::string> model,
             std::unique_ptr<uint32_t> layer,
             std::unique_ptr<uint32_t> index);
    ClassMap(ClassMap&&) = default;
    ClassMap& operator=(ClassMap&&) = default;
    ClassMap(const ClassMap& other)
        : m_class_id(other.m_class_id ? std::unique_ptr<ClassId>(new ClassId(*other.m_class_id)) : nullptr),
          m_vendor(other.m_vendor ? std::unique_ptr<std::string>(new std::string(*other.m_vendor)) : nullptr),
          m_model(other.m_model ? std::unique_ptr<std::string>(new std::string(*other.m_model)) : nullptr),
          m_layer(other.m_layer ? std::unique_ptr<uint32_t>(new uint32_t(*other.m_layer)) : nullptr),
          m_index(other.m_index ? std::unique_ptr<uint32_t>(new uint32_t(*other.m_index)) : nullptr) {}
    ClassMap& operator=(const ClassMap& other) {
        if (this != &other) { ClassMap tmp(other); *this = std::move(tmp); }
        return *this;
    }
    const ClassId* getClassId() const { return m_class_id.get(); }
    const std::string* getVendor() const { return m_vendor.get(); }
    const std::string* getModel() const { return m_model.get(); }
    const uint32_t* getLayer() const { return m_layer.get(); }
    const uint32_t* getIndex() const { return m_index.get(); }

    bool operator==(const ClassMap& other) const;
    bool operator!=(const ClassMap& other) const { return !(*this == other); }
    bool operator<(const ClassMap& other) const;
    bool matches(const ClassMap& evidence) const;
};

class EnvironmentMap {
    std::unique_ptr<ClassMap> m_class;
    std::unique_ptr<InstanceId> m_instance;
    std::unique_ptr<GroupId> m_group;
public:
    EnvironmentMap() = default;
    EnvironmentMap(std::unique_ptr<ClassMap> cls,
                   std::unique_ptr<InstanceId> instance,
                   std::unique_ptr<GroupId> group)
        : m_class(std::move(cls)), m_instance(std::move(instance)), m_group(std::move(group)) {}
    EnvironmentMap(EnvironmentMap&&) = default;
    EnvironmentMap& operator=(EnvironmentMap&&) = default;
    EnvironmentMap(const EnvironmentMap& other)
        : m_class(other.m_class ? std::unique_ptr<ClassMap>(new ClassMap(*other.m_class)) : nullptr),
          m_instance(other.m_instance ? std::unique_ptr<InstanceId>(new InstanceId(*other.m_instance)) : nullptr),
          m_group(other.m_group ? std::unique_ptr<GroupId>(new GroupId(*other.m_group)) : nullptr) {}
    EnvironmentMap& operator=(const EnvironmentMap& other) {
        if (this != &other) { EnvironmentMap tmp(other); *this = std::move(tmp); }
        return *this;
    }
    const ClassMap* getClass() const { return m_class.get(); }
    const InstanceId* getInstance() const { return m_instance.get(); }
    const GroupId* getGroup() const { return m_group.get(); }

    /**
     * Whether this environment-map "matches" the other.
     * "this" should be the reference-value or condition environment-map,
     * and "other" should be the evidence environment-map.
     */
    bool matches(const EnvironmentMap& other) const;

    bool operator==(const EnvironmentMap& other) const;
    bool operator!=(const EnvironmentMap& other) const { return !(*this == other); }
    bool operator<(const EnvironmentMap& other) const;
};

class ReferenceTriple {
    EnvironmentMap m_env;
    std::vector<MeasurementMap> m_measurements;
public:
    ReferenceTriple() = default;
    ReferenceTriple(EnvironmentMap env, std::vector<MeasurementMap> measurements)
        : m_env(std::move(env)), m_measurements(std::move(measurements)) {}
    ReferenceTriple(ReferenceTriple&&) = default;
    ReferenceTriple& operator=(ReferenceTriple&&) = default;
    const EnvironmentMap& getEnvironment() const { return m_env; }
    const std::vector<MeasurementMap>& getMeasurements() const { return m_measurements; }
};

class DependencyTriple {
    EnvironmentMap m_domain_id;
    std::vector<EnvironmentMap> m_trustees;
public:
    DependencyTriple() = default;
    DependencyTriple(EnvironmentMap domain_id, std::vector<EnvironmentMap> trustees)
        : m_domain_id(std::move(domain_id)), m_trustees(std::move(trustees)) {}
    DependencyTriple(DependencyTriple&&) = default;
    DependencyTriple(const DependencyTriple&) = default;
    DependencyTriple& operator=(const DependencyTriple&) = default;
    DependencyTriple& operator=(DependencyTriple&&) = default;
    const EnvironmentMap& getDomainId() const { return m_domain_id; }
    const std::vector<EnvironmentMap>& getTrustees() const { return m_trustees; }
};

enum class EntityRole {
    TagCreator = 0,
    Creator = 1,
    Maintainer = 2
};

class Entity {
    std::string m_name;
    std::unique_ptr<std::string> m_reg_id;
    std::vector<EntityRole> m_roles;
public:
    Entity() = default;
    Entity(std::string name, std::unique_ptr<std::string> reg_id, std::vector<EntityRole> roles)
        : m_name(std::move(name)), m_reg_id(std::move(reg_id)), m_roles(std::move(roles)) {}
    Entity(Entity&&) = default;
    Entity& operator=(Entity&&) = default;
    const std::string& getName() const { return m_name; }
    const std::string* getRegId() const { return m_reg_id.get(); }
    const std::vector<EntityRole>& getRoles() const { return m_roles; }
};

enum class CorimRole {
    ManifestCreator = 1,
    ManifestSigner = 2
};

class CorimEntity {
    std::string m_name;
    std::unique_ptr<std::string> m_reg_id;
    std::vector<CorimRole> m_roles;
public:
    CorimEntity() = default;
    CorimEntity(std::string name, std::unique_ptr<std::string> reg_id, std::vector<CorimRole> roles)
        : m_name(std::move(name)), m_reg_id(std::move(reg_id)), m_roles(std::move(roles)) {}
    CorimEntity(CorimEntity&&) = default;
    CorimEntity& operator=(CorimEntity&&) = default;
    const std::string& getName() const { return m_name; }
    const std::string* getRegId() const { return m_reg_id.get(); }
    const std::vector<CorimRole>& getRoles() const { return m_roles; }
};

class ValidityMap {
    bool m_has_not_before = false;
    std::chrono::system_clock::time_point m_not_before;
    bool m_has_not_after = false;
    std::chrono::system_clock::time_point m_not_after;
public:
    ValidityMap() = default;
    explicit ValidityMap(std::chrono::system_clock::time_point not_after)
        : m_has_not_after(true), m_not_after(not_after) {}
    ValidityMap(std::chrono::system_clock::time_point not_before,
                std::chrono::system_clock::time_point not_after)
        : m_has_not_before(true), m_not_before(not_before)
        , m_has_not_after(true), m_not_after(not_after) {}
    bool getNotBefore(std::chrono::system_clock::time_point& out) const;
    bool getNotAfter(std::chrono::system_clock::time_point& out) const;
};

class ConciseMidTag {
    std::string m_tag_id;
    std::unique_ptr<std::string> m_language;
    std::vector<Entity> m_entities;
    std::vector<ReferenceTriple> m_ref_triples;
    std::vector<DependencyTriple> m_dep_triples;
public:
    ConciseMidTag() = default;
    ConciseMidTag(std::string tag_id,
                  std::unique_ptr<std::string> language,
                  std::vector<Entity> entities,
                  std::vector<ReferenceTriple> ref_triples,
                  std::vector<DependencyTriple> dep_triples);
    ConciseMidTag(ConciseMidTag&&) = default;
    ConciseMidTag& operator=(ConciseMidTag&&) = default;
    std::string getTagId() const { return m_tag_id; }
    const std::string* getLanguage() const { return m_language.get(); }
    const std::vector<Entity>& getEntities() const { return m_entities; }
    const std::vector<ReferenceTriple>& getReferenceTriples() const { return m_ref_triples; }
    const std::vector<DependencyTriple>& getDependencyTriples() const { return m_dep_triples; }
};

// CDDL: profile-type-choice = uri / tagged-oid-type / text
enum class ProfileKind { Uri, Oid, Text };

struct ProfileValue {
    ProfileKind kind;
    // For Oid this is the bare dotted body (no "oid:" prefix). For Uri/Text
    // it is the literal text bytes from CBOR.
    std::string value;
};

// JSON string form used when a profile-type-choice is represented as a claim.
std::string profile_value_to_string(const ProfileValue& profile);

class CorimMap {
    std::string m_id;
    std::unique_ptr<ProfileValue> m_profile;
    std::unique_ptr<ValidityMap> m_rim_validity;
    std::vector<ConciseMidTag> m_tags;
    std::vector<CorimEntity> m_entities;
public:
    CorimMap() = default;
    CorimMap(std::string id,
             std::unique_ptr<ProfileValue> profile,
             std::unique_ptr<ValidityMap> rim_validity,
             std::vector<ConciseMidTag> tags,
             std::vector<CorimEntity> entities);
    ~CorimMap() = default;

    CorimMap(const CorimMap&) = delete;
    CorimMap& operator=(const CorimMap&) = delete;
    CorimMap(CorimMap&&) = default;
    CorimMap& operator=(CorimMap&&) = default;

    std::string getId() const { return m_id; }
    const std::vector<ConciseMidTag>& getCoMidTags() const { return m_tags; }
    const ProfileValue* getProfile() const { return m_profile.get(); }
    const std::vector<CorimEntity>& getEntities() const { return m_entities; }
    const ValidityMap* getRimValidity() const { return m_rim_validity.get(); }
};

// Each concrete matcher is bound to a single ProfileKind at construction so
// the original CDDL variant cannot be confused with another at match time.
// OID matchers additionally validate the dotted-body shape at construction.
class ProfileMatcher {
public:
    virtual ~ProfileMatcher() = default;
    virtual bool matches(const ProfileValue& parsed) const = 0;
};

class ExactOidMatcher final : public ProfileMatcher {
    std::string m_oid;
public:
    explicit ExactOidMatcher(std::string dotted_oid);
    bool matches(const ProfileValue& got) const override;
};

class OidSubtreeMatcher final : public ProfileMatcher {
    std::string m_base;
public:
    explicit OidSubtreeMatcher(std::string dotted_oid);
    bool matches(const ProfileValue& got) const override;
};

class ExactUriMatcher final : public ProfileMatcher {
    std::string m_uri;
public:
    explicit ExactUriMatcher(std::string uri) : m_uri(std::move(uri)) {}
    bool matches(const ProfileValue& got) const override;
};

class ExactTextMatcher final : public ProfileMatcher {
    std::string m_text;
public:
    explicit ExactTextMatcher(std::string text) : m_text(std::move(text)) {}
    bool matches(const ProfileValue& got) const override;
};

// Matches URI/text profiles against a pattern where '*' is a wildcard for one
// or more decimal digits. Supports both terminal-path-segment versioning
// ("tag:nvidia.com,2026:ear/profiles/.../1.*.*") and fragment-style versioning
// ("tag:arm.com,2025:psa#1.*.*"). A pattern without '*' matches only that exact string.
class VersionedUriMatcher final : public ProfileMatcher {
    std::regex m_re;
public:
    explicit VersionedUriMatcher(std::string pattern);
    bool matches(const ProfileValue& got) const override;
};

/**
 * @brief Options that customize CoRIM parsing.
 *
 * accepted_profiles is a list of profile matchers the parser will accept.
 * Empty (the default) rejects any present profile, since no CoRIM profiles
 * are defined as supported by this SDK.
 */
struct CorimParseOptions {
    std::vector<std::shared_ptr<const ProfileMatcher>> accepted_profiles;
};

/**
 * @brief Parses and verifies a signed CoRIM (COSE_Sign1 with CoRIM payload).
 *
 * This function:
 * 1. Verifies the COSE_Sign1 signature and certificate chain
 * 2. Extracts and parses the tagged unsigned CoRIM map (#6.501) from the payload
 *
 * @param corim_bytes The raw CBOR-encoded signed CoRIM bytes
 * @param options COSE verification options including OCSP settings and trust anchor
 * @param ocsp_client The OCSP client for certificate revocation checking
 * @param out_corim Output parameter for the parsed CoRIM structure
 * @param out_cert_claims Output parameter for certificate chain verification claims
 * @param parse_options CoRIM-level parser options (e.g. accepted profile allow-list)
 * @return Error::Ok on success, or an appropriate error code on failure
 */
Error parse_signed_corim(
    const std::vector<uint8_t>& corim_bytes,
    const CoseSign1VerifyOptions& options,
    IOcspHttpClient& ocsp_client,
    CorimMap& out_corim,
    std::vector<PerCertStatus>& out_cert_claims,
    const CorimParseOptions& parse_options = {}
);

/**
 * @brief Parses an unsigned CoRIM map from CBOR bytes.
 *
 * Parses a tagged unsigned CoRIM map (#6.501) without signature verification.
 * Use this for pre-verified CoRIMs or testing scenarios.
 *
 * @param corim_bytes The raw CBOR-encoded tagged unsigned CoRIM bytes
 * @param out_corim Output parameter for the parsed CoRIM structure
 * @param parse_options CoRIM-level parser options (e.g. accepted profile allow-list)
 * @return Error::Ok on success, or an appropriate error code on failure
 */
Error parse_unsigned_corim(
    const std::vector<uint8_t>& corim_bytes,
    CorimMap& out_corim,
    const CorimParseOptions& parse_options = {}
);

/**
 * @brief Parses a standalone CoMID from CBOR bytes.
 *
 * Accepts the inner concise-mid-tag map directly (i.e. the payload of the
 * #6.506 tag, NOT the tagged form). Callers holding `#6.506(bstr .cbor ...)`
 * bytes must strip the tag wrapper before invoking this function.
 *
 * Note: this is asymmetric with parse_unsigned_corim, which accepts its
 * tagged form (#6.501) directly.
 *
 * @param comid_inner_bytes The raw CBOR-encoded inner concise-mid-tag map bytes
 * @param out_tag Output parameter for the parsed ConciseMidTag structure
 * @return Error::Ok on success, or an appropriate error code on failure
 */
Error parse_comid(
    const std::vector<uint8_t>& comid_inner_bytes,
    ConciseMidTag& out_tag
);

void to_json(nlohmann::json& json_out, const ByteString& byte_str);
void to_json(nlohmann::json& json_out, const Digest& digest);
void to_json(nlohmann::json& json_out, const FlagsMap& flags);
void to_json(nlohmann::json& json_out, const Version& ver);
void to_json(nlohmann::json& json_out, const IntRange& range);
void to_json(nlohmann::json& json_out, const MeasurementValues& mval);
void to_json(nlohmann::json& json_out, const MeasurementMapKey& key);
void to_json(nlohmann::json& json_out, const MeasurementMap& meas);
void to_json(nlohmann::json& json_out, const ClassMap& cls);
void to_json(nlohmann::json& json_out, const EnvironmentMap& env);
void to_json(nlohmann::json& json_out, const ReferenceTriple& ref);
void to_json(nlohmann::json& json_out, const DependencyTriple& dep);
void to_json(nlohmann::json& json_out, const EntityRole& role);
void to_json(nlohmann::json& json_out, const Entity& entity);
void to_json(nlohmann::json& json_out, const CorimRole& role);
void to_json(nlohmann::json& json_out, const CorimEntity& entity);
void to_json(nlohmann::json& json_out, const ValidityMap& validity);
void to_json(nlohmann::json& json_out, const ConciseMidTag& tag);
void to_json(nlohmann::json& json_out, const CorimMap& corim);

} // namespace nvattestation

namespace std {
template <>
struct hash<nvattestation::EnvironmentMap> {
    size_t operator()(const nvattestation::EnvironmentMap& env) const noexcept;
};
} // namespace std
