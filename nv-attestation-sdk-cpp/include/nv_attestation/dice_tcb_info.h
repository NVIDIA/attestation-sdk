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

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "nv_attestation/error.h"

namespace nvattestation {

// TCG DICE OID constants (declared extern to avoid per-TU copies; defined in dice_tcb_info.cpp)
extern const std::string OID_TCG_DICE_TCB_INFO;        // "2.23.133.5.4.1"
extern const std::string OID_TCG_DICE_TCB_INFO_ALIAS;  // "2.23.133.5.4.1.1"
extern const std::string OID_TCG_DICE_MULTI_TCB_INFO;  // "2.23.133.5.4.5"
extern const std::string OID_TCG_DICE_UEID;            // "2.23.133.5.4.4"

/**
 * @brief Extract the UEID octets from a tcg-dice-Ueid (OID 2.23.133.5.4.4)
 *        extension on `x509_cert` (const X509* as void*).
 *
 * Extension content is `SEQUENCE { ueid OCTET STRING }`; this function returns
 * just the inner OCTET STRING bytes. When `silent`, "extension absent" demotes
 * to DEBUG so chain probes don't spam ERROR.
 */
Error parse_dice_ueid_from_x509_extension(const void* x509_cert,
                                          std::vector<uint8_t>& out,
                                          bool silent = false);

/**
 * @brief Firmware Identifier from a DiceTcbInfo extension.
 *
 * Each FWID contains a hash algorithm OID and the digest bytes.
 * Per TCG DICE Attestation Architecture v1.2, a FWID is:
 *   SEQUENCE { hashAlg OBJECT IDENTIFIER, digest OCTET STRING }
 */
class FWID {
public:
    FWID() = default;
    FWID(const std::string& hash_alg_oid, const std::vector<uint8_t>& digest)
        : m_hash_alg_oid(hash_alg_oid), m_digest(digest) {}

    const std::string& hash_alg_oid() const { return m_hash_alg_oid; }
    const std::vector<uint8_t>& digest() const { return m_digest; }

    bool operator==(const FWID& other) const {
        return m_hash_alg_oid == other.m_hash_alg_oid && m_digest == other.m_digest;
    }
    bool operator!=(const FWID& other) const { return !(*this == other); }

    friend void to_json(nlohmann::json& js, const FWID& fwid);
    friend void from_json(const nlohmann::json& js, FWID& fwid);

private:
    std::string m_hash_alg_oid;
    std::vector<uint8_t> m_digest;
};

/**
 * @brief A single integrity register entry from the integrityRegisters field.
 *
 * IntegrityRegister ::= SEQUENCE {
 *   registerName    [0] IMPLICIT IA5String OPTIONAL,
 *   registerNum     [1] IMPLICIT INTEGER OPTIONAL,
 *   registerDigests [2] IMPLICIT FWIDLIST
 * }
 */
class IntegrityRegister {
public:
    IntegrityRegister() = default;
    IntegrityRegister(const IntegrityRegister& other);
    IntegrityRegister& operator=(const IntegrityRegister& other);
    IntegrityRegister(IntegrityRegister&&) = default;
    IntegrityRegister& operator=(IntegrityRegister&&) = default;

    bool has_register_name() const { return m_register_name != nullptr; }
    bool has_register_num() const { return m_register_num != nullptr; }

    const std::string& register_name() const { return *m_register_name; }
    int64_t register_num() const { return *m_register_num; }
    const std::vector<FWID>& register_digests() const { return m_register_digests; }

    void set_register_name(const std::string& v) { m_register_name = std::make_unique<std::string>(v); }
    void set_register_num(int64_t v) { m_register_num = std::make_unique<int64_t>(v); }
    void set_register_digests(const std::vector<FWID>& v) { m_register_digests = v; }

    bool operator==(const IntegrityRegister& other) const;
    bool operator!=(const IntegrityRegister& other) const { return !(*this == other); }

    friend void to_json(nlohmann::json& js, const IntegrityRegister& ir);
    friend void from_json(const nlohmann::json& js, IntegrityRegister& ir);

private:
    std::unique_ptr<std::string> m_register_name;
    std::unique_ptr<int64_t> m_register_num;
    std::vector<FWID> m_register_digests;
};

/**
 * @brief Parsed TCG-DICE-FWID.CompositeDeviceID (OID 2.23.133.5.4.1, legacy format).
 *
 * This is the original DICE extension structure used by early devices (Hopper/GH100, BF3).
 * OID 2.23.133.5.4.1 was later reused for DiceTcbInfo, creating an ambiguity.
 *
 * CompositeDeviceID ::= SEQUENCE {
 *   version               INTEGER,
 *   subjectPublicKeyInfo  SEQUENCE { ... },
 *   fwid                  FWID
 * }
 *
 * No OpenSSL types appear in this header; DER parsing uses OpenSSL only in the .cpp.
 */
class CompositeDeviceId {
public:
    CompositeDeviceId() : m_version(0) {}

    static Error parse_from_der(const std::vector<uint8_t>& der, CompositeDeviceId& out);
    static Error parse_from_x509_extension(const void* x509_cert, CompositeDeviceId& out);

    int64_t version() const { return m_version; }
    const std::vector<uint8_t>& subject_public_key_info() const { return m_subject_public_key_info; }
    const FWID& fwid() const { return m_fwid; }

    void set_version(int64_t v) { m_version = v; }
    void set_subject_public_key_info(const std::vector<uint8_t>& v) { m_subject_public_key_info = v; }
    void set_fwid(const FWID& v) { m_fwid = v; }

    bool operator==(const CompositeDeviceId& other) const {
        return m_version == other.m_version &&
               m_subject_public_key_info == other.m_subject_public_key_info &&
               m_fwid == other.m_fwid;
    }
    bool operator!=(const CompositeDeviceId& other) const { return !(*this == other); }

    friend void to_json(nlohmann::json& js, const CompositeDeviceId& cdi);
    friend void from_json(const nlohmann::json& js, CompositeDeviceId& cdi);

private:
    int64_t m_version;
    std::vector<uint8_t> m_subject_public_key_info;
    FWID m_fwid;
};

/**
 * @brief Parsed DiceTcbInfo extension from TCG DICE Attestation Architecture v1.2 Appendix A.
 *
 * DiceTcbInfo ::= SEQUENCE {
 *   vendor     [0] IMPLICIT UTF8String OPTIONAL,
 *   model      [1] IMPLICIT UTF8String OPTIONAL,
 *   version    [2] IMPLICIT UTF8String OPTIONAL,
 *   svn        [3] IMPLICIT INTEGER OPTIONAL,
 *   layer      [4] IMPLICIT INTEGER OPTIONAL,
 *   index      [5] IMPLICIT INTEGER OPTIONAL,
 *   fwids      [6] IMPLICIT FWIDLIST OPTIONAL,
 *   flags      [7] IMPLICIT OperationalFlags OPTIONAL,
 *   vendorInfo [8] IMPLICIT OCTET STRING OPTIONAL,
 *   type       [9] IMPLICIT OCTET STRING OPTIONAL,
 *   flagsMask  [10] IMPLICIT OperationalFlagsMask OPTIONAL,
 *   integrityRegisters [11] IMPLICIT IrList OPTIONAL
 * }
 *
 * NOTE: The v1.2 spec body text (section 6.1.1) omits flagsMask and shows
 * integrityRegisters at [10]. The Appendix A ASN.1 module (normative for
 * encoding) has flagsMask at [10] and integrityRegisters at [11]. This
 * implementation follows Appendix A.
 *
 * No OpenSSL types appear in this header; DER parsing uses OpenSSL only in the .cpp.
 */
class DiceTcbInfo {
public:
    DiceTcbInfo() = default;
    DiceTcbInfo(const DiceTcbInfo& other);
    DiceTcbInfo& operator=(const DiceTcbInfo& other);
    DiceTcbInfo(DiceTcbInfo&&) = default;
    DiceTcbInfo& operator=(DiceTcbInfo&&) = default;

    // Factory: parse from raw DER bytes
    static Error parse_from_der(const std::vector<uint8_t>& der, DiceTcbInfo& out, bool silent = false);

    // Factory: parse from X.509 certificate extension by OID.
    // x509_cert is `const X509*` but declared as `const void*` to avoid OpenSSL includes.
    // When `silent`, "extension absent" demotes to DEBUG so chain probes don't spam ERROR.
    static Error parse_from_x509_extension(const void* x509_cert, const std::string& oid, DiceTcbInfo& out,
                                           bool silent = false);

    // Backward-compat helper: returns the digest of the first FWID, or error if none
    Error get_first_fwid_digest(std::vector<uint8_t>& out) const;

    // Accessors
    bool has_vendor() const { return m_vendor != nullptr; }
    bool has_model() const { return m_model != nullptr; }
    bool has_version() const { return m_version != nullptr; }
    bool has_svn() const { return m_svn != nullptr; }
    bool has_layer() const { return m_layer != nullptr; }
    bool has_index() const { return m_index != nullptr; }
    bool has_fwids() const { return !m_fwids.empty(); }
    bool has_flags() const { return m_flags != nullptr; }
    bool has_flags_mask() const { return m_flags_mask != nullptr; }
    bool has_integrity_registers() const { return !m_integrity_registers.empty(); }
    bool has_vendor_info() const { return !m_vendor_info.empty(); }
    bool has_type() const { return !m_type.empty(); }

    const std::string& vendor() const { return *m_vendor; }
    const std::string& model() const { return *m_model; }
    const std::string& version() const { return *m_version; }
    int64_t svn() const { return *m_svn; }
    int64_t layer() const { return *m_layer; }
    int64_t index() const { return *m_index; }
    const std::vector<FWID>& fwids() const { return m_fwids; }
    uint32_t flags() const { return *m_flags; }
    uint32_t flags_mask() const { return *m_flags_mask; }
    const std::vector<IntegrityRegister>& integrity_registers() const { return m_integrity_registers; }
    const std::vector<uint8_t>& vendor_info() const { return m_vendor_info; }
    const std::vector<uint8_t>& type() const { return m_type; }

    // Setters (for construction in tests and from JSON)
    void set_vendor(const std::string& v) { m_vendor = std::make_unique<std::string>(v); }
    void set_model(const std::string& v) { m_model = std::make_unique<std::string>(v); }
    void set_version(const std::string& v) { m_version = std::make_unique<std::string>(v); }
    void set_svn(int64_t v) { m_svn = std::make_unique<int64_t>(v); }
    void set_layer(int64_t v) { m_layer = std::make_unique<int64_t>(v); }
    void set_index(int64_t v) { m_index = std::make_unique<int64_t>(v); }
    void set_fwids(const std::vector<FWID>& v) { m_fwids = v; }
    void set_flags(uint32_t v) { m_flags = std::make_unique<uint32_t>(v); }
    void set_flags_mask(uint32_t v) { m_flags_mask = std::make_unique<uint32_t>(v); }
    void set_integrity_registers(const std::vector<IntegrityRegister>& v) { m_integrity_registers = v; }
    void set_vendor_info(const std::vector<uint8_t>& v) { m_vendor_info = v; }
    void set_type(const std::vector<uint8_t>& v) { m_type = v; }

    bool operator==(const DiceTcbInfo& other) const;
    bool operator!=(const DiceTcbInfo& other) const { return !(*this == other); }

    friend void to_json(nlohmann::json& js, const DiceTcbInfo& dt);
    friend void from_json(const nlohmann::json& js, DiceTcbInfo& dt);

private:
    // unique_ptr used for optionality (C++14; no std::optional until C++17).
    // Each field is solely owned by this instance.
    std::unique_ptr<std::string> m_vendor;
    std::unique_ptr<std::string> m_model;
    std::unique_ptr<std::string> m_version;
    std::unique_ptr<int64_t> m_svn;
    std::unique_ptr<int64_t> m_layer;
    std::unique_ptr<int64_t> m_index;
    std::vector<FWID> m_fwids;
    std::unique_ptr<uint32_t> m_flags;
    std::unique_ptr<uint32_t> m_flags_mask;
    std::vector<IntegrityRegister> m_integrity_registers;
    std::vector<uint8_t> m_vendor_info;
    std::vector<uint8_t> m_type;
};

/**
 * @brief Parsed MultiDiceTcbInfo (OID 2.23.133.5.4.5).
 * MultiDiceTcbInfo ::= SEQUENCE OF DiceTcbInfo
 */
class MultiDiceTcbInfo {
public:
    MultiDiceTcbInfo() = default;

    static Error parse_from_der(const std::vector<uint8_t>& der, MultiDiceTcbInfo& out);
    static Error parse_from_x509_extension(const void* x509_cert, MultiDiceTcbInfo& out, bool silent = false);

    const std::vector<DiceTcbInfo>& entries() const { return m_entries; }
    void add_entry(const DiceTcbInfo& entry) { m_entries.push_back(entry); }

    bool operator==(const MultiDiceTcbInfo& other) const { return m_entries == other.m_entries; }
    bool operator!=(const MultiDiceTcbInfo& other) const { return !(*this == other); }

    friend void to_json(nlohmann::json& js, const MultiDiceTcbInfo& mt);
    friend void from_json(const nlohmann::json& js, MultiDiceTcbInfo& mt);

private:
    std::vector<DiceTcbInfo> m_entries;
};

} // namespace nvattestation
