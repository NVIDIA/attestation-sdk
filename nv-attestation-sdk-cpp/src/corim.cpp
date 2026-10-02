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

#include "nv_attestation/corim.h"
#include "nv_attestation/corim_evidence/coev.h"  // SpdmIndirectMap complete type for MeasurementValues out-of-line ctors
#include "nv_attestation/cose.h"
#include "nv_attestation/log.h"
#include "nv_attestation/error.h"
#include "nv_attestation/utils.h"
#include "corim_decode.h"
#include "corim_decode_types.h"
#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/nv_x509.h"
#include "internal/cbor_decode_utils.h"
#include "internal/corim_decoders.h"

#include <cstring>
#include <stdexcept>
#include <zcbor_common.h>
#include <zcbor_print.h>
#include <nlohmann/json.hpp>
#include <openssl/objects.h>
#include <openssl/asn1.h>

namespace nvattestation {

namespace {
// Validates a dotted OID body: 1+ digit-runs separated by single dots.
bool is_valid_oid_body(const std::string& body) {
    if (body.empty()) {
        return false;
    }
    bool any_digit_in_arc = false;
    for (char ch : body) {
        if (ch == '.') {
            if (!any_digit_in_arc) {
                return false;
            }
            any_digit_in_arc = false;
        } else if (ch >= '0' && ch <= '9') {
            any_digit_in_arc = true;
        } else {
            return false;
        }
    }
    return any_digit_in_arc;
}

void require_oid_dotted(const std::string& oid, const char* who) {
    if (!is_valid_oid_body(oid)) {
        throw std::invalid_argument(
            std::string(who) + " expects bare dotted OID body, got: " + oid);
    }
}
} // namespace

std::string profile_value_to_string(const ProfileValue& profile) {
    return profile.kind == ProfileKind::Oid ? "oid:" + profile.value
                                            : profile.value;
}

ExactOidMatcher::ExactOidMatcher(std::string dotted_oid)
    : m_oid(std::move(dotted_oid)) {
    require_oid_dotted(m_oid, "ExactOidMatcher");
}

bool ExactOidMatcher::matches(const ProfileValue& got) const {
    return got.kind == ProfileKind::Oid && got.value == m_oid;
}

OidSubtreeMatcher::OidSubtreeMatcher(std::string dotted_oid)
    : m_base(std::move(dotted_oid)) {
    require_oid_dotted(m_base, "OidSubtreeMatcher");
}

bool OidSubtreeMatcher::matches(const ProfileValue& got) const {
    if (got.kind != ProfileKind::Oid) {
        return false;
    }
    if (!is_valid_oid_body(got.value)) {
        return false;
    }
    if (got.value == m_base) {
        return true;
    }
    // Arc-boundary: got.value must extend m_base with a "." separator, not
    // glue digits onto m_base's last arc ("1.2.999" must not match "1.2.9991").
    return got.value.size() > m_base.size()
        && got.value.compare(0, m_base.size(), m_base) == 0
        && got.value[m_base.size()] == '.';
}

bool ExactUriMatcher::matches(const ProfileValue& got) const {
    return got.kind == ProfileKind::Uri && got.value == m_uri;
}

bool ExactTextMatcher::matches(const ProfileValue& got) const {
    return got.kind == ProfileKind::Text && got.value == m_text;
}

VersionedUriMatcher::VersionedUriMatcher(std::string pattern) {
    // Build a full-match regex: escape all regex metacharacters in the literal
    // segments between '*' wildcards, then join with \d+ for each '*'.
    static const std::regex kMetaChars(R"([.^$|()\[\]{}+?\\])");
    std::string re_str;
    std::string rest = std::move(pattern);
    while (true) {
        auto star = rest.find('*');
        std::string literal(rest.substr(0, star));
        re_str += std::regex_replace(literal, kMetaChars, R"(\$&)");
        if (star == std::string::npos) {
            break;
        }
        re_str += R"(\d+)";
        rest = rest.substr(star + 1);
    }
    m_re = std::regex("^" + re_str + "$");
}

bool VersionedUriMatcher::matches(const ProfileValue& got) const {
    if (got.kind == ProfileKind::Oid) {
        return false;
    }
    return std::regex_match(got.value, m_re);
}

// UnsupportedCorimFeatureException is declared in internal/corim_decoders.h
// (shared with the CoEV parser).

// IANA Named Information hash algorithm IDs (not COSE algorithm IDs)
static constexpr int32_t NI_HASH_SHA256 = 1;
static constexpr int32_t NI_HASH_SHA384 = 7;
static constexpr int32_t NI_HASH_SHA512 = 8;

// Handles both COSE algorithm IDs (negative, from COSE_Sign1 digests) and
// IANA Named Information hash algorithm IDs (positive, from CoRIM measurement digests).
static const char* get_hash_algorithm_name(int32_t alg) {
    switch (alg) {
        case cose::HASH_SHA256: return "sha-256";  // COSE: -16
        case cose::HASH_SHA384: return "sha-384";  // COSE: -43
        case cose::HASH_SHA512: return "sha-512";  // COSE: -44
        case NI_HASH_SHA256: return "sha-256";      // NI: 1
        case NI_HASH_SHA384: return "sha-384";      // NI: 7
        case NI_HASH_SHA512: return "sha-512";      // NI: 8
        default: return "unknown";
    }
}


std::string format_uuid(const uint8_t* data, size_t len) {
    std::string uuid;
    if (uuid_to_string(data, len, uuid) != Error::Ok) {
        return "<uuid-format-error>";
    }
    return "uuid:" + uuid;
}

static constexpr uint8_t DER_TAG_OBJECT_IDENTIFIER = 0x06;
static constexpr size_t MAX_DER_SHORT_FORM_LENGTH = 127;
static constexpr size_t DER_TAG_LEN_OVERHEAD = 2;

std::string oid_dotted_body(const uint8_t* data, size_t len) {
    if (len == 0 || len > MAX_DER_SHORT_FORM_LENGTH) {
        return "";
    }

    // CBOR tag 111 carries BER-encoded OID content bytes without the DER
    // tag+length envelope. Wrap in DER for OpenSSL's d2i_ASN1_OBJECT.
    uint8_t der[DER_TAG_LEN_OVERHEAD + MAX_DER_SHORT_FORM_LENGTH];
    der[0] = DER_TAG_OBJECT_IDENTIFIER;
    der[1] = static_cast<uint8_t>(len);
    std::memcpy(der + DER_TAG_LEN_OVERHEAD, data, len);

    const uint8_t* der_ptr = der;
    ASN1_OBJECT* obj = d2i_ASN1_OBJECT(nullptr, &der_ptr, static_cast<long>(DER_TAG_LEN_OVERHEAD + len));
    if (obj == nullptr) {
        return "";
    }

    static constexpr size_t OID_STRING_BUFFER_SIZE = 256;
    char buf[OID_STRING_BUFFER_SIZE];
    int result = OBJ_obj2txt(buf, sizeof(buf), obj, 1);
    ASN1_OBJECT_free(obj);

    if (result <= 0) {
        return "";
    }
    return std::string(buf);
}

std::string oid_to_string(const uint8_t* data, size_t len) {
    std::string body = oid_dotted_body(data, len);
    return body.empty() ? std::string() : "oid:" + body;
}

bool oid_has_arc_prefix(const std::string& oid, const std::string& prefix) {
    if (oid.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    return oid.size() == prefix.size() || oid[prefix.size()] == '.';
}

bool oid_penultimate_arc_equals(const std::string& oid, const std::string& arc) {
    const size_t last_dot = oid.rfind('.');
    if (last_dot == std::string::npos || last_dot == 0) {
        return false;
    }
    const size_t prev_dot = oid.rfind('.', last_dot - 1);
    const size_t begin = (prev_dot == std::string::npos) ? 0 : prev_dot + 1;
    return oid.compare(begin, last_dot - begin, arc) == 0;
}

static ConciseMidTag make_concise_mid_tag(const concise_mid_tag* ptr);
static CorimMap make_corim_map(const corim_map* ptr, const CorimParseOptions& options);

// Convert exceptions from make_* wrapper constructors into Error return codes.
template<typename Fn>
static Error wrap_construction(const char* type_name, Fn fn) {
    try {
        fn();
    } catch (const UnsupportedCorimFeatureException& e) {
        LOG_ERROR(type_name << " contains unsupported features: " << e.what());
        return Error::RimInvalidSchema;
    } catch (const std::invalid_argument& e) {
        // Thrown for content the wrappers cannot make sense of, such as an
        // undecodable embedded CoMID, so the document is at fault here.
        LOG_ERROR(type_name << " is malformed: " << e.what());
        return Error::RimInvalidSchema;
    } catch (const std::exception& e) {
        LOG_ERROR("Internal error constructing " << type_name << " wrappers: " << e.what());
        return Error::InternalError;
    }
    return Error::Ok;
}

Error parse_signed_corim(
    const std::vector<uint8_t>& corim_bytes,
    const CoseSign1VerifyOptions& options,
    IOcspHttpClient& ocsp_client,
    CorimMap& out_corim,
    std::vector<PerCertStatus>& out_cert_claims,
    const CorimParseOptions& parse_options
) {
    CoseSign1Result cose_result;
    Error error = verify_cose_sign1(corim_bytes, options, ocsp_client, cose_result);
    // Propagate cert-chain claims even on failure: verify_cose_sign1 may
    // have populated them before rejecting the chain (e.g. for revocation),
    // and the caller needs that diagnostic data regardless of outcome.
    out_cert_claims = std::move(cose_result.cert_chain_claims);
    if (error != Error::Ok) {
        LOG_ERROR("COSE_Sign1 verification failed");
        return error;
    }

    error = parse_unsigned_corim(cose_result.payload, out_corim, parse_options);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to parse CoRIM payload");
        return error;
    }

    return Error::Ok;
}

Error parse_unsigned_corim(
    const std::vector<uint8_t>& corim_bytes,
    CorimMap& out_corim,
    const CorimParseOptions& parse_options
) {
    std::unique_ptr<corim_map> decoded;
    Error err = decode_cbor(corim_bytes, "CoRIM", cbor_decode_tagged_unsigned_corim_map,
                            decoded, Error::RimInvalidSchema);
    if (err != Error::Ok) {
        return err;
    }

    LOG_INFO("CoRIM contains " << decoded->corim_map_tags_concise_tag_type_choice_m_count << " tag(s)");
    if (decoded->corim_map_entities_present) {
        LOG_INFO("CoRIM has " << decoded->corim_map_entities.corim_map_entities_corim_entity_map_m_count << " entities");
    }

    return wrap_construction("CoRIM", [&]() {
        out_corim = make_corim_map(decoded.get(), parse_options);
    });
}

Error parse_comid(
    const std::vector<uint8_t>& comid_inner_bytes,
    ConciseMidTag& out_tag
) {
    std::unique_ptr<concise_mid_tag> decoded;
    Error err = decode_cbor(comid_inner_bytes, "CoMID", cbor_decode_concise_mid_tag, decoded,
                            Error::RimInvalidSchema);
    if (err != Error::Ok) {
        return err;
    }

    return wrap_construction("CoMID", [&]() { out_tag = make_concise_mid_tag(decoded.get()); });
}

std::string ByteString::toBase64() const {
    std::string result;
    Error err = encode_base64(m_data, result);
    if (err != Error::Ok) {
        LOG_ERROR("Base64 encoding failed");
        return "";
    }
    return result;
}

std::vector<uint8_t> ByteString::toVector() const {
    return m_data;
}

bool Digest::getAlgorithm(int32_t& out) const {
    if (m_alg_kind != AlgKind::kInt) {
        return false;
    }
    out = m_alg_int;
    return true;
}

bool Digest::getAlgorithm(std::string& out) const {
    if (m_alg_kind != AlgKind::kString) {
        return false;
    }
    out = m_alg_str;
    return true;
}

Digest make_digest(const digest* ptr) {
    ByteString value(ptr->digest_val.value, ptr->digest_val.len);
    if (ptr->digest_alg_choice == digest::digest_alg_int_c) {
        return Digest(ptr->digest_alg_int, std::move(value));
    }
    std::string alg_str(
        reinterpret_cast<const char*>(ptr->digest_alg_text_m.value),
        ptr->digest_alg_text_m.len
    );
    return Digest(std::move(alg_str), std::move(value));
}

// `_present` gates whether to set; the inner struct carries the value.
// (Prior versions used `_present` as the value, which lost polarity.)
FlagsMap make_flags_map(const flags_map* ptr) {
    FlagsMap out;
    if (ptr->flags_map_is_configured_present) {
        out.setConfigured(ptr->flags_map_is_configured.flags_map_is_configured);
    }
    if (ptr->flags_map_is_secure_present) {
        out.setSecure(ptr->flags_map_is_secure.flags_map_is_secure);
    }
    if (ptr->flags_map_is_recovery_present) {
        out.setRecovery(ptr->flags_map_is_recovery.flags_map_is_recovery);
    }
    if (ptr->flags_map_is_debug_present) {
        out.setDebug(ptr->flags_map_is_debug.flags_map_is_debug);
    }
    if (ptr->flags_map_is_replay_protected_present) {
        out.setReplayProtected(
            ptr->flags_map_is_replay_protected.flags_map_is_replay_protected);
    }
    if (ptr->flags_map_is_integrity_protected_present) {
        out.setIntegrityProtected(
            ptr->flags_map_is_integrity_protected.flags_map_is_integrity_protected);
    }
    if (ptr->flags_map_is_runtime_meas_present) {
        out.setRuntimeMeas(
            ptr->flags_map_is_runtime_meas.flags_map_is_runtime_meas);
    }
    if (ptr->flags_map_is_immutable_present) {
        out.setImmutable(ptr->flags_map_is_immutable.flags_map_is_immutable);
    }
    if (ptr->flags_map_is_tcb_present) {
        out.setTcb(ptr->flags_map_is_tcb.flags_map_is_tcb);
    }
    if (ptr->flags_map_is_confidentiality_protected_present) {
        out.setConfidentialityProtected(
            ptr->flags_map_is_confidentiality_protected
                .flags_map_is_confidentiality_protected);
    }
    return out;
}

// IANA CoSWID version-scheme value for semver (RFC 9393 §10).
static constexpr int32_t VERSION_SCHEME_SEMVER = 16384;
// CoRIM/CoSWID binary version-scheme: the version field carries the value as
// base64url without padding.
static constexpr int32_t VERSION_SCHEME_BINARY = 5;

Version make_version(const version_map* ptr) {
    std::string value(
        reinterpret_cast<const char*>(ptr->version_map_version.value),
        ptr->version_map_version.len
    );
    if (!ptr->version_map_scheme_present) {
        return Version(std::move(value));
    }
    const auto& scheme = ptr->version_map_scheme.version_map_scheme;
    switch (scheme.version_scheme_type_choice_choice) {
        case version_scheme_type_choice::version_scheme_type_choice_multipartnumeric_m_c:
            return Version(std::move(value), 1);
        case version_scheme_type_choice::version_scheme_type_choice_multipartnumeric_suffix_m_c:
            return Version(std::move(value), 2);
        case version_scheme_type_choice::version_scheme_type_choice_alphanumeric_m_c:
            return Version(std::move(value), 3);
        case version_scheme_type_choice::version_scheme_type_choice_decimal_m_c:
            return Version(std::move(value), 4);
        case version_scheme_type_choice::version_scheme_type_choice_semver_m_c:
            return Version(std::move(value), VERSION_SCHEME_SEMVER);
        case version_scheme_type_choice::version_scheme_type_choice_int_c: {
            const int32_t scheme_int = scheme.version_scheme_type_choice_int;
            if (scheme_int == VERSION_SCHEME_BINARY) {
                // Binary scheme: the version field is base64url (no padding) of the value.
                std::vector<uint8_t> decoded{};
                if (decode_base64url(value, decoded) == Error::Ok) {
                    return Version::withBinaryScheme(std::string(decoded.begin(), decoded.end()));
                }
                throw std::invalid_argument(
                    "version-scheme is binary (5) but version is not valid base64url");
            }
            return Version(std::move(value), scheme_int);
        }
        case version_scheme_type_choice::version_scheme_type_choice_text_m_c:
            return Version::withTextScheme(
                std::move(value),
                std::string(
                    reinterpret_cast<const char*>(scheme.version_scheme_type_choice_text_m.value),
                    scheme.version_scheme_type_choice_text_m.len));
    }
    return Version(std::move(value));
}

IntRange IntRange::simpleInt(int32_t value) {
    IntRange ir;
    ir.m_kind = Kind::kSimpleInt;
    ir.m_simple_value = value;
    return ir;
}

IntRange IntRange::range(bool has_min, int32_t min_val, bool has_max, int32_t max_val) {
    IntRange ir;
    ir.m_kind = Kind::kRange;
    ir.m_has_min = has_min;
    ir.m_min = min_val;
    ir.m_has_max = has_max;
    ir.m_max = max_val;
    return ir;
}

bool IntRange::isSimpleInt(int32_t& out) const {
    if (m_kind == Kind::kSimpleInt) {
        out = m_simple_value;
        return true;
    }
    return false;
}

bool IntRange::isRange(bool& has_min, int32_t& min_out, bool& has_max, int32_t& max_out) const {
    if (m_kind != Kind::kRange) {
        return false;
    }
    has_min = m_has_min;
    if (m_has_min) { min_out = m_min; }
    has_max = m_has_max;
    if (m_has_max) { max_out = m_max; }
    return true;
}

IntRange make_int_range(const int_range_type_choice* ptr) {
    if (ptr->int_range_type_choice_choice == int_range_type_choice::int_range_type_choice_int_c) {
        return IntRange::simpleInt(ptr->int_range_type_choice_int);
    }
    const auto& range = ptr->int_range_type_choice_tagged_int_range_m;
    bool has_min = (range.int_range_type_min_choice == int_range_type::int_range_type_min_int_c);
    bool has_max = (range.int_range_type_max_choice == int_range_type::int_range_type_max_int_c);
    return IntRange::range(has_min, range.int_range_type_min_int, has_max, range.int_range_type_max_int);
}

MeasurementValues::MeasurementValues(
    std::unique_ptr<Version> version,
    std::unique_ptr<FlagsMap> flags,
    std::unique_ptr<ByteString> raw_value,
    std::unique_ptr<ByteString> raw_value_mask,
    std::unique_ptr<std::string> name,
    std::unique_ptr<IntRange> int_range,
    std::unique_ptr<Svn> svn,
    std::vector<Digest> digests,
    std::unique_ptr<SpdmIndirectMap> spdm_indirect
)
    : m_version(std::move(version))
    , m_flags(std::move(flags))
    , m_raw_value(std::move(raw_value))
    , m_raw_value_mask(std::move(raw_value_mask))
    , m_name(std::move(name))
    , m_int_range(std::move(int_range))
    , m_svn(std::move(svn))
    , m_digests(std::move(digests))
    , m_spdm_indirect(std::move(spdm_indirect))
{}

MeasurementValues::MeasurementValues() = default;
MeasurementValues::~MeasurementValues() = default;
MeasurementValues::MeasurementValues(MeasurementValues&&) noexcept = default;
MeasurementValues& MeasurementValues::operator=(MeasurementValues&&) noexcept = default;

MeasurementValues::MeasurementValues(const MeasurementValues& other)
    : m_version(other.m_version ? std::make_unique<Version>(*other.m_version) : nullptr)
    , m_flags(other.m_flags ? std::make_unique<FlagsMap>(*other.m_flags) : nullptr)
    , m_raw_value(other.m_raw_value ? std::make_unique<ByteString>(*other.m_raw_value) : nullptr)
    , m_raw_value_mask(other.m_raw_value_mask ? std::make_unique<ByteString>(*other.m_raw_value_mask) : nullptr)
    , m_name(other.m_name ? std::make_unique<std::string>(*other.m_name) : nullptr)
    , m_int_range(other.m_int_range ? std::make_unique<IntRange>(*other.m_int_range) : nullptr)
    , m_svn(other.m_svn ? std::make_unique<Svn>(*other.m_svn) : nullptr)
    , m_digests(other.m_digests)
    , m_spdm_indirect(other.m_spdm_indirect
        ? std::make_unique<SpdmIndirectMap>(*other.m_spdm_indirect)
        : nullptr)
{}

MeasurementValues& MeasurementValues::operator=(const MeasurementValues& other) {
    if (this != &other) {
        MeasurementValues tmp(other);
        *this = std::move(tmp);
    }
    return *this;
}

// Reject (Strict) or warn-skip (Permissive) a single unsupported
// measurement-values-map field. The wrapper does not carry the field
// either way; Strict mode fails the parse, Permissive mode continues.
// spdm-indirect-map has a single optional member.
constexpr SchemaKey kSpdmIndirectSchemaKeys[] = {
    {0, "index"},
};

static void reject_or_skip_mvm_field(bool present, Strictness strict, const char* field_label) {
    if (!present) {
        return;
    }
    if (strict == Strictness::Strict) {
        throw UnsupportedCorimFeatureException(
            std::string("measurement-values-map ") + field_label + " field not supported");
    }
    LOG_WARN("permissive skip: measurement-values-map." << field_label << " not surfaced");
}

MeasurementValues make_measurement_values(const measurement_values_map* ptr, Strictness strict) {
    reject_or_skip_mvm_field(ptr->measurement_values_map_mac_addr_present, strict, "mac-addr");
    reject_or_skip_mvm_field(ptr->measurement_values_map_ip_addr_present, strict, "ip-addr");
    reject_or_skip_mvm_field(ptr->measurement_values_map_serial_number_present, strict, "serial-number");
    reject_or_skip_mvm_field(ptr->measurement_values_map_ueid_present, strict, "ueid");
    reject_or_skip_mvm_field(ptr->measurement_values_map_uuid_present, strict, "uuid");
    reject_or_skip_mvm_field(ptr->measurement_values_map_cryptokeys_present, strict, "cryptokeys");
    reject_or_skip_mvm_field(ptr->measurement_values_map_integrity_registers_present, strict, "integrity-registers");
    reject_or_skip_mvm_field(ptr->measurement_values_map_raw_value_mask_DEPRECATED_present, strict, "raw-value-mask-DEPRECATED");

    std::unique_ptr<Version> version;
    if (ptr->measurement_values_map_version_present) {
        version.reset(new Version(
            make_version(&ptr->measurement_values_map_version.measurement_values_map_version)));
    }
    std::unique_ptr<FlagsMap> flags;
    if (ptr->measurement_values_map_flags_present) {
        flags.reset(new FlagsMap(
            make_flags_map(&ptr->measurement_values_map_flags.measurement_values_map_flags)));
    }
    std::unique_ptr<ByteString> raw_value;
    std::unique_ptr<ByteString> raw_value_mask;
    if (ptr->measurement_values_map_raw_value_present) {
        const auto& raw = ptr->measurement_values_map_raw_value.measurement_values_map_raw_value;
        switch (raw.raw_value_type_choice_choice) {
            case raw_value_type_choice::raw_value_type_choice_tagged_bytes_m_c:
                raw_value.reset(new ByteString(
                    raw.raw_value_type_choice_tagged_bytes_m.value,
                    raw.raw_value_type_choice_tagged_bytes_m.len
                ));
                break;
            case raw_value_type_choice::raw_value_type_choice_tagged_masked_raw_value_m_c: {
                const auto& masked = raw.raw_value_type_choice_tagged_masked_raw_value_m;
                if (masked.tagged_masked_raw_value_value.len != masked.tagged_masked_raw_value_mask.len) {
                    throw UnsupportedCorimFeatureException(
                        "tagged-masked-raw-value: value and mask must have equal length");
                }
                raw_value.reset(new ByteString(
                    masked.tagged_masked_raw_value_value.value,
                    masked.tagged_masked_raw_value_value.len
                ));
                raw_value_mask.reset(new ByteString(
                    masked.tagged_masked_raw_value_mask.value,
                    masked.tagged_masked_raw_value_mask.len
                ));
                break;
            }
            default:
                break;
        }
    }
    std::unique_ptr<std::string> name;
    if (ptr->measurement_values_map_name_present) {
        name.reset(new std::string(
            reinterpret_cast<const char*>(ptr->measurement_values_map_name.measurement_values_map_name.value),
            ptr->measurement_values_map_name.measurement_values_map_name.len
        ));
    }
    std::unique_ptr<IntRange> int_range;
    if (ptr->measurement_values_map_int_range_present) {
        int_range.reset(new IntRange(
            make_int_range(&ptr->measurement_values_map_int_range.measurement_values_map_int_range)));
    }
    std::unique_ptr<Svn> svn;
    if (ptr->measurement_values_map_svn_present) {
        const auto& svn_choice = ptr->measurement_values_map_svn.measurement_values_map_svn;
        SvnKind kind = SvnKind::kExact;
        uint32_t value = 0;
        switch (svn_choice.svn_type_choice_choice) {
            case svn_type_choice::svn_type_choice_svn_val_m_c:
                value = svn_choice.svn_type_choice_svn_val_m;
                break;
            case svn_type_choice::svn_type_choice_tagged_svn_m_c:
                value = svn_choice.svn_type_choice_tagged_svn_m;
                break;
            case svn_type_choice::svn_type_choice_tagged_min_svn_m_c:
                kind = SvnKind::kMin;
                value = svn_choice.svn_type_choice_tagged_min_svn_m;
                break;
        }
        svn.reset(new Svn(kind, value));
    }
    std::vector<Digest> digests;
    if (ptr->measurement_values_map_digests_present) {
        const auto& dg = ptr->measurement_values_map_digests.measurement_values_map_digests;
        digests.reserve(dg.digests_type_digest_m_count);
        for (size_t i = 0; i < dg.digests_type_digest_m_count; i++) {
            digests.push_back(make_digest(&dg.digests_type_digest_m[i]));
        }
    }
    // §7.1 spdm-indirect extension. Meaningful only for CoEV evidence;
    // strict CoRIM parsing rejects it. Permissive parsing surfaces it.
    std::unique_ptr<SpdmIndirectMap> spdm_indirect;
    if (ptr->measurement_values_map_spdm_indirect_present) {
        if (strict == Strictness::Strict) {
            throw UnsupportedCorimFeatureException(
                "measurement-values-map spdm-indirect (key 12) field not supported");
        }
        const auto& si = ptr->measurement_values_map_spdm_indirect.measurement_values_map_spdm_indirect;
        // A malformed index list is shadowed into the extension array and would
        // otherwise leave the measurement resolving to no SPDM blocks at all —
        // silently under-verified rather than rejected.
        if (report_shadowed_keys("CoEV", "spdm-indirect-map", si.spdm_indirect_map_intany,
                                 si.spdm_indirect_map_intany_count,
                                 kSpdmIndirectSchemaKeys)) {
            throw UnsupportedCorimFeatureException(
                "spdm-indirect-map member failed schema validation");
        }
        std::vector<uint64_t> indexes;
        if (si.spdm_indirect_map_index_present) {
            const auto& idx = si.spdm_indirect_map_index.spdm_indirect_map_index_uint;
            size_t count = si.spdm_indirect_map_index.spdm_indirect_map_index_uint_count;
            indexes.reserve(count);
            for (size_t i = 0; i < count; ++i) {
                indexes.push_back(idx[i]);
            }
        }
        spdm_indirect = std::make_unique<SpdmIndirectMap>(std::move(indexes));
    }

    return MeasurementValues(
        std::move(version), std::move(flags),
        std::move(raw_value), std::move(raw_value_mask),
        std::move(name), std::move(int_range),
        std::move(svn), std::move(digests),
        std::move(spdm_indirect)
    );
}

MeasurementMapKey make_measurement_map_key(const measurement_map* ptr) {
    MeasurementMapKey key;
    if (!ptr->measurement_map_mkey_present) {
        return key;
    }

    const auto& mkey = ptr->measurement_map_mkey.measurement_map_mkey;
    switch (mkey.measured_element_type_choice_choice) {
        case measured_element_type_choice::measured_element_type_choice_tstr_c:
            key.type = MeasurementMapKey::Type::kString;
            key.str_value = std::string(
                reinterpret_cast<const char*>(mkey.measured_element_type_choice_tstr.value),
                mkey.measured_element_type_choice_tstr.len
            );
            break;
        case measured_element_type_choice::measured_element_type_choice_uint_c:
            key.type = MeasurementMapKey::Type::kUint;
            key.uint_value = mkey.measured_element_type_choice_uint;
            break;
        case measured_element_type_choice::measured_element_type_choice_tagged_oid_type_m_c:
            key.type = MeasurementMapKey::Type::kOid;
            key.str_value = oid_to_string(
                mkey.measured_element_type_choice_tagged_oid_type_m.value,
                mkey.measured_element_type_choice_tagged_oid_type_m.len
            );
            break;
        case measured_element_type_choice::measured_element_type_choice_tagged_uuid_type_m_c:
            key.type = MeasurementMapKey::Type::kUuid;
            key.str_value = format_uuid(
                mkey.measured_element_type_choice_tagged_uuid_type_m.value,
                mkey.measured_element_type_choice_tagged_uuid_type_m.len
            );
            break;
        default:
            break;
    }
    return key;
}

MeasurementMap make_measurement_map(const measurement_map* ptr, Strictness strict) {
    if (ptr->measurement_map_authorized_by_present) {
        if (strict == Strictness::Strict) {
            throw UnsupportedCorimFeatureException("measurement-map authorized-by field not supported");
        }
        LOG_WARN("permissive skip: measurement-map.authorized-by not surfaced");
    }
    auto key = make_measurement_map_key(ptr);
    auto values = make_measurement_values(&ptr->measurement_map_mval, strict);
    return MeasurementMap(std::move(key), std::move(values));
}

ClassMap::ClassMap(
    std::unique_ptr<ClassId> class_id,
    std::unique_ptr<std::string> vendor,
    std::unique_ptr<std::string> model,
    std::unique_ptr<uint32_t> layer,
    std::unique_ptr<uint32_t> index
)
    : m_class_id(std::move(class_id))
    , m_vendor(std::move(vendor))
    , m_model(std::move(model))
    , m_layer(std::move(layer))
    , m_index(std::move(index))
{}

ClassMap make_class_map(const class_map* ptr) {
    std::unique_ptr<ClassId> class_id;
    if (ptr->class_map_class_id_present) {
        const auto& cid = ptr->class_map_class_id.class_map_class_id;
        if (cid.class_id_type_choice_choice == class_id_type_choice::class_id_type_choice_tagged_oid_type_m_c) {
            class_id.reset(new ClassId(ClassId::Kind::kOid, ByteString(
                cid.class_id_type_choice_tagged_oid_type_m.value,
                cid.class_id_type_choice_tagged_oid_type_m.len)));
        } else if (cid.class_id_type_choice_choice == class_id_type_choice::class_id_type_choice_tagged_uuid_type_m_c) {
            class_id.reset(new ClassId(ClassId::Kind::kUuid, ByteString(
                cid.class_id_type_choice_tagged_uuid_type_m.value,
                cid.class_id_type_choice_tagged_uuid_type_m.len)));
        } else {
            class_id.reset(new ClassId(ClassId::Kind::kBytes, ByteString(
                cid.class_id_type_choice_tagged_bytes_m.value,
                cid.class_id_type_choice_tagged_bytes_m.len)));
        }
    }
    std::unique_ptr<std::string> vendor;
    if (ptr->class_map_vendor_present) {
        vendor.reset(new std::string(
            reinterpret_cast<const char*>(ptr->class_map_vendor.class_map_vendor.value),
            ptr->class_map_vendor.class_map_vendor.len
        ));
    }
    std::unique_ptr<std::string> model;
    if (ptr->class_map_model_present) {
        model.reset(new std::string(
            reinterpret_cast<const char*>(ptr->class_map_model.class_map_model.value),
            ptr->class_map_model.class_map_model.len
        ));
    }
    std::unique_ptr<uint32_t> layer;
    if (ptr->class_map_layer_present) {
        layer.reset(new uint32_t(ptr->class_map_layer.class_map_layer));
    }
    std::unique_ptr<uint32_t> index;
    if (ptr->class_map_index_present) {
        index.reset(new uint32_t(ptr->class_map_index.class_map_index));
    }
    return ClassMap(
        std::move(class_id), std::move(vendor), std::move(model),
        std::move(layer), std::move(index)
    );
}

namespace {
// Boost hash_combine constants: fractional parts of the golden ratio,
// used as hash-mix seed and perturbation.
constexpr uint64_t kHashGoldenRatio64 = 0x9e3779b97f4a7c15ULL;
constexpr uint64_t kHashGoldenRatio32 = 0x9e3779b9ULL;
constexpr int kHashCombineShift = 6;

// nullptr orders before any non-null value.
template <typename T>
int cmp_optional(const T* lhs, const T* rhs) {
    if (lhs == nullptr && rhs == nullptr) { return 0; }
    if (lhs == nullptr) { return -1; }
    if (rhs == nullptr) { return 1; }
    if (*lhs < *rhs) { return -1; }
    if (*rhs < *lhs) { return 1; }
    return 0;
}

inline void hash_combine(size_t& seed, size_t value) {
    seed ^= value + kHashGoldenRatio64 + (seed << kHashCombineShift) + (seed >> 2);
}

template <typename T>
size_t hash_optional(const T* ptr) {
    if (ptr == nullptr) { return 0; }
    return std::hash<T>{}(*ptr) ^ kHashGoldenRatio32;  // tag present-vs-absent
}
} // namespace

bool ClassMap::operator<(const ClassMap& other) const {
    int cmp = cmp_optional(getClassId(), other.getClassId());
    if (cmp != 0) { return cmp < 0; }
    cmp = cmp_optional(getVendor(), other.getVendor());
    if (cmp != 0) { return cmp < 0; }
    cmp = cmp_optional(getModel(), other.getModel());
    if (cmp != 0) { return cmp < 0; }
    cmp = cmp_optional(getLayer(), other.getLayer());
    if (cmp != 0) { return cmp < 0; }
    cmp = cmp_optional(getIndex(), other.getIndex());
    return cmp < 0;
}

bool ClassMap::operator==(const ClassMap& other) const {
    const ClassId* class_id = getClassId();
    const ClassId* other_class_id = other.getClassId();
    if ((class_id == nullptr) != (other_class_id == nullptr)) { return false; }
    if (class_id != nullptr && *class_id != *other_class_id) { return false; }

    const std::string* vendor = getVendor();
    const std::string* other_vendor = other.getVendor();
    if ((vendor == nullptr) != (other_vendor == nullptr)) { return false; }
    if (vendor != nullptr && *vendor != *other_vendor) { return false; }

    const std::string* model = getModel();
    const std::string* other_model = other.getModel();
    if ((model == nullptr) != (other_model == nullptr)) { return false; }
    if (model != nullptr && *model != *other_model) { return false; }

    const uint32_t* layer = getLayer();
    const uint32_t* other_layer = other.getLayer();
    if ((layer == nullptr) != (other_layer == nullptr)) { return false; }
    if (layer != nullptr && *layer != *other_layer) { return false; }

    const uint32_t* index = getIndex();
    const uint32_t* other_index = other.getIndex();
    if ((index == nullptr) != (other_index == nullptr)) { return false; }
    if (index != nullptr && *index != *other_index) { return false; }

    return true;
}

bool ClassMap::matches(const ClassMap& evidence) const {
    if (m_class_id != nullptr) {
        if (evidence.m_class_id == nullptr || *m_class_id != *evidence.m_class_id) { return false; }
    }
    if (m_vendor != nullptr) {
        if (evidence.m_vendor == nullptr || *m_vendor != *evidence.m_vendor) { return false; }
    }
    if (m_model != nullptr) {
        if (evidence.m_model == nullptr || *m_model != *evidence.m_model) { return false; }
    }
    if (m_layer != nullptr) {
        if (evidence.m_layer == nullptr || *m_layer != *evidence.m_layer) { return false; }
    }
    if (m_index != nullptr) {
        if (evidence.m_index == nullptr || *m_index != *evidence.m_index) { return false; }
    }
    return true;
}

InstanceId make_instance_id(const instance_id_type_choice& id) {
    switch (id.instance_id_type_choice_choice) {
        case instance_id_type_choice::instance_id_type_choice_tagged_uuid_type_m_c:
            return InstanceId(InstanceId::Kind::kUuid, ByteString(
                id.instance_id_type_choice_tagged_uuid_type_m.value,
                id.instance_id_type_choice_tagged_uuid_type_m.len));
        case instance_id_type_choice::instance_id_type_choice_tagged_ueid_type_m_c:
            return InstanceId(InstanceId::Kind::kUeid, ByteString(
                id.instance_id_type_choice_tagged_ueid_type_m.value,
                id.instance_id_type_choice_tagged_ueid_type_m.len));
        case instance_id_type_choice::instance_id_type_choice_tagged_bytes_m_c:
            return InstanceId(InstanceId::Kind::kBytes, ByteString(
                id.instance_id_type_choice_tagged_bytes_m.value,
                id.instance_id_type_choice_tagged_bytes_m.len));
        default:
            throw UnsupportedCorimFeatureException(
                "CoRIM environment instance type not supported (key/cert variants)");
    }
}

GroupId make_group_id(const group_id_type_choice& id) {
    switch (id.group_id_type_choice_choice) {
        case group_id_type_choice::group_id_type_choice_tagged_uuid_type_m_c:
            return GroupId(GroupId::Kind::kUuid, ByteString(
                id.group_id_type_choice_tagged_uuid_type_m.value,
                id.group_id_type_choice_tagged_uuid_type_m.len));
        case group_id_type_choice::group_id_type_choice_tagged_bytes_m_c:
            return GroupId(GroupId::Kind::kBytes, ByteString(
                id.group_id_type_choice_tagged_bytes_m.value,
                id.group_id_type_choice_tagged_bytes_m.len));
        default:
            throw UnsupportedCorimFeatureException("CoRIM environment group type unrecognized");
    }
}

EnvironmentMap make_environment_map(const environment_map* ptr) {
    std::unique_ptr<ClassMap> cls;
    if (ptr->environment_map_class_present) {
        cls.reset(new ClassMap(make_class_map(&ptr->environment_map_class.environment_map_class)));
    }
    std::unique_ptr<InstanceId> instance;
    if (ptr->environment_map_instance_present) {
        instance.reset(new InstanceId(
            make_instance_id(ptr->environment_map_instance.environment_map_instance)));
    }
    std::unique_ptr<GroupId> group;
    if (ptr->environment_map_group_present) {
        group.reset(new GroupId(
            make_group_id(ptr->environment_map_group.environment_map_group)));
    }
    return EnvironmentMap(std::move(cls), std::move(instance), std::move(group));
}

bool EnvironmentMap::matches(const EnvironmentMap& other) const {
    if (m_class != nullptr) {
        if (other.m_class == nullptr || !m_class->matches(*other.m_class)) {
            return false;
        }
    }
    if (m_instance != nullptr) {
        if (other.m_instance == nullptr || *m_instance != *other.m_instance) {
            return false;
        }
    }
    if (m_group != nullptr) {
        if (other.m_group == nullptr || *m_group != *other.m_group) {
            return false;
        }
    }
    return true;
}

bool EnvironmentMap::operator<(const EnvironmentMap& other) const {
    int cmp = cmp_optional(getClass(), other.getClass());
    if (cmp != 0) { return cmp < 0; }
    cmp = cmp_optional(getInstance(), other.getInstance());
    if (cmp != 0) { return cmp < 0; }
    cmp = cmp_optional(getGroup(), other.getGroup());
    return cmp < 0;
}

bool EnvironmentMap::operator==(const EnvironmentMap& other) const {
    const ClassMap* cls = getClass();
    const ClassMap* other_cls = other.getClass();
    if ((cls == nullptr) != (other_cls == nullptr)) { return false; }
    if (cls != nullptr && *cls != *other_cls) { return false; }

    const InstanceId* instance = getInstance();
    const InstanceId* other_instance = other.getInstance();
    if ((instance == nullptr) != (other_instance == nullptr)) { return false; }
    if (instance != nullptr && *instance != *other_instance) { return false; }

    const GroupId* group = getGroup();
    const GroupId* other_group = other.getGroup();
    if ((group == nullptr) != (other_group == nullptr)) { return false; }
    if (group != nullptr && *group != *other_group) { return false; }

    return true;
}

namespace {
size_t hash_class_id(const ClassId* cid) {
    if (cid == nullptr) { return 0; }
    size_t seed = kHashGoldenRatio32;
    hash_combine(seed, std::hash<int>{}(static_cast<int>(cid->getKind())));
    const ByteString& bytes = cid->getValue();
    for (size_t i = 0; i < bytes.size(); i++) {
        hash_combine(seed, std::hash<uint8_t>{}(bytes.data()[i]));
    }
    return seed;
}

size_t hash_class_map(const ClassMap* cls) {
    if (cls == nullptr) { return 0; }
    size_t seed = kHashGoldenRatio32;
    hash_combine(seed, hash_class_id(cls->getClassId()));
    hash_combine(seed, hash_optional(cls->getVendor()));
    hash_combine(seed, hash_optional(cls->getModel()));
    hash_combine(seed, hash_optional(cls->getLayer()));
    hash_combine(seed, hash_optional(cls->getIndex()));
    return seed;
}

template <typename TypedId>
size_t hash_typed_id(const TypedId* id) {
    if (id == nullptr) { return 0; }
    size_t seed = kHashGoldenRatio32;
    hash_combine(seed, std::hash<int>{}(static_cast<int>(id->getKind())));
    const ByteString& bytes = id->getValue();
    for (size_t i = 0; i < bytes.size(); i++) {
        hash_combine(seed, std::hash<uint8_t>{}(bytes.data()[i]));
    }
    return seed;
}
} // namespace

} // namespace nvattestation

namespace std {
size_t hash<nvattestation::EnvironmentMap>::operator()(
        const nvattestation::EnvironmentMap& env) const noexcept {
    size_t seed = 0;
    nvattestation::hash_combine(seed, nvattestation::hash_class_map(env.getClass()));
    nvattestation::hash_combine(seed, nvattestation::hash_typed_id(env.getInstance()));
    nvattestation::hash_combine(seed, nvattestation::hash_typed_id(env.getGroup()));
    return seed;
}
} // namespace std

namespace nvattestation {

ProfileValue make_profile(const profile_type_choice* ptr) {
    ProfileValue pv;
    switch (ptr->profile_type_choice_choice) {
        case profile_type_choice::profile_type_choice_uri_m_c:
            pv.kind = ProfileKind::Uri;
            pv.value.assign(
                reinterpret_cast<const char*>(ptr->profile_type_choice_uri_m.value),
                ptr->profile_type_choice_uri_m.len);
            break;
        default:
            pv.kind = ProfileKind::Oid;
            pv.value = oid_dotted_body(
                ptr->profile_type_choice_tagged_oid_type_m.value,
                ptr->profile_type_choice_tagged_oid_type_m.len);
            break;
    }
    return pv;
}

static ReferenceTriple make_reference_triple(const reference_triple_record* ptr) {
    auto env = make_environment_map(&ptr->reference_triple_record_ref_env);
    std::vector<MeasurementMap> measurements;
    measurements.reserve(ptr->reference_triple_record_ref_claims_measurement_map_m_count);
    for (size_t i = 0; i < ptr->reference_triple_record_ref_claims_measurement_map_m_count; i++) {
        measurements.push_back(
            make_measurement_map(&ptr->reference_triple_record_ref_claims_measurement_map_m[i], Strictness::Strict));
    }
    return ReferenceTriple(std::move(env), std::move(measurements));
}

static DependencyTriple make_dependency_triple(const domain_dependency_triple_record* ptr) {
    auto domain_id = make_environment_map(&ptr->domain_dependency_triple_record_domain_id);
    std::vector<EnvironmentMap> trustees;
    trustees.reserve(ptr->domain_dependency_triple_record_trustees_domain_type_m_count);
    for (size_t i = 0; i < ptr->domain_dependency_triple_record_trustees_domain_type_m_count; i++) {
        trustees.push_back(make_environment_map(&ptr->domain_dependency_triple_record_trustees_domain_type_m[i]));
    }
    return DependencyTriple(std::move(domain_id), std::move(trustees));
}

static Entity make_entity(const comid_entity_map* ptr) {
    std::string name(
        reinterpret_cast<const char*>(ptr->comid_entity_map_comid_entity_name.value),
        ptr->comid_entity_map_comid_entity_name.len
    );
    std::unique_ptr<std::string> reg_id;
    if (ptr->comid_entity_map_comid_reg_id_present) {
        reg_id.reset(new std::string(
            reinterpret_cast<const char*>(ptr->comid_entity_map_comid_reg_id.comid_entity_map_comid_reg_id.value),
            ptr->comid_entity_map_comid_reg_id.comid_entity_map_comid_reg_id.len
        ));
    }
    std::vector<EntityRole> roles;
    roles.reserve(ptr->comid_entity_map_comid_role_comid_role_type_choice_m_count);
    for (size_t i = 0; i < ptr->comid_entity_map_comid_role_comid_role_type_choice_m_count; i++) {
        const auto& role = ptr->comid_entity_map_comid_role_comid_role_type_choice_m[i];
        roles.push_back(static_cast<EntityRole>(role.comid_role_type_choice_choice));
    }
    return Entity(std::move(name), std::move(reg_id), std::move(roles));
}

static CorimEntity make_corim_entity(const corim_entity_map* ptr) {
    std::string name(
        reinterpret_cast<const char*>(ptr->corim_entity_map_corim_entity_name.value),
        ptr->corim_entity_map_corim_entity_name.len
    );
    std::unique_ptr<std::string> reg_id;
    if (ptr->corim_entity_map_corim_reg_id_present) {
        reg_id.reset(new std::string(
            reinterpret_cast<const char*>(ptr->corim_entity_map_corim_reg_id.corim_entity_map_corim_reg_id.value),
            ptr->corim_entity_map_corim_reg_id.corim_entity_map_corim_reg_id.len
        ));
    }
    std::vector<CorimRole> roles;
    roles.reserve(ptr->corim_entity_map_corim_role_corim_role_type_choice_m_count);
    for (size_t i = 0; i < ptr->corim_entity_map_corim_role_corim_role_type_choice_m_count; i++) {
        const auto& role = ptr->corim_entity_map_corim_role_corim_role_type_choice_m[i];
        roles.push_back(static_cast<CorimRole>(role.corim_role_type_choice_choice));
    }
    return CorimEntity(std::move(name), std::move(reg_id), std::move(roles));
}

bool ValidityMap::getNotBefore(std::chrono::system_clock::time_point& out) const {
    if (!m_has_not_before) {
        return false;
    }
    out = m_not_before;
    return true;
}

bool ValidityMap::getNotAfter(std::chrono::system_clock::time_point& out) const {
    if (!m_has_not_after) {
        return false;
    }
    out = m_not_after;
    return true;
}

static std::chrono::system_clock::time_point parse_number_as_time(const number& num) {
    if (num.number_choice == number::number_int_c) {
        return std::chrono::system_clock::from_time_t(static_cast<time_t>(num.number_int));
    }
    throw UnsupportedCorimFeatureException("CoRIM validity-map float timestamps not supported");
}

static ValidityMap make_validity_map(const validity_map* ptr) {
    auto not_after = parse_number_as_time(ptr->validity_map_not_after);
    if (ptr->validity_map_not_before_present) {
        auto not_before = parse_number_as_time(ptr->validity_map_not_before.validity_map_not_before);
        return ValidityMap(not_before, not_after);
    }
    return ValidityMap(not_after);
}

ConciseMidTag::ConciseMidTag(
    std::string tag_id,
    std::unique_ptr<std::string> language,
    std::vector<Entity> entities,
    std::vector<ReferenceTriple> ref_triples,
    std::vector<DependencyTriple> dep_triples
)
    : m_tag_id(std::move(tag_id))
    , m_language(std::move(language))
    , m_entities(std::move(entities))
    , m_ref_triples(std::move(ref_triples))
    , m_dep_triples(std::move(dep_triples))
{}

static ConciseMidTag make_concise_mid_tag(const concise_mid_tag* ptr) {
    if (ptr->concise_mid_tag_linked_tags_present) {
        throw UnsupportedCorimFeatureException("CoRIM concise-mid-tag linked-tags field not supported");
    }
    if (ptr->concise_mid_tag_extension_key_count > 0) {
        // No shadowed-member check here: concise-mid-tag ends with the
        // mandatory triples (key 4), so an earlier optional whose value fails
        // leaves the positional walk misaligned and the whole map decode fails
        // before the extension rule ever runs. Only maps whose trailing members
        // are all optional can shadow — see make_corim_map.
        throw UnsupportedCorimFeatureException("CoRIM concise-mid-tag extension fields not supported");
    }

    const auto& triples = ptr->concise_mid_tag_triples;
    if (triples.triples_map_identity_triples_present) {
        throw UnsupportedCorimFeatureException("CoRIM identity-triples not supported");
    }
    if (triples.triples_map_attest_key_triples_present) {
        throw UnsupportedCorimFeatureException("CoRIM attest-key-triples not supported");
    }
    if (triples.triples_map_membership_triples_present) {
        throw UnsupportedCorimFeatureException("CoRIM membership-triples not supported");
    }
    if (triples.triples_map_coswid_triples_present) {
        throw UnsupportedCorimFeatureException("CoRIM coswid-triples not supported");
    }
    // endorsed-triples, conditional-endorsement-triples, and
    // conditional-endorsement-series-triples are "parsed, ignored" per the
    // coverage spec: walk past them without populating anything.

    const auto& tag_id = ptr->concise_mid_tag_tag_identity.tag_identity_map_tag_id;
    std::string tag_id_str;
    if (tag_id.tag_id_type_choice_choice == tag_id_type_choice::tag_id_type_choice_tstr_c) {
        tag_id_str = std::string(
            reinterpret_cast<const char*>(tag_id.tag_id_type_choice_tstr.value),
            tag_id.tag_id_type_choice_tstr.len
        );
    } else {
        tag_id_str = format_uuid(
            tag_id.tag_id_type_choice_uuid_type_m.value,
            tag_id.tag_id_type_choice_uuid_type_m.len
        );
    }

    std::unique_ptr<std::string> language;
    if (ptr->concise_mid_tag_language_present) {
        language.reset(new std::string(
            reinterpret_cast<const char*>(ptr->concise_mid_tag_language.concise_mid_tag_language.value),
            ptr->concise_mid_tag_language.concise_mid_tag_language.len
        ));
    }

    std::vector<Entity> entities;
    if (ptr->concise_mid_tag_entities_present) {
        const auto& en = ptr->concise_mid_tag_entities;
        entities.reserve(en.concise_mid_tag_entities_comid_entity_map_m_count);
        for (size_t i = 0; i < en.concise_mid_tag_entities_comid_entity_map_m_count; i++) {
            entities.push_back(make_entity(&en.concise_mid_tag_entities_comid_entity_map_m[i]));
        }
    }

    std::vector<ReferenceTriple> ref_triples;
    if (triples.triples_map_reference_triples_present) {
        const auto& refs = triples.triples_map_reference_triples;
        ref_triples.reserve(refs.triples_map_reference_triples_reference_triple_record_m_count);
        for (size_t i = 0; i < refs.triples_map_reference_triples_reference_triple_record_m_count; i++) {
            ref_triples.push_back(make_reference_triple(&refs.triples_map_reference_triples_reference_triple_record_m[i]));
        }
    }

    std::vector<DependencyTriple> dep_triples;
    if (triples.triples_map_dependency_triples_present) {
        const auto& deps = triples.triples_map_dependency_triples;
        dep_triples.reserve(deps.triples_map_dependency_triples_domain_dependency_triple_record_m_count);
        for (size_t i = 0; i < deps.triples_map_dependency_triples_domain_dependency_triple_record_m_count; i++) {
            dep_triples.push_back(make_dependency_triple(&deps.triples_map_dependency_triples_domain_dependency_triple_record_m[i]));
        }
    }

    return ConciseMidTag(
        std::move(tag_id_str), std::move(language),
        std::move(entities), std::move(ref_triples), std::move(dep_triples)
    );
}

CorimMap::CorimMap(
    std::string id,
    std::unique_ptr<ProfileValue> profile,
    std::unique_ptr<ValidityMap> rim_validity,
    std::vector<ConciseMidTag> tags,
    std::vector<CorimEntity> entities
)
    : m_id(std::move(id))
    , m_profile(std::move(profile))
    , m_rim_validity(std::move(rim_validity))
    , m_tags(std::move(tags))
    , m_entities(std::move(entities))
{}

void log_shadowed_key(const char* dialect, const char* map_name,
                      const SchemaKey& culprit) {
    LOG_ERROR(dialect << " " << map_name << ": key " << culprit.key << " ("
              << culprit.name << ") is malformed, not absent: its value "
              "failed schema validation, so the decoder consumed it as an "
              "unrecognized extension entry");
}

// corim-map members that can be shadowed. id (0) and tags (1) are mandatory,
// so a malformed value there fails the whole map decode instead.
constexpr SchemaKey kCorimMapSchemaKeys[] = {
    {2, "dependent-rims"}, {3, "profile"}, {4, "rim-validity"}, {5, "entities"},
};

static CorimMap make_corim_map(const corim_map* ptr, const CorimParseOptions& options) {
    if (ptr->corim_map_dependent_rims_present) {
        throw UnsupportedCorimFeatureException("CoRIM corim-map dependent-rims field not supported");
    }
    if (ptr->corim_map_extension_key_count > 0) {
        // A shadowed member lands here too, so name it before falling back to
        // the generic message: "extension fields not supported" would send the
        // reader looking for a key the producer never added.
        if (report_shadowed_keys("CoRIM", "corim-map",
                                 ptr->corim_map_extension_key,
                                 ptr->corim_map_extension_key_count,
                                 kCorimMapSchemaKeys)) {
            throw UnsupportedCorimFeatureException(
                "CoRIM corim-map member failed schema validation");
        }
        throw UnsupportedCorimFeatureException("CoRIM corim-map extension fields not supported");
    }

    const auto& id = ptr->corim_map_id;
    std::string id_str;
    if (id.corim_id_type_choice_choice == corim_id_type_choice::corim_id_type_choice_tstr_c) {
        id_str = std::string(
            reinterpret_cast<const char*>(id.corim_id_type_choice_tstr.value),
            id.corim_id_type_choice_tstr.len
        );
    } else {
        id_str = format_uuid(
            id.corim_id_type_choice_uuid_type_m.value,
            id.corim_id_type_choice_uuid_type_m.len
        );
    }

    // Profile must match an entry in the caller-supplied allow-list.
    // Empty allow-list (the default) rejects every profile.
    std::unique_ptr<ProfileValue> profile;
    if (ptr->corim_map_profile_present) {
        ProfileValue parsed = make_profile(&ptr->corim_map_profile.corim_map_profile);
        bool accepted = false;
        for (const auto& matcher : options.accepted_profiles) {
            if (matcher && matcher->matches(parsed)) {
                accepted = true;
                break;
            }
        }
        if (!accepted) {
            const char* kind_str = parsed.kind == ProfileKind::Oid  ? "oid"
                                  : parsed.kind == ProfileKind::Uri ? "uri"
                                                                    : "text";
            throw UnsupportedCorimFeatureException(
                std::string("CoRIM corim-map profile not in accepted set (kind=")
                + kind_str + ", value=" + parsed.value + ")");
        }
        profile.reset(new ProfileValue(std::move(parsed)));
    }

    std::unique_ptr<ValidityMap> rim_validity;
    if (ptr->corim_map_rim_validity_present) {
        rim_validity.reset(new ValidityMap(
            make_validity_map(&ptr->corim_map_rim_validity.corim_map_rim_validity)));
    }

    std::vector<ConciseMidTag> tags;
    for (size_t i = 0; i < ptr->corim_map_tags_concise_tag_type_choice_m_count; i++) {
        const auto& tag = ptr->corim_map_tags_concise_tag_type_choice_m[i];
        if (tag.concise_tag_type_choice_choice == concise_tag_type_choice::concise_tag_type_choice_tagged_concise_mid_tag_m_c) {
            const auto& bstr = tag.concise_tag_type_choice_tagged_concise_mid_tag_m;
            std::unique_ptr<concise_mid_tag> decoded(new concise_mid_tag());
            std::memset(decoded.get(), 0, sizeof(concise_mid_tag));
            size_t len_out = 0;
            int ret = cbor_decode_concise_mid_tag(bstr.value, bstr.len, decoded.get(), &len_out);
            if (ret != 0 || len_out != bstr.len) {
                throw std::invalid_argument(
                    std::string("Failed to decode embedded CoMID tag ")
                    + std::to_string(i)
                    + " (zcbor rc=" + std::to_string(ret)
                    + " (" + zcbor_error_str(ret) + "), consumed="
                    + std::to_string(len_out) + ", expected="
                    + std::to_string(bstr.len) + ")");
            }
            tags.push_back(make_concise_mid_tag(decoded.get()));
        } else {
            LOG_WARN("Skipping unsupported tag type at index " << i << " (e.g. SWID)");
        }
    }

    std::vector<CorimEntity> entities;
    if (ptr->corim_map_entities_present) {
        const auto& en = ptr->corim_map_entities;
        entities.reserve(en.corim_map_entities_corim_entity_map_m_count);
        for (size_t i = 0; i < en.corim_map_entities_corim_entity_map_m_count; i++) {
            entities.push_back(make_corim_entity(&en.corim_map_entities_corim_entity_map_m[i]));
        }
    }

    return CorimMap(
        std::move(id_str), std::move(profile), std::move(rim_validity),
        std::move(tags), std::move(entities)
    );
}

bool MeasurementMapKey::operator==(const MeasurementMapKey& other) const {
    if (type != other.type) { return false; }
    switch (type) {
        case Type::kAbsent: return true;
        case Type::kUint:   return uint_value == other.uint_value;
        case Type::kString:
        case Type::kOid:
        case Type::kUuid:   return str_value == other.str_value;
    }
    return false;
}

bool MeasurementMapKey::operator<(const MeasurementMapKey& other) const {
    if (type != other.type) {
        return static_cast<int>(type) < static_cast<int>(other.type);
    }
    switch (type) {
        case Type::kAbsent: return false;
        case Type::kUint:   return uint_value < other.uint_value;
        case Type::kString:
        case Type::kOid:
        case Type::kUuid:   return str_value < other.str_value;
    }
    return false;
}

std::string MeasurementMapKey::toDisplayString() const {
    switch (type) {
        case Type::kAbsent: return "<absent>";
        case Type::kUint:   return std::to_string(uint_value);
        case Type::kString:
        case Type::kOid:
        case Type::kUuid:   return str_value;
    }
    return std::string();
}

bool MeasurementMapKey::asString(std::string& out) const {
    if (type == Type::kString || type == Type::kOid || type == Type::kUuid) {
        out = str_value;
        return true;
    }
    return false;
}

bool MeasurementMapKey::asUint(uint32_t& out) const {
    if (type == Type::kUint) {
        out = uint_value;
        return true;
    }
    return false;
}


void to_json(nlohmann::json& json_out, const ByteString& byte_str) {
    json_out = byte_str.toBase64();
}

void to_json(nlohmann::json& json_out, const Digest& digest) {
    int32_t alg_int = 0;
    std::string alg_str;
    const char* alg_name = nullptr;

    if (digest.getAlgorithm(alg_int)) {
        alg_name = get_hash_algorithm_name(alg_int);
    } else if (digest.getAlgorithm(alg_str)) {
        alg_name = alg_str.c_str();
    } else {
        alg_name = "unknown";
    }

    json_out = std::string(alg_name) + ";" + digest.getValue().toBase64();
}

void to_json(nlohmann::json& json_out, const FlagsMap& flags) {
    json_out = nlohmann::json::object();
    if (const bool* val = flags.getConfigured())              { json_out["configured"] = *val; }
    if (const bool* val = flags.getSecure())                  { json_out["secure"] = *val; }
    if (const bool* val = flags.getRecovery())                { json_out["recovery"] = *val; }
    if (const bool* val = flags.getDebug())                   { json_out["debug"] = *val; }
    if (const bool* val = flags.getReplayProtected())         { json_out["replay_protected"] = *val; }
    if (const bool* val = flags.getIntegrityProtected())      { json_out["integrity_protected"] = *val; }
    if (const bool* val = flags.getRuntimeMeas())             { json_out["runtime_meas"] = *val; }
    if (const bool* val = flags.getImmutable())               { json_out["immutable"] = *val; }
    if (const bool* val = flags.getTcb())                     { json_out["tcb"] = *val; }
    if (const bool* val = flags.getConfidentialityProtected()){ json_out["confidentiality_protected"] = *val; }
}

void to_json(nlohmann::json& json_out, const Version& ver) {
    if (ver.getSchemeKind() == Version::SchemeKind::kBinary) {
        const std::string& bytes = ver.getValue();
        json_out["value"] = to_hex_string(std::vector<uint8_t>(bytes.begin(), bytes.end()));
        json_out["scheme"] = "binary";
        return;
    }
    json_out["value"] = ver.getValue();
    if (const int32_t* scheme = ver.getScheme()) {
        json_out["scheme"] = *scheme;
    } else if (const std::string* scheme_text = ver.getSchemeText()) {
        json_out["scheme"] = *scheme_text;
    }
}

void to_json(nlohmann::json& json_out, const IntRange& range) {
    int32_t simple_val = 0;
    if (range.isSimpleInt(simple_val)) {
        json_out = simple_val;
    } else {
        bool has_min = false;
        bool has_max = false;
        int32_t min_val = 0;
        int32_t max_val = 0;
        if (range.isRange(has_min, min_val, has_max, max_val)) {
            json_out = nlohmann::json::object();
            if (has_min) {
                json_out["min"] = min_val;
            } else {
                json_out["min"] = "-inf";
            }
            if (has_max) {
                json_out["max"] = max_val;
            } else {
                json_out["max"] = "+inf";
            }
        }
    }
}

void to_json(nlohmann::json& json_out, const MeasurementValues& mval) {
    json_out = nlohmann::json::object();

    const std::string* name = mval.getName();
    if (name != nullptr) { json_out["name"] = *name; }

    const Version* version = mval.getVersion();
    if (version != nullptr) { json_out["version"] = *version; }

    if (const Svn* svn = mval.getSvn()) {
        const char* kind = svn->kind == SvnKind::kMin ? "min" : "exact";
        json_out["svn"] = {{"kind", kind}, {"value", svn->value}};
    }

    const auto& digests = mval.getDigests();
    if (!digests.empty()) { json_out["digests"] = digests; }

    const FlagsMap* flags = mval.getFlags();
    if (flags != nullptr) { json_out["flags"] = *flags; }

    const ByteString* raw_value = mval.getRawValue();
    if (raw_value != nullptr) { json_out["raw_value"] = *raw_value; }

    const ByteString* raw_value_mask = mval.getRawValueMask();
    if (raw_value_mask != nullptr) { json_out["raw_value_mask"] = *raw_value_mask; }

    const IntRange* int_range = mval.getIntRange();
    if (int_range != nullptr) { json_out["int_range"] = *int_range; }

    if (const SpdmIndirectMap* indirect = mval.getSpdmIndirect()) {
        nlohmann::json indirect_j;
        to_json(indirect_j, *indirect);
        json_out["spdm_indirect"] = std::move(indirect_j);
    }
}

void to_json(nlohmann::json& json_out, const MeasurementMapKey& key) {
    switch (key.type) {
        case MeasurementMapKey::Type::kString:
        case MeasurementMapKey::Type::kOid:
        case MeasurementMapKey::Type::kUuid:
            json_out = key.str_value;
            break;
        case MeasurementMapKey::Type::kUint:
            json_out = key.uint_value;
            break;
        case MeasurementMapKey::Type::kAbsent:
            break;
    }
}

void to_json(nlohmann::json& json_out, const MeasurementMap& meas) {
    json_out = nlohmann::json::object();
    auto key = meas.getKey();
    if (key.type != MeasurementMapKey::Type::kAbsent) {
        json_out["key"] = key;
    }
    json_out["values"] = meas.getValues();
}

static std::string class_id_display(const ClassId& cid) {
    const ByteString& bytes = cid.getValue();
    switch (cid.getKind()) {
        case ClassId::Kind::kOid:
            return oid_to_string(bytes.data(), bytes.size());
        case ClassId::Kind::kUuid:
            return format_uuid(bytes.data(), bytes.size());
        case ClassId::Kind::kBytes:
            return "bytes:" + bytes.toBase64();
    }
    return std::string();
}

void to_json(nlohmann::json& json_out, const ClassMap& cls) {
    json_out = nlohmann::json::object();

    const ClassId* class_id = cls.getClassId();
    if (class_id != nullptr) { json_out["class_id"] = class_id_display(*class_id); }

    const std::string* vendor = cls.getVendor();
    if (vendor != nullptr) { json_out["vendor"] = *vendor; }

    const std::string* model = cls.getModel();
    if (model != nullptr) { json_out["model"] = *model; }

    const uint32_t* layer = cls.getLayer();
    if (layer != nullptr) { json_out["layer"] = *layer; }

    const uint32_t* index = cls.getIndex();
    if (index != nullptr) { json_out["index"] = *index; }
}

static std::string instance_id_display(const InstanceId& id) {
    const ByteString& bytes = id.getValue();
    switch (id.getKind()) {
        case InstanceId::Kind::kUuid:
            return format_uuid(bytes.data(), bytes.size());
        case InstanceId::Kind::kUeid:
            return "ueid:" + bytes.toBase64();
        case InstanceId::Kind::kBytes:
            return "bytes:" + bytes.toBase64();
    }
    return std::string();
}

static std::string group_id_display(const GroupId& id) {
    const ByteString& bytes = id.getValue();
    switch (id.getKind()) {
        case GroupId::Kind::kUuid:
            return format_uuid(bytes.data(), bytes.size());
        case GroupId::Kind::kBytes:
            return "bytes:" + bytes.toBase64();
    }
    return std::string();
}

void to_json(nlohmann::json& json_out, const EnvironmentMap& env) {
    json_out = nlohmann::json::object();

    if (const ClassMap* cls = env.getClass()) { json_out["class"] = *cls; }
    if (const InstanceId* instance = env.getInstance()) { json_out["instance"] = instance_id_display(*instance); }
    if (const GroupId* group = env.getGroup()) { json_out["group"] = group_id_display(*group); }
}

void to_json(nlohmann::json& json_out, const ReferenceTriple& ref) {
    json_out = nlohmann::json::object();
    json_out["environment"] = ref.getEnvironment();
    json_out["measurements"] = ref.getMeasurements();
}

void to_json(nlohmann::json& json_out, const DependencyTriple& dep) {
    json_out = nlohmann::json::object();
    json_out["domain_id"] = dep.getDomainId();
    json_out["trustees"] = dep.getTrustees();
}

void to_json(nlohmann::json& json_out, const EntityRole& role) {
    switch (role) {
        case EntityRole::TagCreator: json_out = "tag-creator"; break;
        case EntityRole::Creator: json_out = "creator"; break;
        case EntityRole::Maintainer: json_out = "maintainer"; break;
        default: json_out = "unknown"; break;
    }
}

void to_json(nlohmann::json& json_out, const Entity& entity) {
    json_out = nlohmann::json::object();
    json_out["name"] = entity.getName();

    const std::string* reg_id = entity.getRegId();
    if (reg_id != nullptr) { json_out["reg_id"] = *reg_id; }

    json_out["roles"] = entity.getRoles();
}

void to_json(nlohmann::json& json_out, const CorimRole& role) {
    switch (role) {
        case CorimRole::ManifestCreator: json_out = "manifest-creator"; break;
        case CorimRole::ManifestSigner: json_out = "manifest-signer"; break;
        default: json_out = "unknown"; break;
    }
}

void to_json(nlohmann::json& json_out, const CorimEntity& entity) {
    json_out = nlohmann::json::object();
    json_out["name"] = entity.getName();

    const std::string* reg_id = entity.getRegId();
    if (reg_id != nullptr) { json_out["reg_id"] = *reg_id; }

    json_out["roles"] = entity.getRoles();
}

void to_json(nlohmann::json& json_out, const ValidityMap& validity) {
    json_out = nlohmann::json::object();

    std::chrono::system_clock::time_point nb;
    if (validity.getNotBefore(nb)) {
        auto seconds = std::chrono::system_clock::to_time_t(nb);
        json_out["not_before"] = seconds;
    }

    std::chrono::system_clock::time_point na;
    if (validity.getNotAfter(na)) {
        auto seconds = std::chrono::system_clock::to_time_t(na);
        json_out["not_after"] = seconds;
    }
}

void to_json(nlohmann::json& json_out, const ConciseMidTag& tag) {
    json_out = nlohmann::json::object();
    json_out["tag_id"] = tag.getTagId();

    const std::string* language = tag.getLanguage();
    if (language != nullptr) { json_out["language"] = *language; }

    const auto& entities = tag.getEntities();
    if (!entities.empty()) { json_out["entities"] = entities; }

    const auto& ref_triples = tag.getReferenceTriples();
    if (!ref_triples.empty()) { json_out["reference_triples"] = ref_triples; }

    const auto& dep_triples = tag.getDependencyTriples();
    if (!dep_triples.empty()) { json_out["dependency_triples"] = dep_triples; }
}

void to_json(nlohmann::json& json_out, const CorimMap& corim) {
    json_out = nlohmann::json::object();
    json_out["id"] = corim.getId();
    json_out["tags"] = corim.getCoMidTags();

    if (const ProfileValue* profile = corim.getProfile()) {
        json_out["profile"] = profile_value_to_string(*profile);
    }

    const auto& entities = corim.getEntities();
    if (!entities.empty()) { json_out["entities"] = entities; }

    const ValidityMap* rim_validity = corim.getRimValidity();
    if (rim_validity != nullptr) { json_out["rim_validity"] = *rim_validity; }
}

} // namespace nvattestation
