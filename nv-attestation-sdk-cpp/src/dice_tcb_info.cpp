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

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "nv_attestation/dice_tcb_info.h"
#include "nv_attestation/log.h"
#include "nv_attestation/nv_types.h"
#include "nv_attestation/utils.h"

namespace nvattestation {

// OID constant definitions
const std::string OID_TCG_DICE_TCB_INFO = "2.23.133.5.4.1";
const std::string OID_TCG_DICE_TCB_INFO_ALIAS = "2.23.133.5.4.1.1";
const std::string OID_TCG_DICE_MULTI_TCB_INFO = "2.23.133.5.4.5";
const std::string OID_TCG_DICE_UEID = "2.23.133.5.4.4";

// DER encoding constants (X.690)
static const uint8_t DER_TAG_SEQUENCE = 0x30;
static const uint8_t DER_LENGTH_LONG_FORM = 0x80;
static const uint8_t DER_LENGTH_MASK = 0x7F;
static const int DER_BITS_PER_BYTE = 8;
static const int DER_MAX_BIT_STRING_UINT32_LEN = 5;  // 1 unused-bits byte + 4 value bytes
static const uint8_t DER_CONTEXT_SPECIFIC_CLASS = 0x80;
static const uint8_t DER_CONTEXT_SPECIFIC_MASK = 0xC0;
static const uint8_t DER_TAG_NUMBER_MASK = 0x1F;

// DiceTcbInfo IMPLICIT context-specific tag numbers (per TCG DICE Attestation Architecture v1.2)
static const int TAG_VENDOR = 0;
static const int TAG_MODEL = 1;
static const int TAG_VERSION = 2;
static const int TAG_SVN = 3;
static const int TAG_LAYER = 4;
static const int TAG_INDEX = 5;
static const int TAG_FWIDS = 6;
static const int TAG_FLAGS = 7;
static const int TAG_VENDOR_INFO = 8;
static const int TAG_TYPE = 9;
static const int TAG_FLAGS_MASK = 10;
static const int TAG_INTEGRITY_REGISTERS = 11;

// IntegrityRegister IMPLICIT context-specific tag numbers
static const int IR_TAG_REGISTER_NAME = 0;
static const int IR_TAG_REGISTER_NUM = 1;
static const int IR_TAG_REGISTER_DIGESTS = 2;

// Convert an ASN1_OBJECT to a dotted-notation OID string
static std::string asn1_object_to_oid_string(const ASN1_OBJECT* obj, LogLevel err_lvl) {
    char buf[256];  // NOLINT(readability-magic-numbers)
    int len = OBJ_obj2txt(buf, sizeof(buf), obj, 1);  // 1 = numeric form
    if (len <= 0) {
        return "";
    }
    if (static_cast<size_t>(len) >= sizeof(buf)) {
        LOG_AT_LEVEL(err_lvl, "OID string was truncated (needed " << len << " bytes, buffer is " << sizeof(buf) << ")");
        return "";
    }
    return std::string(buf, static_cast<size_t>(len));
}

// Parse a single FWID from DER bytes: SEQUENCE { OID, OCTET STRING }
static Error parse_fwid_from_der(const unsigned char* data, long length, FWID& out, LogLevel err_lvl) {
    const unsigned char* ptr = data;
    nv_unique_ptr<ASN1_SEQUENCE_ANY> fwid_seq(d2i_ASN1_SEQUENCE_ANY(nullptr, &ptr, length));
    if (!fwid_seq) {
        LOG_AT_LEVEL(err_lvl, "Failed to parse FWID SEQUENCE");
        return Error::InternalError;
    }

    if (sk_ASN1_TYPE_num(fwid_seq.get()) < 2) {
        LOG_AT_LEVEL(err_lvl, "FWID SEQUENCE must have at least 2 elements (OID + OCTET STRING)");
        return Error::InternalError;
    }

    // Element 0: hash algorithm OID
    ASN1_TYPE* hash_alg_type = sk_ASN1_TYPE_value(fwid_seq.get(), 0);
    if (hash_alg_type == nullptr || hash_alg_type->type != V_ASN1_OBJECT) {
        LOG_AT_LEVEL(err_lvl, "FWID element 0 is not an OID");
        return Error::InternalError;
    }
    std::string oid_str = asn1_object_to_oid_string(hash_alg_type->value.object, err_lvl);

    // Element 1: digest OCTET STRING
    ASN1_TYPE* digest_type = sk_ASN1_TYPE_value(fwid_seq.get(), 1);
    if (digest_type == nullptr || digest_type->type != V_ASN1_OCTET_STRING) {
        LOG_AT_LEVEL(err_lvl, "FWID element 1 is not an OCTET STRING");
        return Error::InternalError;
    }
    const unsigned char* digest_data = ASN1_STRING_get0_data(digest_type->value.octet_string);
    int digest_len = ASN1_STRING_length(digest_type->value.octet_string);
    if (digest_data == nullptr || digest_len < 0) {
        LOG_AT_LEVEL(err_lvl, "FWID digest data is null or has invalid length");
        return Error::InternalError;
    }
    std::vector<uint8_t> digest(digest_data, digest_data + digest_len);

    out = FWID(oid_str, digest);
    return Error::Ok;
}

// Extract raw DER bytes from an X.509 certificate extension identified by OID.
// Shared helper used by CompositeDeviceId, DiceTcbInfo, and MultiDiceTcbInfo.
// When `silent`, "extension absent" cases log at TRACE so callers that probe
// many certs / OIDs don't pollute the log with ERRORs or DEBUGs.
static Error get_extension_der_bytes(const void* x509_cert, const std::string& oid, std::vector<uint8_t>& out,
                                     bool silent = false) {
    LogLevel absent_lvl = silent ? LogLevel::TRACE : LogLevel::ERROR;
    if (x509_cert == nullptr) {
        LOG_ERROR("x509_cert is null");
        return Error::InternalError;
    }

    const X509* cert = static_cast<const X509*>(x509_cert);

    nv_unique_ptr<ASN1_OBJECT> obj(OBJ_txt2obj(oid.c_str(), 0));
    if (!obj) {
        LOG_AT_LEVEL(absent_lvl, "Could not convert OID string to ASN1_OBJECT: " << oid);
        return Error::CertFwidNotFound;
    }

    int loc = X509_get_ext_by_OBJ(cert, obj.get(), -1);
    if (loc < 0) {
        LOG_AT_LEVEL(absent_lvl, "Extension with OID " << oid << " not found in certificate");
        return Error::CertFwidNotFound;
    }

    X509_EXTENSION* ext = X509_get_ext(cert, loc);
    if (ext == nullptr) {
        LOG_ERROR("Could not retrieve extension at location " << loc);
        return Error::InternalError;
    }

    ASN1_OCTET_STRING* octet_str = X509_EXTENSION_get_data(ext);
    if (octet_str == nullptr) {
        LOG_ERROR("Could not get data from extension");
        return Error::InternalError;
    }

    const unsigned char* data = ASN1_STRING_get0_data(octet_str);
    int length = ASN1_STRING_length(octet_str);

    if (data == nullptr || length <= 0) {
        LOG_ERROR("Extension data is empty");
        return Error::InternalError;
    }

    out.assign(data, data + length);
    return Error::Ok;
}

// --- CompositeDeviceId ---

Error CompositeDeviceId::parse_from_der(const std::vector<uint8_t>& der, CompositeDeviceId& out) {
    if (der.empty()) {
        LOG_DEBUG("CompositeDeviceId DER data is empty");
        return Error::InternalError;
    }

    // CompositeDeviceID is wrapped in: SEQUENCE { OID, SEQUENCE CompositeDeviceID }
    // The extension value contains this outer wrapper.
    const unsigned char* ptr = der.data();
    nv_unique_ptr<ASN1_SEQUENCE_ANY> outer_seq(d2i_ASN1_SEQUENCE_ANY(nullptr, &ptr, static_cast<long>(der.size())));
    if (!outer_seq) {
        LOG_DEBUG("Failed to parse CompositeDeviceId outer SEQUENCE");
        return Error::InternalError;
    }

    int num_outer = sk_ASN1_TYPE_num(outer_seq.get());
    if (num_outer < 2) {
        LOG_DEBUG("CompositeDeviceId outer SEQUENCE must have at least 2 elements (OID + SEQUENCE)");
        return Error::InternalError;
    }

    // Element 0: OID (2.23.133.5.4.1)
    ASN1_TYPE* oid_elem = sk_ASN1_TYPE_value(outer_seq.get(), 0);
    if (oid_elem == nullptr || oid_elem->type != V_ASN1_OBJECT) {
        LOG_DEBUG("CompositeDeviceId element 0 is not an OID");
        return Error::InternalError;
    }

    // Element 1: SEQUENCE CompositeDeviceID { version, SubjectPublicKeyInfo, FWID }
    ASN1_TYPE* inner_elem = sk_ASN1_TYPE_value(outer_seq.get(), 1);
    if (inner_elem == nullptr || inner_elem->type != V_ASN1_SEQUENCE) {
        LOG_DEBUG("CompositeDeviceId element 1 is not a SEQUENCE");
        return Error::InternalError;
    }

    const unsigned char* inner_data = ASN1_STRING_get0_data(inner_elem->value.sequence);
    int inner_len = ASN1_STRING_length(inner_elem->value.sequence);
    if (inner_data == nullptr || inner_len <= 0) {
        LOG_DEBUG("CompositeDeviceId inner SEQUENCE data is null or empty");
        return Error::InternalError;
    }

    const unsigned char* qtr = inner_data;
    nv_unique_ptr<ASN1_SEQUENCE_ANY> inner_seq(d2i_ASN1_SEQUENCE_ANY(nullptr, &qtr, inner_len));
    if (!inner_seq) {
        LOG_DEBUG("Failed to parse CompositeDeviceId inner SEQUENCE");
        return Error::InternalError;
    }

    int num_inner = sk_ASN1_TYPE_num(inner_seq.get());
    if (num_inner < 3) {
        LOG_DEBUG("CompositeDeviceId inner SEQUENCE must have at least 3 elements");
        return Error::InternalError;
    }

    CompositeDeviceId result;

    // Element 0: version INTEGER
    ASN1_TYPE* version_elem = sk_ASN1_TYPE_value(inner_seq.get(), 0);
    if (version_elem == nullptr || version_elem->type != V_ASN1_INTEGER) {
        LOG_DEBUG("CompositeDeviceId: version is not an INTEGER");
        return Error::InternalError;
    }
    result.m_version = ASN1_INTEGER_get(version_elem->value.integer);

    // Element 1: SubjectPublicKeyInfo SEQUENCE — store as raw DER bytes
    ASN1_TYPE* spki_elem = sk_ASN1_TYPE_value(inner_seq.get(), 1);
    if (spki_elem == nullptr || spki_elem->type != V_ASN1_SEQUENCE) {
        LOG_DEBUG("CompositeDeviceId: SubjectPublicKeyInfo is not a SEQUENCE");
        return Error::InternalError;
    }
    const unsigned char* spki_data = ASN1_STRING_get0_data(spki_elem->value.sequence);
    int spki_len = ASN1_STRING_length(spki_elem->value.sequence);
    if (spki_data != nullptr && spki_len > 0) {
        result.m_subject_public_key_info.assign(spki_data, spki_data + spki_len);
    }

    // Element 2: FWID SEQUENCE { hashAlg OID, digest OCTET STRING }
    ASN1_TYPE* fwid_elem = sk_ASN1_TYPE_value(inner_seq.get(), 2);
    if (fwid_elem == nullptr || fwid_elem->type != V_ASN1_SEQUENCE) {
        LOG_DEBUG("CompositeDeviceId: FWID is not a SEQUENCE");
        return Error::InternalError;
    }
    const unsigned char* fwid_data = ASN1_STRING_get0_data(fwid_elem->value.sequence);
    int fwid_len = ASN1_STRING_length(fwid_elem->value.sequence);
    if (fwid_data == nullptr || fwid_len <= 0) {
        LOG_DEBUG("CompositeDeviceId: FWID data is null or empty");
        return Error::InternalError;
    }

    Error err = parse_fwid_from_der(fwid_data, fwid_len, result.m_fwid, LogLevel::DEBUG);
    if (err != Error::Ok) {
        return err;
    }

    out = std::move(result);
    return Error::Ok;
}

Error CompositeDeviceId::parse_from_x509_extension(const void* x509_cert, CompositeDeviceId& out) {
    std::vector<uint8_t> der_bytes;
    // Note: get_extension_der_bytes logs at LOG_ERROR (canonical path).
    // parse_from_der logs at LOG_DEBUG unconditionally — if this method is ever called from a
    // canonical (non-probe) context, extend the silent-flag pattern to CompositeDeviceId as well.
    Error err = get_extension_der_bytes(x509_cert, OID_TCG_DICE_TCB_INFO, der_bytes);
    if (err != Error::Ok) {
        return err;
    }
    return CompositeDeviceId::parse_from_der(der_bytes, out);
}

// Parse the FWID list (tag [6]) from the inner bytes of the context-specific element.
// The bytes are: SEQUENCE { FWID1 } SEQUENCE { FWID2 } ...
// But because the outer element is IMPLICIT [6] CONSTRUCTED, the data we get is the
// content of SEQUENCE OF FWID, i.e. concatenated DER-encoded FWID sequences.
static Error parse_fwid_list(const unsigned char* data, int length, std::vector<FWID>& out, LogLevel err_lvl) {
    if (length < 0) {
        LOG_AT_LEVEL(err_lvl, "FWID list has invalid length");
        return Error::InternalError;
    }
    const unsigned char* ptr = data;
    const unsigned char* end = data + length;

    while (ptr < end) {
        // Each FWID is a SEQUENCE. Read its tag and length to know how many bytes to consume.
        if (*ptr != DER_TAG_SEQUENCE) {
            LOG_AT_LEVEL(err_lvl, "Expected SEQUENCE tag (0x30) for FWID, got 0x" << to_hex_string(static_cast<uint8_t>(*ptr)));
            return Error::InternalError;
        }

        const unsigned char* seq_start = ptr;
        ptr++;  // skip tag byte

        if (ptr >= end) {
            LOG_AT_LEVEL(err_lvl, "FWID list truncated after SEQUENCE tag");
            return Error::InternalError;
        }

        // Parse length
        long content_len = 0;
        if ((*ptr & DER_LENGTH_LONG_FORM) != 0) {
            int num_len_bytes = *ptr & DER_LENGTH_MASK;
            ptr++;
            if (num_len_bytes == 0 || num_len_bytes > 4 || ptr + num_len_bytes > end) {
                LOG_AT_LEVEL(err_lvl, "FWID SEQUENCE has invalid multi-byte length encoding");
                return Error::InternalError;
            }
            for (int i = 0; i < num_len_bytes; i++) {
                content_len = (content_len << DER_BITS_PER_BYTE) | *ptr;
                ptr++;
            }
            // Guard against sign wrap on platforms where long is 32 bits
            if (content_len < 0) {
                LOG_AT_LEVEL(err_lvl, "FWID SEQUENCE has invalid (overflow) length");
                return Error::InternalError;
            }
        } else {
            content_len = *ptr;
            ptr++;
        }

        long total_len = (ptr - seq_start) + content_len;
        if (seq_start + total_len > end) {
            LOG_AT_LEVEL(err_lvl, "FWID SEQUENCE content extends past end of FWID list");
            return Error::InternalError;
        }

        FWID fwid;
        Error err = parse_fwid_from_der(seq_start, total_len, fwid, err_lvl);
        if (err != Error::Ok) {
            return err;
        }
        out.push_back(fwid);

        ptr = seq_start + total_len;
    }

    return Error::Ok;
}

// Extract an INTEGER value from the raw bytes of an IMPLICIT context-specific element.
// The bytes are the BER/DER encoding of the integer value (big-endian, possibly with sign byte).
static Error parse_implicit_integer(const unsigned char* data, int length, int64_t& out, LogLevel err_lvl) {
    if (length <= 0 || length > static_cast<int>(sizeof(int64_t))) {
        LOG_AT_LEVEL(err_lvl, "IMPLICIT INTEGER has invalid length: " << length);
        return Error::InternalError;
    }
    // Accumulate in unsigned to avoid UB from left-shifting negative values,
    // then reinterpret as signed at the end.
    uint64_t uvalue = 0;
    if ((data[0] & DER_LENGTH_LONG_FORM) != 0) {
        uvalue = ~static_cast<uint64_t>(0);  // sign-extend for negative
    }
    for (int i = 0; i < length; i++) {
        uvalue = (uvalue << DER_BITS_PER_BYTE) | data[i];
    }
    out = static_cast<int64_t>(uvalue);
    return Error::Ok;
}

// Parse a DER length field. Advances ptr past the length bytes.
// Returns the content length, or -1 on error.
static long parse_der_length(const unsigned char*& ptr, const unsigned char* end) {
    if (ptr >= end) {
        return -1;
    }
    if ((*ptr & DER_LENGTH_LONG_FORM) == 0) {
        // Short form: length is the byte itself
        long len = *ptr;
        ptr++;
        return len;
    }
    int num_bytes = *ptr & DER_LENGTH_MASK;
    ptr++;
    if (num_bytes == 0 || num_bytes > 4 || ptr + num_bytes > end) {
        return -1;
    }
    long len = 0;
    for (int i = 0; i < num_bytes; i++) {
        len = (len << DER_BITS_PER_BYTE) | *ptr;
        ptr++;
    }
    // Guard against sign wrap on platforms where long is 32 bits
    if (len < 0) {
        return -1;
    }
    return len;
}

// Parse an IMPLICIT BIT STRING into a uint32_t.
// Per X.690, the first byte is the number of unused bits in the final octet;
// those trailing bits must be masked off.
static Error parse_implicit_bit_string(const unsigned char* content, long content_len,
                                       const char* field_name, std::unique_ptr<uint32_t>& out,
                                       LogLevel err_lvl) {
    if (content_len < 1) {
        LOG_AT_LEVEL(err_lvl, field_name << " BIT STRING is too short");
        return Error::InternalError;
    }
    // 1 byte for unused_bits + at most 4 bytes for uint32_t value
    if (content_len > DER_MAX_BIT_STRING_UINT32_LEN) {
        LOG_AT_LEVEL(err_lvl, field_name << " BIT STRING too long for uint32_t: " << content_len << " bytes");
        return Error::InternalError;
    }
    uint8_t unused_bits = content[0];
    if (unused_bits > 7) {  // NOLINT(readability-magic-numbers)
        LOG_AT_LEVEL(err_lvl, field_name << " BIT STRING has invalid unused bits value: " << static_cast<int>(unused_bits));
        return Error::InternalError;
    }
    uint32_t value = 0;
    for (long bi = 1; bi < content_len; bi++) {
        value = (value << DER_BITS_PER_BYTE) | content[bi];
    }
    // Zero out the unused trailing bits in the last octet (per X.690 §8.6)
    if (unused_bits > 0 && content_len > 1) {
        value &= ~((1U << unused_bits) - 1U);
    }
    out = std::make_unique<uint32_t>(value);
    return Error::Ok;
}

// Parse a single IntegrityRegister from DER bytes within the IMPLICIT [11] content.
// IntegrityRegister ::= SEQUENCE {
//   registerName    [0] IMPLICIT IA5String OPTIONAL,
//   registerNum     [1] IMPLICIT INTEGER OPTIONAL,
//   registerDigests [2] IMPLICIT FWIDLIST
// }
static Error parse_integrity_register(const unsigned char* data, long length, IntegrityRegister& out,
                                      LogLevel err_lvl) {
    const unsigned char* ptr = data;
    const unsigned char* reg_end = data + length;
    IntegrityRegister result;

    while (ptr < reg_end) {
        uint8_t tag_byte = *ptr;
        ptr++;

        long content_len = parse_der_length(ptr, reg_end);
        if (content_len < 0 || ptr + content_len > reg_end) {
            LOG_AT_LEVEL(err_lvl, "IntegrityRegister: invalid element length at tag 0x" << to_hex_string(tag_byte));
            return Error::InternalError;
        }

        const unsigned char* content = ptr;
        ptr += content_len;

        if ((tag_byte & DER_CONTEXT_SPECIFIC_MASK) != DER_CONTEXT_SPECIFIC_CLASS) {
            continue;
        }

        int tag_number = tag_byte & DER_TAG_NUMBER_MASK;

        switch (tag_number) {
            case IR_TAG_REGISTER_NAME:
                result.set_register_name(std::string(
                    reinterpret_cast<const char*>(content), static_cast<size_t>(content_len)));
                break;

            case IR_TAG_REGISTER_NUM: {
                int64_t num_val = 0;
                Error err = parse_implicit_integer(content, static_cast<int>(content_len), num_val, err_lvl);
                if (err != Error::Ok) {
                    return err;
                }
                result.set_register_num(num_val);
                break;
            }

            case IR_TAG_REGISTER_DIGESTS: {
                std::vector<FWID> digests;
                Error err = parse_fwid_list(content, static_cast<int>(content_len), digests, err_lvl);
                if (err != Error::Ok) {
                    return err;
                }
                result.set_register_digests(digests);
                break;
            }

            default:
                LOG_INFO("Skipping unsupported IntegrityRegister tag [" << tag_number << "]");
                break;
        }
    }

    // registerDigests [2] is required per TCG DICE Attestation Architecture v1.2 section 6.1.1.4
    if (result.register_digests().empty()) {
        LOG_AT_LEVEL(err_lvl, "IntegrityRegister missing required registerDigests field");
        return Error::InternalError;
    }

    out = std::move(result);
    return Error::Ok;
}

// Parse an IrList (tag [11]) from the inner bytes of the context-specific element.
// IrList ::= SEQUENCE SIZE (1..MAX) OF IntegrityRegister
// Since tag [11] is IMPLICIT CONSTRUCTED, the content is concatenated DER-encoded
// IntegrityRegister SEQUENCEs (same pattern as parse_fwid_list).
static Error parse_integrity_register_list(const unsigned char* data, int length,
                                           std::vector<IntegrityRegister>& out, LogLevel err_lvl) {
    if (length < 0) {
        LOG_AT_LEVEL(err_lvl, "IntegrityRegister list has invalid length");
        return Error::InternalError;
    }
    const unsigned char* ptr = data;
    const unsigned char* end = data + length;

    while (ptr < end) {
        if (*ptr != DER_TAG_SEQUENCE) {
            LOG_AT_LEVEL(err_lvl, "Expected SEQUENCE tag (0x30) for IntegrityRegister, got 0x"
                         << to_hex_string(static_cast<uint8_t>(*ptr)));
            return Error::InternalError;
        }

        ptr++;  // skip SEQUENCE tag

        if (ptr >= end) {
            LOG_AT_LEVEL(err_lvl, "IntegrityRegister list truncated after SEQUENCE tag");
            return Error::InternalError;
        }

        long content_len = parse_der_length(ptr, end);
        if (content_len < 0 || ptr + content_len > end) {
            LOG_AT_LEVEL(err_lvl, "IntegrityRegister SEQUENCE has invalid length");
            return Error::InternalError;
        }

        IntegrityRegister reg;
        Error err = parse_integrity_register(ptr, content_len, reg, err_lvl);
        if (err != Error::Ok) {
            return err;
        }
        out.push_back(std::move(reg));

        ptr += content_len;
    }

    return Error::Ok;
}

// Manual DER TLV walking is required here because OpenSSL's high-level decoder
// (d2i_ASN1_SEQUENCE_ANY) does not preserve IMPLICIT context-specific tags — it reports
// them as V_ASN1_OTHER, losing the tag number needed to identify each DiceTcbInfo field.
// OpenSSL has no built-in schema for the TCG DICE DiceTcbInfo structure, so there is no
// d2i_DiceTcbInfo function to call. The alternative would be writing a full ASN.1 module
// definition and compiling it with OpenSSL's ASN1_ITEM machinery, which is significantly
// more complex than the ~60 lines of TLV walking below.
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
Error DiceTcbInfo::parse_from_der(const std::vector<uint8_t>& der, DiceTcbInfo& out, bool silent) { // NOSONAR cpp:S3776
    const LogLevel err_lvl = silent ? LogLevel::DEBUG : LogLevel::ERROR;

    if (der.empty()) {
        LOG_AT_LEVEL(err_lvl, "DiceTcbInfo DER data is empty");
        return Error::InternalError;
    }

    const unsigned char* ptr = der.data();
    const unsigned char* end = ptr + der.size();

    // Expect outer SEQUENCE tag (0x30)
    if (*ptr != DER_TAG_SEQUENCE) {
        LOG_AT_LEVEL(err_lvl, "DiceTcbInfo: expected SEQUENCE tag 0x30, got 0x" << to_hex_string(static_cast<uint8_t>(*ptr)));
        return Error::InternalError;
    }
    ptr++;

    long seq_len = parse_der_length(ptr, end);
    if (seq_len < 0 || ptr + seq_len > end) {
        LOG_AT_LEVEL(err_lvl, "DiceTcbInfo: invalid SEQUENCE length");
        return Error::InternalError;
    }

    const unsigned char* seq_end = ptr + seq_len;
    DiceTcbInfo result;
    int context_specific_tags_found = 0;

    // Walk TLV elements inside the SEQUENCE
    while (ptr < seq_end) {
        uint8_t tag_byte = *ptr;
        ptr++;

        long content_len = parse_der_length(ptr, seq_end);
        if (content_len < 0 || ptr + content_len > seq_end) {
            LOG_AT_LEVEL(err_lvl, "DiceTcbInfo: invalid element length at tag 0x" << to_hex_string(tag_byte));
            return Error::InternalError;
        }

        const unsigned char* content = ptr;
        ptr += content_len;

        // Check for context-specific class (bits 7-6 = 10)
        if ((tag_byte & DER_CONTEXT_SPECIFIC_MASK) != DER_CONTEXT_SPECIFIC_CLASS) {
            LOG_AT_LEVEL(err_lvl, "Skipping non-context-specific element with tag 0x" << to_hex_string(tag_byte));
            continue;
        }

        context_specific_tags_found++;
        int tag_number = tag_byte & DER_TAG_NUMBER_MASK;

        switch (tag_number) {
            case TAG_VENDOR:
                result.m_vendor = std::make_unique<std::string>(
                    reinterpret_cast<const char*>(content), static_cast<size_t>(content_len));
                break;

            case TAG_MODEL:
                result.m_model = std::make_unique<std::string>(
                    reinterpret_cast<const char*>(content), static_cast<size_t>(content_len));
                break;

            case TAG_VERSION:
                result.m_version = std::make_unique<std::string>(
                    reinterpret_cast<const char*>(content), static_cast<size_t>(content_len));
                break;

            case TAG_SVN: {
                int64_t int_val = 0;
                Error err = parse_implicit_integer(content, static_cast<int>(content_len), int_val, err_lvl);
                if (err != Error::Ok) {
                    return err;
                }
                result.m_svn = std::make_unique<int64_t>(int_val);
                break;
            }

            case TAG_LAYER: {
                int64_t int_val = 0;
                Error err = parse_implicit_integer(content, static_cast<int>(content_len), int_val, err_lvl);
                if (err != Error::Ok) {
                    return err;
                }
                result.m_layer = std::make_unique<int64_t>(int_val);
                break;
            }

            case TAG_INDEX: {
                int64_t int_val = 0;
                Error err = parse_implicit_integer(content, static_cast<int>(content_len), int_val, err_lvl);
                if (err != Error::Ok) {
                    return err;
                }
                result.m_index = std::make_unique<int64_t>(int_val);
                break;
            }

            case TAG_FWIDS: {
                Error err = parse_fwid_list(content, static_cast<int>(content_len), result.m_fwids, err_lvl);
                if (err != Error::Ok) {
                    return err;
                }
                break;
            }

            case TAG_FLAGS: {
                Error err = parse_implicit_bit_string(content, content_len, "flags", result.m_flags, err_lvl);
                if (err != Error::Ok) {
                    return err;
                }
                break;
            }

            case TAG_VENDOR_INFO:
                result.m_vendor_info.assign(content, content + content_len);
                break;

            case TAG_TYPE:
                result.m_type.assign(content, content + content_len);
                break;

            case TAG_FLAGS_MASK: {
                Error err = parse_implicit_bit_string(content, content_len, "flags_mask", result.m_flags_mask, err_lvl);
                if (err != Error::Ok) {
                    return err;
                }
                break;
            }

            case TAG_INTEGRITY_REGISTERS: {
                Error err = parse_integrity_register_list(content, static_cast<int>(content_len),
                                                         result.m_integrity_registers, err_lvl);
                if (err != Error::Ok) {
                    return err;
                }
                break;
            }

            default:
                LOG_INFO("Skipping unsupported DiceTcbInfo tag [" << tag_number << "]");
                break;
        }
    }

    // If no context-specific tags were found, this is not a DiceTcbInfo structure.
    // This distinguishes DiceTcbInfo from CompositeDeviceID (OID 2.23.133.5.4.1 ambiguity).
    if (context_specific_tags_found == 0) {
        LOG_AT_LEVEL(err_lvl, "No context-specific tags found in SEQUENCE — not a DiceTcbInfo");
        return Error::InternalError;
    }

    out = std::move(result);
    return Error::Ok;
}

Error DiceTcbInfo::parse_from_x509_extension(const void* x509_cert, const std::string& oid, DiceTcbInfo& out,
                                             bool silent) {
    std::vector<uint8_t> der_bytes;
    Error err = get_extension_der_bytes(x509_cert, oid, der_bytes, silent);
    if (err != Error::Ok) {
        return err;
    }
    return DiceTcbInfo::parse_from_der(der_bytes, out, silent);
}

Error DiceTcbInfo::get_first_fwid_digest(std::vector<uint8_t>& out) const {
    if (m_fwids.empty()) {
        LOG_ERROR("No FWIDs present in DiceTcbInfo");
        return Error::CertFwidNotFound;
    }
    out = m_fwids[0].digest();
    return Error::Ok;
}

// Deep-copy helper for unique_ptr fields
template<typename T>
static std::unique_ptr<T> clone_unique_ptr(const std::unique_ptr<T>& src) {
    if (src) {
        return std::make_unique<T>(*src);
    }
    return nullptr;
}

DiceTcbInfo::DiceTcbInfo(const DiceTcbInfo& other)
    : m_vendor(clone_unique_ptr(other.m_vendor)),
      m_model(clone_unique_ptr(other.m_model)),
      m_version(clone_unique_ptr(other.m_version)),
      m_svn(clone_unique_ptr(other.m_svn)),
      m_layer(clone_unique_ptr(other.m_layer)),
      m_index(clone_unique_ptr(other.m_index)),
      m_fwids(other.m_fwids),
      m_flags(clone_unique_ptr(other.m_flags)),
      m_flags_mask(clone_unique_ptr(other.m_flags_mask)),
      m_integrity_registers(other.m_integrity_registers),
      m_vendor_info(other.m_vendor_info),
      m_type(other.m_type) {}

DiceTcbInfo& DiceTcbInfo::operator=(const DiceTcbInfo& other) {
    if (this != &other) {
        m_vendor = clone_unique_ptr(other.m_vendor);
        m_model = clone_unique_ptr(other.m_model);
        m_version = clone_unique_ptr(other.m_version);
        m_svn = clone_unique_ptr(other.m_svn);
        m_layer = clone_unique_ptr(other.m_layer);
        m_index = clone_unique_ptr(other.m_index);
        m_fwids = other.m_fwids;
        m_flags = clone_unique_ptr(other.m_flags);
        m_flags_mask = clone_unique_ptr(other.m_flags_mask);
        m_integrity_registers = other.m_integrity_registers;
        m_vendor_info = other.m_vendor_info;
        m_type = other.m_type;
    }
    return *this;
}

bool DiceTcbInfo::operator==(const DiceTcbInfo& other) const {
    return compare_unique_ptr(m_vendor, other.m_vendor) &&
           compare_unique_ptr(m_model, other.m_model) &&
           compare_unique_ptr(m_version, other.m_version) &&
           compare_unique_ptr(m_svn, other.m_svn) &&
           compare_unique_ptr(m_layer, other.m_layer) &&
           compare_unique_ptr(m_index, other.m_index) &&
           m_fwids == other.m_fwids &&
           compare_unique_ptr(m_flags, other.m_flags) &&
           compare_unique_ptr(m_flags_mask, other.m_flags_mask) &&
           m_integrity_registers == other.m_integrity_registers &&
           m_vendor_info == other.m_vendor_info &&
           m_type == other.m_type;
}

// --- MultiDiceTcbInfo ---

Error MultiDiceTcbInfo::parse_from_der(const std::vector<uint8_t>& der, MultiDiceTcbInfo& out) {
    if (der.empty()) {
        LOG_ERROR("MultiDiceTcbInfo DER data is empty");
        return Error::InternalError;
    }

    // MultiDiceTcbInfo is SEQUENCE OF DiceTcbInfo.
    // The outer SEQUENCE wraps inner SEQUENCEs, each being a DiceTcbInfo.
    const unsigned char* ptr = der.data();
    nv_unique_ptr<ASN1_SEQUENCE_ANY> outer_seq(d2i_ASN1_SEQUENCE_ANY(nullptr, &ptr, static_cast<long>(der.size())));
    if (!outer_seq) {
        LOG_ERROR("Failed to parse MultiDiceTcbInfo outer SEQUENCE from DER");
        return Error::InternalError;
    }

    MultiDiceTcbInfo result;
    int num_elements = sk_ASN1_TYPE_num(outer_seq.get());

    for (int i = 0; i < num_elements; i++) {
        ASN1_TYPE* elem = sk_ASN1_TYPE_value(outer_seq.get(), i);
        if (elem == nullptr || elem->type != V_ASN1_SEQUENCE) {
            LOG_ERROR("MultiDiceTcbInfo element " << i << " is not a SEQUENCE");
            return Error::InternalError;
        }

        // For V_ASN1_SEQUENCE elements in ASN1_SEQUENCE_ANY, OpenSSL stores the content
        // bytes of the outer SEQUENCE. Since the outer SEQUENCE's content is a concatenation
        // of inner DiceTcbInfo SEQUENCE TLVs, each element contains a complete inner
        // SEQUENCE including its tag + length + content.
        const unsigned char* seq_data = ASN1_STRING_get0_data(elem->value.sequence);
        int seq_len = ASN1_STRING_length(elem->value.sequence);

        if (seq_data == nullptr || seq_len <= 0) {
            LOG_ERROR("MultiDiceTcbInfo element " << i << " has null or empty SEQUENCE data");
            return Error::InternalError;
        }

        std::vector<uint8_t> entry_der(seq_data, seq_data + seq_len);

        DiceTcbInfo entry;
        Error err = DiceTcbInfo::parse_from_der(entry_der, entry);
        if (err != Error::Ok) {
            LOG_ERROR("Failed to parse DiceTcbInfo entry " << i);
            return err;
        }
        result.m_entries.push_back(std::move(entry));
    }

    out = std::move(result);
    return Error::Ok;
}

Error MultiDiceTcbInfo::parse_from_x509_extension(const void* x509_cert, MultiDiceTcbInfo& out, bool silent) {
    std::vector<uint8_t> der_bytes;
    Error err = get_extension_der_bytes(x509_cert, OID_TCG_DICE_MULTI_TCB_INFO, der_bytes, silent);
    if (err != Error::Ok) {
        return err;
    }
    return MultiDiceTcbInfo::parse_from_der(der_bytes, out);
}

// Strip `SEQUENCE { ueid OCTET STRING }` to inner octets. Short-form lengths only.
Error parse_dice_ueid_from_x509_extension(const void* x509_cert,
                                          std::vector<uint8_t>& out,
                                          bool silent) {
    std::vector<uint8_t> der_bytes;
    Error err = get_extension_der_bytes(x509_cert, OID_TCG_DICE_UEID, der_bytes, silent);
    if (err != Error::Ok) {
        return err;
    }
    LogLevel err_lvl = silent ? LogLevel::DEBUG : LogLevel::ERROR;
    if (der_bytes.size() < 4 || der_bytes[0] != DER_TAG_SEQUENCE) {
        LOG_AT_LEVEL(err_lvl, "DiceUeid: outer SEQUENCE missing");
        return Error::InternalError;
    }
    size_t outer_len = der_bytes[1];
    size_t inner_off = 2;
    if ((outer_len & DER_LENGTH_LONG_FORM) != 0U) {
        LOG_AT_LEVEL(err_lvl, "DiceUeid: long-form length not supported");
        return Error::InternalError;
    }
    if (der_bytes.size() < inner_off + outer_len) {
        LOG_AT_LEVEL(err_lvl, "DiceUeid: outer length exceeds buffer");
        return Error::InternalError;
    }
    if (der_bytes[inner_off] != 0x04) {
        LOG_AT_LEVEL(err_lvl, "DiceUeid: inner is not OCTET STRING");
        return Error::InternalError;
    }
    size_t inner_len = der_bytes[inner_off + 1];
    if ((inner_len & DER_LENGTH_LONG_FORM) != 0U) {
        LOG_AT_LEVEL(err_lvl, "DiceUeid: inner long-form length not supported");
        return Error::InternalError;
    }
    if (inner_off + 2 + inner_len > der_bytes.size()) {
        LOG_AT_LEVEL(err_lvl, "DiceUeid: inner length exceeds buffer");
        return Error::InternalError;
    }
    const auto inner_data_off = static_cast<std::ptrdiff_t>(inner_off + 2);
    const auto inner_data_end = static_cast<std::ptrdiff_t>(inner_off + 2 + inner_len);
    out.assign(der_bytes.begin() + inner_data_off,
               der_bytes.begin() + inner_data_end);
    return Error::Ok;
}

// --- IntegrityRegister ---

IntegrityRegister::IntegrityRegister(const IntegrityRegister& other)
    : m_register_name(clone_unique_ptr(other.m_register_name)),
      m_register_num(clone_unique_ptr(other.m_register_num)),
      m_register_digests(other.m_register_digests) {}

IntegrityRegister& IntegrityRegister::operator=(const IntegrityRegister& other) {
    if (this != &other) {
        m_register_name = clone_unique_ptr(other.m_register_name);
        m_register_num = clone_unique_ptr(other.m_register_num);
        m_register_digests = other.m_register_digests;
    }
    return *this;
}

bool IntegrityRegister::operator==(const IntegrityRegister& other) const {
    return compare_unique_ptr(m_register_name, other.m_register_name) &&
           compare_unique_ptr(m_register_num, other.m_register_num) &&
           m_register_digests == other.m_register_digests;
}

// --- JSON serialization ---

void to_json(nlohmann::json& js, const FWID& fwid) {
    js = nlohmann::json{
        {"hash_alg_oid", fwid.m_hash_alg_oid},
        {"digest", to_hex_string(fwid.m_digest)}
    };
}

void from_json(const nlohmann::json& js, FWID& fwid) {
    js.at("hash_alg_oid").get_to(fwid.m_hash_alg_oid);
    std::string digest_hex;
    js.at("digest").get_to(digest_hex);
    fwid.m_digest = hex_string_to_bytes(digest_hex);
}

void to_json(nlohmann::json& js, const CompositeDeviceId& cdi) {
    js = nlohmann::json{
        {"version", cdi.m_version},
        {"subject_public_key_info", to_hex_string(cdi.m_subject_public_key_info)},
        {"fwid", cdi.m_fwid}
    };
}

void to_json(nlohmann::json& js, const IntegrityRegister& ir) {
    js = nlohmann::json{};
    js["register_name"] = serialize_optional_shared_ptr(ir.m_register_name.get());
    js["register_num"] = serialize_optional_shared_ptr(ir.m_register_num.get());
    js["register_digests"] = ir.m_register_digests;
}

void from_json(const nlohmann::json& js, IntegrityRegister& ir) {
    ir.m_register_name = deserialize_optional_unique_ptr<std::string>(js, "register_name");
    ir.m_register_num = deserialize_optional_unique_ptr<int64_t>(js, "register_num");
    if (js.contains("register_digests") && !js.at("register_digests").is_null()) {
        ir.m_register_digests = js.at("register_digests").get<std::vector<FWID>>();
    }
}

void from_json(const nlohmann::json& js, CompositeDeviceId& cdi) {
    js.at("version").get_to(cdi.m_version);
    cdi.m_subject_public_key_info = hex_string_to_bytes(js.at("subject_public_key_info").get<std::string>());
    cdi.m_fwid = js.at("fwid").get<FWID>();
}

void to_json(nlohmann::json& js, const DiceTcbInfo& dt) {
    js = nlohmann::json{};
    js["vendor"] = serialize_optional_shared_ptr(dt.m_vendor.get());
    js["model"] = serialize_optional_shared_ptr(dt.m_model.get());
    js["version"] = serialize_optional_shared_ptr(dt.m_version.get());
    js["svn"] = serialize_optional_shared_ptr(dt.m_svn.get());
    js["layer"] = serialize_optional_shared_ptr(dt.m_layer.get());
    js["index"] = serialize_optional_shared_ptr(dt.m_index.get());
    js["fwids"] = dt.m_fwids;
    js["flags"] = serialize_optional_shared_ptr(dt.m_flags.get());
    js["flags_mask"] = serialize_optional_shared_ptr(dt.m_flags_mask.get());
    js["integrity_registers"] = dt.m_integrity_registers.empty() ? nlohmann::json(nullptr) : nlohmann::json(dt.m_integrity_registers);
    js["vendor_info"] = dt.m_vendor_info.empty() ? nlohmann::json(nullptr) : nlohmann::json(to_hex_string(dt.m_vendor_info));
    js["type"] = dt.m_type.empty() ? nlohmann::json(nullptr) : nlohmann::json(to_hex_string(dt.m_type));
}

void from_json(const nlohmann::json& js, DiceTcbInfo& dt) {
    dt.m_vendor = deserialize_optional_unique_ptr<std::string>(js, "vendor");
    dt.m_model = deserialize_optional_unique_ptr<std::string>(js, "model");
    dt.m_version = deserialize_optional_unique_ptr<std::string>(js, "version");
    dt.m_svn = deserialize_optional_unique_ptr<int64_t>(js, "svn");
    dt.m_layer = deserialize_optional_unique_ptr<int64_t>(js, "layer");
    dt.m_index = deserialize_optional_unique_ptr<int64_t>(js, "index");

    if (js.contains("fwids") && !js.at("fwids").is_null()) {
        dt.m_fwids = js.at("fwids").get<std::vector<FWID>>();
    }

    dt.m_flags = deserialize_optional_unique_ptr<uint32_t>(js, "flags");
    dt.m_flags_mask = deserialize_optional_unique_ptr<uint32_t>(js, "flags_mask");

    if (js.contains("integrity_registers") && !js.at("integrity_registers").is_null()) {
        dt.m_integrity_registers = js.at("integrity_registers").get<std::vector<IntegrityRegister>>();
    }

    if (js.contains("vendor_info") && !js.at("vendor_info").is_null()) {
        dt.m_vendor_info = hex_string_to_bytes(js.at("vendor_info").get<std::string>());
    }
    if (js.contains("type") && !js.at("type").is_null()) {
        dt.m_type = hex_string_to_bytes(js.at("type").get<std::string>());
    }
}

void to_json(nlohmann::json& js, const MultiDiceTcbInfo& mt) {
    js = nlohmann::json{{"entries", mt.m_entries}};
}

void from_json(const nlohmann::json& js, MultiDiceTcbInfo& mt) {
    js.at("entries").get_to(mt.m_entries);
}

} // namespace nvattestation
