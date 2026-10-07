/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "nv_attestation/corim_evidence/eat_cwt.h"

#include <cstddef>
#include <cstdint>
#include <vector>

#include "nv_attestation/log.h"
#include "internal/cbor_head.h"  // read_cbor_head, kCborMajorTag

namespace nvattestation {

namespace {
// Outer tag stack of an EAT/CWT token.
constexpr uint64_t kSelfDescribedCborTag = 55799;  // RFC 8949 §3.4.6
constexpr uint64_t kCwtTag = 61;                   // RFC 8392 (CWT)

// Peels a single CBOR tag (major type 6) off the front of `in`. Confirms the
// decoded tag equals `expected_tag`, then copies the remaining bytes (the
// tagged item, with its own head intact) into `out_content`. Returns false if
// the input is truncated, the next item is not a tag, or the tag mismatches.
// Bounds: read_cbor_head bounds-checks the head read; the content copy uses the
// post-head offset, which read_cbor_head guarantees is <= in.size().
bool peel_cbor_tag(const std::vector<uint8_t>& in, uint64_t expected_tag,
                   std::vector<uint8_t>& out_content) {
    size_t pos = 0;
    uint8_t major_type = 0;
    uint64_t tag = 0;
    if (!read_cbor_head(in, pos, major_type, tag)) {
        return false;
    }
    if (major_type != kCborMajorTag) {  // not a tag
        return false;
    }
    if (tag != expected_tag) {
        return false;
    }
    out_content.assign(in.begin() + static_cast<std::ptrdiff_t>(pos), in.end());
    return true;
}
}  // namespace

Error peel_eat_cwt_envelope(const std::vector<uint8_t>& signed_cwt_bytes,
                            std::vector<uint8_t>& out_cose_sign1_tagged) {
    if (signed_cwt_bytes.empty()) {
        LOG_ERROR("peel_eat_cwt_envelope called with empty buffer");
        return Error::BadArgument;
    }

    // The self-described-CBOR tag (55799, RFC 8949 §3.4.6) and the CWT tag
    // (61, RFC 8392 §6) are both optional, so peel whichever are present.
    // The COSE_Sign1 tag 18 is left intact for verify_cose_sign1.
    std::vector<uint8_t> stage1;
    const std::vector<uint8_t>& after_self_described =
        peel_cbor_tag(signed_cwt_bytes, kSelfDescribedCborTag, stage1)
            ? stage1
            : signed_cwt_bytes;

    std::vector<uint8_t> stage2;
    if (peel_cbor_tag(after_self_described, kCwtTag, stage2)) {
        out_cose_sign1_tagged = std::move(stage2);
    } else {
        out_cose_sign1_tagged = after_self_described;
    }
    return Error::Ok;
}

Error verify_and_parse_eat_cwt(const std::vector<uint8_t>& signed_cwt_bytes,
                               const CoseSign1VerifyOptions& verify_options,
                               IOcspHttpClient& ocsp_client,
                               Eat& out_eat) {
    if (signed_cwt_bytes.empty()) {
        LOG_ERROR("EAT verify_and_parse_eat_cwt called with empty buffer");
        return Error::EvidenceMalformed;
    }

    std::vector<uint8_t> cose_sign1_tagged;
    Error peel_err = peel_eat_cwt_envelope(signed_cwt_bytes, cose_sign1_tagged);
    if (peel_err != Error::Ok) {
        return peel_err;
    }

    CoseSign1Result verify_result;
    Error verr = verify_cose_sign1(cose_sign1_tagged, verify_options,
                                   ocsp_client, verify_result);
    if (verr != Error::Ok) {
        LOG_ERROR("EAT COSE_Sign1 verification failed");
        return verr;
    }
    return parse_eat_claims(verify_result.payload, out_eat);
}

}  // namespace nvattestation
