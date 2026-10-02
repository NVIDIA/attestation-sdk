/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace nvattestation {

// CBOR major types (RFC 8949 §3.1), encoded in the top 3 bits of the head byte.
constexpr uint8_t kCborMajorUnsignedInt = 0;
constexpr uint8_t kCborMajorNegativeInt = 1;
constexpr uint8_t kCborMajorByteString = 2;
constexpr uint8_t kCborMajorTextString = 3;
constexpr uint8_t kCborMajorArray = 4;
constexpr uint8_t kCborMajorMap = 5;
constexpr uint8_t kCborMajorTag = 6;
constexpr uint8_t kCborMajorSimple = 7;

// CBOR head encoding (RFC 8949 §3): the low 5 bits ("additional information").
constexpr uint8_t kCborMajorTypeShift = 5;
constexpr uint8_t kCborAdditionalInfoMask = 0x1F;
// Additional-info values < 24 carry the argument inline; 24..27 select a
// 1/2/4/8-byte big-endian argument that follows the head byte.
constexpr uint8_t kCborArgInline = 24;
constexpr uint8_t kCborArg1Byte = 24;
constexpr uint8_t kCborArg2Byte = 25;
constexpr uint8_t kCborArg4Byte = 26;
constexpr uint8_t kCborArg8Byte = 27;
constexpr size_t kCborArg1ByteLen = 1;
constexpr size_t kCborArg2ByteLen = 2;
constexpr size_t kCborArg4ByteLen = 4;
constexpr size_t kCborArg8ByteLen = 8;
constexpr unsigned kBitsPerByte = 8;

// Reads a CBOR head at `data[pos]`: returns the major type and the argument
// value, and advances `pos` past the head. Returns false on truncation or an
// unsupported (indefinite/reserved) additional-information value. Pure with
// respect to `data`; no zcbor dependency.
inline bool read_cbor_head(const std::vector<uint8_t>& data, size_t& pos,
                           uint8_t& major_type, uint64_t& argument) {
    if (pos >= data.size()) {
        return false;
    }
    const uint8_t initial = data[pos];
    ++pos;
    major_type = static_cast<uint8_t>(initial >> kCborMajorTypeShift);
    const uint8_t info = initial & kCborAdditionalInfoMask;
    if (info < kCborArgInline) {
        argument = info;
        return true;
    }
    size_t nbytes = 0;
    switch (info) {
        case kCborArg1Byte: nbytes = kCborArg1ByteLen; break;
        case kCborArg2Byte: nbytes = kCborArg2ByteLen; break;
        case kCborArg4Byte: nbytes = kCborArg4ByteLen; break;
        case kCborArg8Byte: nbytes = kCborArg8ByteLen; break;
        default: return false;  // indefinite / reserved not supported here
    }
    // Overflow-safe form (pos <= data.size() guaranteed by the check above).
    if (nbytes > data.size() - pos) {
        return false;
    }
    argument = 0;
    for (size_t i = 0; i < nbytes; ++i) {
        argument = (argument << kBitsPerByte) | data[pos];
        ++pos;
    }
    return true;
}

}  // namespace nvattestation
