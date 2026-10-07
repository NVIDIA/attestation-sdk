/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <cstdint>
#include <vector>

#include "nv_attestation/error.h"
#include "nv_attestation/cose.h"                 // CoseSign1VerifyOptions
#include "nv_attestation/nv_ocsp.h"              // IOcspHttpClient
#include "nv_attestation/corim_evidence/eat.h"   // Eat, parse_eat_claims

namespace nvattestation {

// Strips the optional self-described-CBOR (55799) and CWT (61) tags, leaving
// the inner #6.18(COSE_Sign1) bytes with its tag intact. Returns
// Error::BadArgument on empty input.
Error peel_eat_cwt_envelope(const std::vector<uint8_t>& signed_cwt_bytes,
                            std::vector<uint8_t>& out_cose_sign1_tagged);

// Signed EAT/CWT entry point: peels the outer tags, verifies the COSE_Sign1,
// then parses the payload claims. `out` is undefined unless Error::Ok is
// returned.
//
// This composes signature verification with claims parsing; the pure claims
// parser (parse_eat_claims, eat.h) has no COSE/OCSP dependency.
Error verify_and_parse_eat_cwt(const std::vector<uint8_t>& signed_cwt_bytes,
                               const CoseSign1VerifyOptions& verify_options,
                               IOcspHttpClient& ocsp_client,
                               Eat& out_eat);

}  // namespace nvattestation
