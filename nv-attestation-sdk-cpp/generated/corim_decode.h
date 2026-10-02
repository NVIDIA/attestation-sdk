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
 *
 * Generated using zcbor version 0.9.99
 * https://github.com/nordicsemi/zcbor
 */

#ifndef CORIM_DECODE_H__
#define CORIM_DECODE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "corim_decode_types.h"

#ifdef __cplusplus
extern "C" {
#endif


int cbor_decode_corim(
		const uint8_t *payload, size_t payload_len,
		struct corim_map *result,
		size_t *payload_len_out);


int cbor_decode_tagged_unsigned_corim_map(
		const uint8_t *payload, size_t payload_len,
		struct corim_map *result,
		size_t *payload_len_out);


int cbor_decode_concise_mid_tag(
		const uint8_t *payload, size_t payload_len,
		struct concise_mid_tag *result,
		size_t *payload_len_out);


int cbor_decode_tagged_spdm_toc(
		const uint8_t *payload, size_t payload_len,
		struct spdm_toc_map *result,
		size_t *payload_len_out);


int cbor_decode_concise_evidence(
		const uint8_t *payload, size_t payload_len,
		struct concise_evidence *result,
		size_t *payload_len_out);


int cbor_decode_eat_claims_map(
		const uint8_t *payload, size_t payload_len,
		struct eat_claims_map *result,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* CORIM_DECODE_H__ */
