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

#ifndef COSE_DECODE_TYPES_H__
#define COSE_DECODE_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <zcbor_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Which value for --default-max-qty this file was created with.
 *
 *  This can be safely edited.
 *
 *  See `zcbor --help` for more information about --default-max-qty
 */
#define ZCBOR_COSE_DEFAULT_MAX_QTY 10

struct header_map_alg_r {
	union {
		int32_t header_map_alg_int;
		struct zcbor_string header_map_alg_tstr;
	};
	enum {
		header_map_alg_int_c,
		header_map_alg_tstr_c,
	} header_map_alg_choice;
};

struct header_map_content_type_r {
	union {
		int32_t header_map_content_type_int;
		struct zcbor_string header_map_content_type_tstr;
	};
	enum {
		header_map_content_type_int_c,
		header_map_content_type_tstr_c,
	} header_map_content_type_choice;
};

struct COSE_X509_chain {
	struct zcbor_string COSE_X509_chain_bstr[ZCBOR_COSE_DEFAULT_MAX_QTY];
	size_t COSE_X509_chain_bstr_count;
};

struct COSE_X509 {
	union {
		struct zcbor_string COSE_X509_single_m;
		struct COSE_X509_chain COSE_X509_chain_m;
	};
	enum {
		COSE_X509_single_m_c,
		COSE_X509_chain_m_c,
	} COSE_X509_choice;
};

struct header_map_x5chain_r {
	struct COSE_X509 header_map_x5chain;
};

struct COSE_CertHash {
	int32_t COSE_CertHash_hashAlg;
	struct zcbor_string COSE_CertHash_hashValue;
};

struct header_map_x5t_r {
	struct COSE_CertHash header_map_x5t;
};

struct header_map_intany_r {
	int32_t header_map_intany_key;
};

struct header_map {
	struct header_map_alg_r header_map_alg;
	bool header_map_alg_present;
	struct header_map_content_type_r header_map_content_type;
	bool header_map_content_type_present;
	bool header_map_custom_8_present;
	struct header_map_x5chain_r header_map_x5chain;
	bool header_map_x5chain_present;
	struct header_map_x5t_r header_map_x5t;
	bool header_map_x5t_present;
	struct header_map_intany_r header_map_intany[ZCBOR_COSE_DEFAULT_MAX_QTY];
	size_t header_map_intany_count;
};

struct serialized_header_map {
	struct zcbor_string serialized_header_map;
	struct header_map serialized_header_map_cbor;
};

struct empty_or_serialized_map {
	union {
		struct serialized_header_map empty_or_serialized_map_serialized_header_map_m;
		struct zcbor_string empty_or_serialized_map_empty_header_map_m;
	};
	enum {
		empty_or_serialized_map_serialized_header_map_m_c,
		empty_or_serialized_map_empty_header_map_m_c,
	} empty_or_serialized_map_choice;
};

struct COSE_Sign1 {
	struct empty_or_serialized_map COSE_Sign1_protected;
	struct header_map COSE_Sign1_unprotected;
	union {
		struct zcbor_string COSE_Sign1_payload_bstr;
	};
	enum {
		COSE_Sign1_payload_bstr_c,
		COSE_Sign1_payload_nil_c,
	} COSE_Sign1_payload_choice;
	struct zcbor_string COSE_Sign1_signature;
};

#ifdef __cplusplus
}
#endif

#endif /* COSE_DECODE_TYPES_H__ */
