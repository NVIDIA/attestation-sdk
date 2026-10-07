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

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "cose_decode.h"
#include "zcbor_print.h"

#define ZCBOR_CUSTOM_CAST_FP(func) _Generic((func), \
	bool(*)(zcbor_state_t *, struct header_map_alg_r *):          ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct header_map_content_type_r *): ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct COSE_X509_chain *):           ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct COSE_X509 *):                 ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct header_map_x5chain_r *):      ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct COSE_CertHash *):             ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct header_map_x5t_r *):          ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct header_map_intany_r *):       ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct header_map *):                ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct serialized_header_map *):     ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct empty_or_serialized_map *):   ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct COSE_Sign1 *):                ((zcbor_decoder_t *)func), \
	default: ZCBOR_CAST_FP(func))


#ifndef ZCBOR_MAP_SMART_SEARCH
#error "This file needs ZCBOR_MAP_SMART_SEARCH to function"
#endif

#define log_result(state, result, func) do { \
	if (!result) { \
		zcbor_trace_file(state); \
		zcbor_log("%s error: %s\r\n", func, zcbor_error_str(zcbor_peek_error(state))); \
	} else { \
		zcbor_log("%s success\r\n", func); \
	} \
} while(0)

static bool decode_repeated_header_map_alg(zcbor_state_t *state, struct header_map_alg_r *result);
static bool decode_repeated_header_map_content_type(zcbor_state_t *state, struct header_map_content_type_r *result);
static bool decode_repeated_header_map_custom_8(zcbor_state_t *state, void *result);
static bool decode_COSE_X509_chain(zcbor_state_t *state, struct COSE_X509_chain *result);
static bool decode_COSE_X509(zcbor_state_t *state, struct COSE_X509 *result);
static bool decode_repeated_header_map_x5chain(zcbor_state_t *state, struct header_map_x5chain_r *result);
static bool decode_COSE_CertHash(zcbor_state_t *state, struct COSE_CertHash *result);
static bool decode_repeated_header_map_x5t(zcbor_state_t *state, struct header_map_x5t_r *result);
static bool decode_repeated_header_map_intany(zcbor_state_t *state, struct header_map_intany_r *result);
static bool decode_header_map(zcbor_state_t *state, struct header_map *result);
static bool decode_serialized_header_map(zcbor_state_t *state, struct serialized_header_map *result);
static bool decode_empty_or_serialized_map(zcbor_state_t *state, struct empty_or_serialized_map *result);
static bool decode_COSE_Sign1(zcbor_state_t *state, struct COSE_Sign1 *result);
static bool decode_COSE_Sign1_Tagged(zcbor_state_t *state, struct COSE_Sign1 *result);


static bool decode_repeated_header_map_alg(
		zcbor_state_t *state, struct header_map_alg_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).header_map_alg_int)))) && (((*result).header_map_alg_choice = header_map_alg_int_c), true))
	|| (((zcbor_tstr_decode(state, (&(*result).header_map_alg_tstr)))) && (((*result).header_map_alg_choice = header_map_alg_tstr_c), true))), zcbor_union_end_code(state), int_res))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){1}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_header_map_content_type(
		zcbor_state_t *state, struct header_map_content_type_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){3}))
	&& (zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).header_map_content_type_int)))) && (((*result).header_map_content_type_choice = header_map_content_type_int_c), true))
	|| (((zcbor_tstr_decode(state, (&(*result).header_map_content_type_tstr)))) && (((*result).header_map_content_type_choice = header_map_content_type_tstr_c), true))), zcbor_union_end_code(state), int_res))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){3}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_header_map_custom_8(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){8}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){8}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_COSE_X509_chain(
		zcbor_state_t *state, struct COSE_X509_chain *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((zcbor_multi_decode(2, ZCBOR_COSE_DEFAULT_MAX_QTY, &(*result).COSE_X509_chain_bstr_count, ZCBOR_CUSTOM_CAST_FP(zcbor_bstr_decode), state, (*&(*result).COSE_X509_chain_bstr), sizeof(struct zcbor_string))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_bstr_decode(state, (*&(*result).COSE_X509_chain_bstr));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_COSE_X509(
		zcbor_state_t *state, struct COSE_X509 *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result).COSE_X509_single_m)))) && (((*result).COSE_X509_choice = COSE_X509_single_m_c), true))
	|| (((decode_COSE_X509_chain(state, (&(*result).COSE_X509_chain_m)))) && (((*result).COSE_X509_choice = COSE_X509_chain_m_c), true))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_header_map_x5chain(
		zcbor_state_t *state, struct header_map_x5chain_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){33}))
	&& (decode_COSE_X509(state, (&(*result).header_map_x5chain)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){33}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_COSE_CertHash(
		zcbor_state_t *state, struct COSE_CertHash *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_int32_decode(state, (&(*result).COSE_CertHash_hashAlg))))
	&& ((zcbor_bstr_decode(state, (&(*result).COSE_CertHash_hashValue))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_header_map_x5t(
		zcbor_state_t *state, struct header_map_x5t_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){34}))
	&& (decode_COSE_CertHash(state, (&(*result).header_map_x5t)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){34}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_header_map_intany(
		zcbor_state_t *state, struct header_map_intany_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_int32_decode), state, (&(*result).header_map_intany_key))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_int32_decode(state, (&(*result).header_map_intany_key));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_header_map(
		zcbor_state_t *state, struct header_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_present_decode_w_backup(&((*result).header_map_alg_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_header_map_alg), state, (&(*result).header_map_alg)))
	&& (zcbor_present_decode_w_backup(&((*result).header_map_content_type_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_header_map_content_type), state, (&(*result).header_map_content_type)))
	&& (zcbor_present_decode_w_backup(&((*result).header_map_custom_8_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_header_map_custom_8), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).header_map_x5chain_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_header_map_x5chain), state, (&(*result).header_map_x5chain)))
	&& (zcbor_present_decode_w_backup(&((*result).header_map_x5t_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_header_map_x5t), state, (&(*result).header_map_x5t)))
	&& zcbor_multi_decode_w_backup(0, ZCBOR_COSE_DEFAULT_MAX_QTY, &(*result).header_map_intany_count, ZCBOR_CUSTOM_CAST_FP(decode_repeated_header_map_intany), state, (*&(*result).header_map_intany), sizeof(struct header_map_intany_r))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_header_map_intany(state, (*&(*result).header_map_intany));
		decode_repeated_header_map_alg(state, (&(*result).header_map_alg));
		decode_repeated_header_map_content_type(state, (&(*result).header_map_content_type));
		decode_repeated_header_map_custom_8(state, NULL);
		decode_repeated_header_map_x5chain(state, (&(*result).header_map_x5chain));
		decode_repeated_header_map_x5t(state, (&(*result).header_map_x5t));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_serialized_header_map(
		zcbor_state_t *state, struct serialized_header_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((((zcbor_bstr_start_decode(state, &(*result).serialized_header_map)) && (((((decode_header_map(state, (&(*result).serialized_header_map_cbor)))))) || (zcbor_bstr_end_force_decode(state), false)) && (zcbor_bstr_end_decode(state, true)))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_empty_or_serialized_map(
		zcbor_state_t *state, struct empty_or_serialized_map *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_serialized_header_map(state, (&(*result).empty_or_serialized_map_serialized_header_map_m)))) && (((*result).empty_or_serialized_map_choice = empty_or_serialized_map_serialized_header_map_m_c), true))
	|| (zcbor_union_elem_code(state) && (((zcbor_bstr_decode(state, (&(*result).empty_or_serialized_map_empty_header_map_m)))
	&& ((((((*result).empty_or_serialized_map_empty_header_map_m.len == 0)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) && (((*result).empty_or_serialized_map_choice = empty_or_serialized_map_empty_header_map_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_COSE_Sign1(
		zcbor_state_t *state, struct COSE_Sign1 *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_list_start_decode(state) && ((((decode_empty_or_serialized_map(state, (&(*result).COSE_Sign1_protected))))
	&& ((decode_header_map(state, (&(*result).COSE_Sign1_unprotected))))
	&& ((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result).COSE_Sign1_payload_bstr)))) && (((*result).COSE_Sign1_payload_choice = COSE_Sign1_payload_bstr_c), true))
	|| (((zcbor_nil_expect(state, NULL))) && (((*result).COSE_Sign1_payload_choice = COSE_Sign1_payload_nil_c), true))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result).COSE_Sign1_signature))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_COSE_Sign1_Tagged(
		zcbor_state_t *state, struct COSE_Sign1 *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 18)
	&& (decode_COSE_Sign1(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}



int cbor_decode_COSE_Sign1_Tagged(
		const uint8_t *payload, size_t payload_len,
		struct COSE_Sign1 *result,
		size_t *payload_len_out)
{
	const size_t num_flags = ((MAX(((((((ZCBOR_ROUND_UP(1 + 1 + 1 + 1 + 1 + ZCBOR_COSE_DEFAULT_MAX_QTY, 8) * 3)))))), ((ZCBOR_ROUND_UP(1 + 1 + 1 + 1 + 1 + ZCBOR_COSE_DEFAULT_MAX_QTY, 8) * 3)))));
	zcbor_state_t states[7 + ZCBOR_EXTRA_STATES + ZCBOR_FLAG_STATES(num_flags)];

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_COSE_Sign1_Tagged(states, result);
	}

	return zcbor_entry_function_with_elem_states(payload, payload_len, (void *)result, payload_len_out, states, (zcbor_decoder_t *)ZCBOR_CUSTOM_CAST_FP(decode_COSE_Sign1_Tagged), sizeof(states) / sizeof(zcbor_state_t), ZCBOR_LARGE_ELEM_COUNT, num_flags);
}
