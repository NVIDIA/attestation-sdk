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
#include "corim_decode.h"
#include "zcbor_print.h"

#define ZCBOR_CUSTOM_CAST_FP(func) _Generic((func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map_dbgstat_r *):                 ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_profile_type_choice *):                  ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurements_format *):                      ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurements_type *):                        ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map_iss_r *):                     ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map_cti_r *):                     ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map_ueid_r *):                    ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map_sueid_r *):                   ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct oemid_type *):                               ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map_oemid_r *):                   ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map_hwmodel_r *):                 ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map_uptime_r *):                  ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map_bootcount_r *):               ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map_bootseed_r *):                ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct digest *):                                   ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct corim_locator_map_corim_thumbprint_r *):     ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct corim_locator_map *):                        ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map_rim_locators_r *):            ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map_intany_r *):                  ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct eat_claims_map *):                           ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct corim_id_type_choice *):                     ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct concise_tag_type_choice *):                  ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct corim_map_dependent_rims_r *):               ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct profile_type_choice *):                      ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct corim_map_profile_r *):                      ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct number *):                                   ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct validity_map_not_before_r *):                ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct validity_map *):                             ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct corim_map_rim_validity_r *):                 ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct corim_entity_map_corim_reg_id_r *):          ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct corim_role_type_choice *):                   ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct corim_entity_map *):                         ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct corim_map_entities_r *):                     ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct extension_key *):                            ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct corim_map_extension_key_r *):                ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct corim_map *):                                ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct concise_mid_tag_language_r *):               ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct tag_id_type_choice *):                       ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct tag_identity_map_tag_version_r *):           ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct tag_identity_map *):                         ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct comid_entity_map_comid_reg_id_r *):          ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct comid_role_type_choice *):                   ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct comid_entity_map *):                         ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct concise_mid_tag_entities_r *):               ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct class_id_type_choice *):                     ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct class_map_class_id_r *):                     ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct class_map_vendor_r *):                       ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct class_map_model_r *):                        ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct class_map_layer_r *):                        ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct class_map_index_r *):                        ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct class_map *):                                ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct environment_map_class_r *):                  ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct instance_id_type_choice *):                  ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct environment_map_instance_r *):               ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct group_id_type_choice *):                     ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct environment_map_group_r *):                  ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct environment_map *):                          ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measured_element_type_choice *):             ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurement_map_mkey_r *):                   ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct version_scheme_type_choice *):               ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct version_map_scheme_r *):                     ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct version_map *):                              ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurement_values_map_version_r *):         ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct svn_type_choice *):                          ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurement_values_map_svn_r *):             ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct digests_type *):                             ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurement_values_map_digests_r *):         ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct flags_map_is_configured_r *):                ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct flags_map_is_secure_r *):                    ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct flags_map_is_recovery_r *):                  ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct flags_map_is_debug_r *):                     ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct flags_map_is_replay_protected_r *):          ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct flags_map_is_integrity_protected_r *):       ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct flags_map_is_runtime_meas_r *):              ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct flags_map_is_immutable_r *):                 ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct flags_map_is_tcb_r *):                       ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct flags_map_is_confidentiality_protected_r *): ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct flags_map *):                                ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurement_values_map_flags_r *):           ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct tagged_masked_raw_value *):                  ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct raw_value_type_choice *):                    ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurement_values_map_raw_value_r *):       ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurement_values_map_name_r *):            ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct spdm_indirect_map_index_r *):                ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct spdm_indirect_map_intany_r *):               ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct spdm_indirect_map *):                        ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurement_values_map_spdm_indirect_r *):   ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct int_range_type *):                           ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct int_range_type_choice *):                    ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurement_values_map_int_range_r *):       ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurement_values_map *):                   ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct measurement_map *):                          ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct reference_triple_record *):                  ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct triples_map_reference_triples_r *):          ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct domain_dependency_triple_record *):          ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct triples_map_dependency_triples_r *):         ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct triples_map *):                              ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct concise_mid_tag_extension_key_r *):          ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct concise_mid_tag *):                          ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct evidence_triple_record *):                   ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct ev_triples_map_evidence_triples_r *):        ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct ev_triples_map_intany_r *):                  ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct ev_triples_map *):                           ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct concise_evidence_map_evidence_id_r *):       ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct concise_evidence_map_profile_r *):           ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct concise_evidence_map_intany_r *):            ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct concise_evidence_map *):                     ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct concise_evidence *):                         ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct spdm_toc_map_rim_locators_r *):              ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct spdm_toc_map_profile_r *):                   ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct spdm_toc_map_intany_r *):                    ((zcbor_decoder_t *)func), \
	bool(*)(zcbor_state_t *, struct spdm_toc_map *):                             ((zcbor_decoder_t *)func), \
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

static bool decode_repeated_eat_claims_map_dbgstat(zcbor_state_t *state, struct eat_claims_map_dbgstat_r *result);
static bool decode_eat_profile_type_choice(zcbor_state_t *state, struct eat_profile_type_choice *result);
static bool decode_measurements_format(zcbor_state_t *state, struct measurements_format *result);
static bool decode_measurements_type(zcbor_state_t *state, struct measurements_type *result);
static bool decode_repeated_eat_claims_map_iss(zcbor_state_t *state, struct eat_claims_map_iss_r *result);
static bool decode_repeated_eat_claims_map_cti(zcbor_state_t *state, struct eat_claims_map_cti_r *result);
static bool decode_repeated_eat_claims_map_ueid(zcbor_state_t *state, struct eat_claims_map_ueid_r *result);
static bool decode_repeated_eat_claims_map_sueid(zcbor_state_t *state, struct eat_claims_map_sueid_r *result);
static bool decode_oemid_type(zcbor_state_t *state, struct oemid_type *result);
static bool decode_repeated_eat_claims_map_oemid(zcbor_state_t *state, struct eat_claims_map_oemid_r *result);
static bool decode_repeated_eat_claims_map_hwmodel(zcbor_state_t *state, struct eat_claims_map_hwmodel_r *result);
static bool decode_repeated_eat_claims_map_uptime(zcbor_state_t *state, struct eat_claims_map_uptime_r *result);
static bool decode_repeated_eat_claims_map_bootcount(zcbor_state_t *state, struct eat_claims_map_bootcount_r *result);
static bool decode_repeated_eat_claims_map_bootseed(zcbor_state_t *state, struct eat_claims_map_bootseed_r *result);
static bool decode_uri(zcbor_state_t *state, struct zcbor_string *result);
static bool decode_digest(zcbor_state_t *state, struct digest *result);
static bool decode_repeated_corim_locator_map_corim_thumbprint(zcbor_state_t *state, struct corim_locator_map_corim_thumbprint_r *result);
static bool decode_corim_locator_map(zcbor_state_t *state, struct corim_locator_map *result);
static bool decode_repeated_eat_claims_map_rim_locators(zcbor_state_t *state, struct eat_claims_map_rim_locators_r *result);
static bool decode_repeated_eat_claims_map_intany(zcbor_state_t *state, struct eat_claims_map_intany_r *result);
static bool decode_corim_id_type_choice(zcbor_state_t *state, struct corim_id_type_choice *result);
static bool decode_tagged_concise_swid_tag(zcbor_state_t *state, struct zcbor_string *result);
static bool decode_tagged_concise_mid_tag(zcbor_state_t *state, struct zcbor_string *result);
static bool decode_tagged_concise_tl_tag(zcbor_state_t *state, struct zcbor_string *result);
static bool decode_concise_tag_type_choice(zcbor_state_t *state, struct concise_tag_type_choice *result);
static bool decode_repeated_corim_map_dependent_rims(zcbor_state_t *state, struct corim_map_dependent_rims_r *result);
static bool decode_tagged_oid_type(zcbor_state_t *state, struct zcbor_string *result);
static bool decode_profile_type_choice(zcbor_state_t *state, struct profile_type_choice *result);
static bool decode_repeated_corim_map_profile(zcbor_state_t *state, struct corim_map_profile_r *result);
static bool decode_number(zcbor_state_t *state, struct number *result);
static bool decode_time(zcbor_state_t *state, struct number *result);
static bool decode_repeated_validity_map_not_before(zcbor_state_t *state, struct validity_map_not_before_r *result);
static bool decode_validity_map(zcbor_state_t *state, struct validity_map *result);
static bool decode_repeated_corim_map_rim_validity(zcbor_state_t *state, struct corim_map_rim_validity_r *result);
static bool decode_repeated_corim_entity_map_corim_reg_id(zcbor_state_t *state, struct corim_entity_map_corim_reg_id_r *result);
static bool decode_corim_role_type_choice(zcbor_state_t *state, struct corim_role_type_choice *result);
static bool decode_corim_entity_map(zcbor_state_t *state, struct corim_entity_map *result);
static bool decode_repeated_corim_map_entities(zcbor_state_t *state, struct corim_map_entities_r *result);
static bool decode_extension_key(zcbor_state_t *state, struct extension_key *result);
static bool decode_repeated_corim_map_extension_key(zcbor_state_t *state, struct corim_map_extension_key_r *result);
static bool decode_corim_map(zcbor_state_t *state, struct corim_map *result);
static bool decode_repeated_concise_mid_tag_language(zcbor_state_t *state, struct concise_mid_tag_language_r *result);
static bool decode_tag_id_type_choice(zcbor_state_t *state, struct tag_id_type_choice *result);
static bool decode_repeated_tag_identity_map_tag_version(zcbor_state_t *state, struct tag_identity_map_tag_version_r *result);
static bool decode_tag_identity_map(zcbor_state_t *state, struct tag_identity_map *result);
static bool decode_repeated_comid_entity_map_comid_reg_id(zcbor_state_t *state, struct comid_entity_map_comid_reg_id_r *result);
static bool decode_comid_role_type_choice(zcbor_state_t *state, struct comid_role_type_choice *result);
static bool decode_comid_entity_map(zcbor_state_t *state, struct comid_entity_map *result);
static bool decode_repeated_concise_mid_tag_entities(zcbor_state_t *state, struct concise_mid_tag_entities_r *result);
static bool decode_repeated_concise_mid_tag_linked_tags(zcbor_state_t *state, void *result);
static bool decode_tagged_uuid_type(zcbor_state_t *state, struct zcbor_string *result);
static bool decode_tagged_bytes(zcbor_state_t *state, struct zcbor_string *result);
static bool decode_class_id_type_choice(zcbor_state_t *state, struct class_id_type_choice *result);
static bool decode_repeated_class_map_class_id(zcbor_state_t *state, struct class_map_class_id_r *result);
static bool decode_repeated_class_map_vendor(zcbor_state_t *state, struct class_map_vendor_r *result);
static bool decode_repeated_class_map_model(zcbor_state_t *state, struct class_map_model_r *result);
static bool decode_repeated_class_map_layer(zcbor_state_t *state, struct class_map_layer_r *result);
static bool decode_repeated_class_map_index(zcbor_state_t *state, struct class_map_index_r *result);
static bool decode_class_map(zcbor_state_t *state, struct class_map *result);
static bool decode_repeated_environment_map_class(zcbor_state_t *state, struct environment_map_class_r *result);
static bool decode_tagged_ueid_type(zcbor_state_t *state, struct zcbor_string *result);
static bool decode_instance_id_type_choice(zcbor_state_t *state, struct instance_id_type_choice *result);
static bool decode_repeated_environment_map_instance(zcbor_state_t *state, struct environment_map_instance_r *result);
static bool decode_group_id_type_choice(zcbor_state_t *state, struct group_id_type_choice *result);
static bool decode_repeated_environment_map_group(zcbor_state_t *state, struct environment_map_group_r *result);
static bool decode_environment_map(zcbor_state_t *state, struct environment_map *result);
static bool decode_measured_element_type_choice(zcbor_state_t *state, struct measured_element_type_choice *result);
static bool decode_repeated_measurement_map_mkey(zcbor_state_t *state, struct measurement_map_mkey_r *result);
static bool decode_version_scheme_type_choice(zcbor_state_t *state, struct version_scheme_type_choice *result);
static bool decode_repeated_version_map_scheme(zcbor_state_t *state, struct version_map_scheme_r *result);
static bool decode_version_map(zcbor_state_t *state, struct version_map *result);
static bool decode_repeated_measurement_values_map_version(zcbor_state_t *state, struct measurement_values_map_version_r *result);
static bool decode_tagged_svn(zcbor_state_t *state, uint32_t *result);
static bool decode_tagged_min_svn(zcbor_state_t *state, uint32_t *result);
static bool decode_svn_type_choice(zcbor_state_t *state, struct svn_type_choice *result);
static bool decode_repeated_measurement_values_map_svn(zcbor_state_t *state, struct measurement_values_map_svn_r *result);
static bool decode_digests_type(zcbor_state_t *state, struct digests_type *result);
static bool decode_repeated_measurement_values_map_digests(zcbor_state_t *state, struct measurement_values_map_digests_r *result);
static bool decode_repeated_flags_map_is_configured(zcbor_state_t *state, struct flags_map_is_configured_r *result);
static bool decode_repeated_flags_map_is_secure(zcbor_state_t *state, struct flags_map_is_secure_r *result);
static bool decode_repeated_flags_map_is_recovery(zcbor_state_t *state, struct flags_map_is_recovery_r *result);
static bool decode_repeated_flags_map_is_debug(zcbor_state_t *state, struct flags_map_is_debug_r *result);
static bool decode_repeated_flags_map_is_replay_protected(zcbor_state_t *state, struct flags_map_is_replay_protected_r *result);
static bool decode_repeated_flags_map_is_integrity_protected(zcbor_state_t *state, struct flags_map_is_integrity_protected_r *result);
static bool decode_repeated_flags_map_is_runtime_meas(zcbor_state_t *state, struct flags_map_is_runtime_meas_r *result);
static bool decode_repeated_flags_map_is_immutable(zcbor_state_t *state, struct flags_map_is_immutable_r *result);
static bool decode_repeated_flags_map_is_tcb(zcbor_state_t *state, struct flags_map_is_tcb_r *result);
static bool decode_repeated_flags_map_is_confidentiality_protected(zcbor_state_t *state, struct flags_map_is_confidentiality_protected_r *result);
static bool decode_flags_map(zcbor_state_t *state, struct flags_map *result);
static bool decode_repeated_measurement_values_map_flags(zcbor_state_t *state, struct measurement_values_map_flags_r *result);
static bool decode_tagged_masked_raw_value(zcbor_state_t *state, struct tagged_masked_raw_value *result);
static bool decode_raw_value_type_choice(zcbor_state_t *state, struct raw_value_type_choice *result);
static bool decode_repeated_measurement_values_map_raw_value(zcbor_state_t *state, struct measurement_values_map_raw_value_r *result);
static bool decode_repeated_measurement_values_map_raw_value_mask_DEPRECATED(zcbor_state_t *state, void *result);
static bool decode_repeated_measurement_values_map_mac_addr(zcbor_state_t *state, void *result);
static bool decode_repeated_measurement_values_map_ip_addr(zcbor_state_t *state, void *result);
static bool decode_repeated_measurement_values_map_serial_number(zcbor_state_t *state, void *result);
static bool decode_repeated_measurement_values_map_ueid(zcbor_state_t *state, void *result);
static bool decode_repeated_measurement_values_map_uuid(zcbor_state_t *state, void *result);
static bool decode_repeated_measurement_values_map_name(zcbor_state_t *state, struct measurement_values_map_name_r *result);
static bool decode_repeated_spdm_indirect_map_index(zcbor_state_t *state, struct spdm_indirect_map_index_r *result);
static bool decode_repeated_spdm_indirect_map_intany(zcbor_state_t *state, struct spdm_indirect_map_intany_r *result);
static bool decode_spdm_indirect_map(zcbor_state_t *state, struct spdm_indirect_map *result);
static bool decode_repeated_measurement_values_map_spdm_indirect(zcbor_state_t *state, struct measurement_values_map_spdm_indirect_r *result);
static bool decode_repeated_measurement_values_map_cryptokeys(zcbor_state_t *state, void *result);
static bool decode_repeated_measurement_values_map_integrity_registers(zcbor_state_t *state, void *result);
static bool decode_int_range_type(zcbor_state_t *state, struct int_range_type *result);
static bool decode_tagged_int_range(zcbor_state_t *state, struct int_range_type *result);
static bool decode_int_range_type_choice(zcbor_state_t *state, struct int_range_type_choice *result);
static bool decode_repeated_measurement_values_map_int_range(zcbor_state_t *state, struct measurement_values_map_int_range_r *result);
static bool decode_measurement_values_map(zcbor_state_t *state, struct measurement_values_map *result);
static bool decode_repeated_measurement_map_authorized_by(zcbor_state_t *state, void *result);
static bool decode_measurement_map(zcbor_state_t *state, struct measurement_map *result);
static bool decode_reference_triple_record(zcbor_state_t *state, struct reference_triple_record *result);
static bool decode_repeated_triples_map_reference_triples(zcbor_state_t *state, struct triples_map_reference_triples_r *result);
static bool decode_repeated_triples_map_endorsed_triples(zcbor_state_t *state, void *result);
static bool decode_repeated_triples_map_identity_triples(zcbor_state_t *state, void *result);
static bool decode_repeated_triples_map_attest_key_triples(zcbor_state_t *state, void *result);
static bool decode_domain_dependency_triple_record(zcbor_state_t *state, struct domain_dependency_triple_record *result);
static bool decode_repeated_triples_map_dependency_triples(zcbor_state_t *state, struct triples_map_dependency_triples_r *result);
static bool decode_repeated_triples_map_membership_triples(zcbor_state_t *state, void *result);
static bool decode_repeated_triples_map_coswid_triples(zcbor_state_t *state, void *result);
static bool decode_repeated_triples_map_conditional_endorsement_series_triples(zcbor_state_t *state, void *result);
static bool decode_repeated_triples_map_conditional_endorsement_triples(zcbor_state_t *state, void *result);
static bool decode_triples_map(zcbor_state_t *state, struct triples_map *result);
static bool decode_repeated_concise_mid_tag_extension_key(zcbor_state_t *state, struct concise_mid_tag_extension_key_r *result);
static bool decode_evidence_triple_record(zcbor_state_t *state, struct evidence_triple_record *result);
static bool decode_repeated_ev_triples_map_evidence_triples(zcbor_state_t *state, struct ev_triples_map_evidence_triples_r *result);
static bool decode_repeated_ev_triples_map_identity_triples(zcbor_state_t *state, void *result);
static bool decode_repeated_ev_triples_map_dependency_triples(zcbor_state_t *state, void *result);
static bool decode_repeated_ev_triples_map_membership_triples(zcbor_state_t *state, void *result);
static bool decode_repeated_ev_triples_map_coswid_triples(zcbor_state_t *state, void *result);
static bool decode_repeated_ev_triples_map_attest_key_triples(zcbor_state_t *state, void *result);
static bool decode_repeated_ev_triples_map_intany(zcbor_state_t *state, struct ev_triples_map_intany_r *result);
static bool decode_ev_triples_map(zcbor_state_t *state, struct ev_triples_map *result);
static bool decode_repeated_concise_evidence_map_evidence_id(zcbor_state_t *state, struct concise_evidence_map_evidence_id_r *result);
static bool decode_repeated_concise_evidence_map_profile(zcbor_state_t *state, struct concise_evidence_map_profile_r *result);
static bool decode_repeated_concise_evidence_map_intany(zcbor_state_t *state, struct concise_evidence_map_intany_r *result);
static bool decode_concise_evidence_map(zcbor_state_t *state, struct concise_evidence_map *result);
static bool decode_tagged_concise_evidence(zcbor_state_t *state, struct concise_evidence_map *result);
static bool decode_repeated_spdm_toc_map_rim_locators(zcbor_state_t *state, struct spdm_toc_map_rim_locators_r *result);
static bool decode_repeated_spdm_toc_map_profile(zcbor_state_t *state, struct spdm_toc_map_profile_r *result);
static bool decode_repeated_spdm_toc_map_intany(zcbor_state_t *state, struct spdm_toc_map_intany_r *result);
static bool decode_spdm_toc_map(zcbor_state_t *state, struct spdm_toc_map *result);
static bool decode_eat_claims_map(zcbor_state_t *state, struct eat_claims_map *result);
static bool decode_concise_evidence(zcbor_state_t *state, struct concise_evidence *result);
static bool decode_tagged_spdm_toc(zcbor_state_t *state, struct spdm_toc_map *result);
static bool decode_concise_mid_tag(zcbor_state_t *state, struct concise_mid_tag *result);
static bool decode_tagged_unsigned_corim_map(zcbor_state_t *state, struct corim_map *result);
static bool decode_corim(zcbor_state_t *state, struct corim_map *result);


static bool decode_repeated_eat_claims_map_dbgstat(
		zcbor_state_t *state, struct eat_claims_map_dbgstat_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint16_pexpect), state, (&(uint16_t){263}))
	&& (zcbor_uint8_decode(state, (&(*result).eat_claims_map_dbgstat)))
	&& ((((((*result).eat_claims_map_dbgstat <= 4)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint16_pexpect(state, (&(uint16_t){263}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_eat_profile_type_choice(
		zcbor_state_t *state, struct eat_profile_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_tstr_decode(state, (&(*result).eat_profile_type_choice_tstr)))) && (((*result).eat_profile_type_choice_choice = eat_profile_type_choice_tstr_c), true))
	|| (((zcbor_bstr_decode(state, (&(*result).eat_profile_type_choice_bstr)))) && (((*result).eat_profile_type_choice_choice = eat_profile_type_choice_bstr_c), true))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_measurements_format(
		zcbor_state_t *state, struct measurements_format *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_uint16_decode(state, (&(*result).measurements_format_content_format)))
	&& ((((*result).measurements_format_content_format <= 65535)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false)))
	&& ((zcbor_bstr_decode(state, (&(*result).measurements_format_body))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_measurements_type(
		zcbor_state_t *state, struct measurements_type *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, 8, &(*result).measurements_type_measurements_format_m_count, ZCBOR_CUSTOM_CAST_FP(decode_measurements_format), state, (*&(*result).measurements_type_measurements_format_m), sizeof(struct measurements_format))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_measurements_format(state, (*&(*result).measurements_type_measurements_format_m));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_eat_claims_map_iss(
		zcbor_state_t *state, struct eat_claims_map_iss_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (zcbor_tstr_decode(state, (&(*result).eat_claims_map_iss)))
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

static bool decode_repeated_eat_claims_map_cti(
		zcbor_state_t *state, struct eat_claims_map_cti_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){7}))
	&& (zcbor_bstr_decode(state, (&(*result).eat_claims_map_cti)))
	&& ((((*result).eat_claims_map_cti.len >= 8)
	&& ((*result).eat_claims_map_cti.len <= 64)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){7}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_eat_claims_map_ueid(
		zcbor_state_t *state, struct eat_claims_map_ueid_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint16_pexpect), state, (&(uint16_t){256}))
	&& (zcbor_bstr_decode(state, (&(*result).eat_claims_map_ueid)))
	&& ((((*result).eat_claims_map_ueid.len >= 7)
	&& ((*result).eat_claims_map_ueid.len <= 33)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint16_pexpect(state, (&(uint16_t){256}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_eat_claims_map_sueid(
		zcbor_state_t *state, struct eat_claims_map_sueid_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint16_pexpect), state, (&(uint16_t){257}))
	&& (zcbor_bstr_decode(state, (&(*result).eat_claims_map_sueid)))
	&& ((((*result).eat_claims_map_sueid.len >= 7)
	&& ((*result).eat_claims_map_sueid.len <= 33)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint16_pexpect(state, (&(uint16_t){257}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_oemid_type(
		zcbor_state_t *state, struct oemid_type *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result).oemid_type_bstr)))) && (((*result).oemid_type_choice = oemid_type_bstr_c), true))
	|| (((zcbor_int32_decode(state, (&(*result).oemid_type_int)))) && (((*result).oemid_type_choice = oemid_type_int_c), true))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_eat_claims_map_oemid(
		zcbor_state_t *state, struct eat_claims_map_oemid_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint16_pexpect), state, (&(uint16_t){258}))
	&& (decode_oemid_type(state, (&(*result).eat_claims_map_oemid)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint16_pexpect(state, (&(uint16_t){258}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_eat_claims_map_hwmodel(
		zcbor_state_t *state, struct eat_claims_map_hwmodel_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint16_pexpect), state, (&(uint16_t){259}))
	&& (zcbor_bstr_decode(state, (&(*result).eat_claims_map_hwmodel)))
	&& ((((*result).eat_claims_map_hwmodel.len >= 1)
	&& ((*result).eat_claims_map_hwmodel.len <= 32)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint16_pexpect(state, (&(uint16_t){259}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_eat_claims_map_uptime(
		zcbor_state_t *state, struct eat_claims_map_uptime_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint16_pexpect), state, (&(uint16_t){261}))
	&& (zcbor_uint32_decode(state, (&(*result).eat_claims_map_uptime)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint16_pexpect(state, (&(uint16_t){261}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_eat_claims_map_bootcount(
		zcbor_state_t *state, struct eat_claims_map_bootcount_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint16_pexpect), state, (&(uint16_t){267}))
	&& (zcbor_uint32_decode(state, (&(*result).eat_claims_map_bootcount)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint16_pexpect(state, (&(uint16_t){267}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_eat_claims_map_bootseed(
		zcbor_state_t *state, struct eat_claims_map_bootseed_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint16_pexpect), state, (&(uint16_t){268}))
	&& (zcbor_bstr_decode(state, (&(*result).eat_claims_map_bootseed)))
	&& ((((*result).eat_claims_map_bootseed.len >= 32)
	&& ((*result).eat_claims_map_bootseed.len <= 64)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint16_pexpect(state, (&(uint16_t){268}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_uri(
		zcbor_state_t *state, struct zcbor_string *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 32)
	&& (zcbor_tstr_decode(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_digest(
		zcbor_state_t *state, struct digest *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).digest_alg_int)))) && (((*result).digest_alg_choice = digest_alg_int_c), true))
	|| (((zcbor_tstr_decode(state, (&(*result).digest_alg_text_m)))) && (((*result).digest_alg_choice = digest_alg_text_m_c), true))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result).digest_val))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_corim_locator_map_corim_thumbprint(
		zcbor_state_t *state, struct corim_locator_map_corim_thumbprint_r *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (zcbor_union_start_code(state) && (int_res = ((((decode_digest(state, (&(*result).corim_locator_map_corim_thumbprint_digest_m)))) && (((*result).corim_locator_map_corim_thumbprint_choice = corim_locator_map_corim_thumbprint_digest_m_c), true))
	|| (zcbor_union_elem_code(state) && (((zcbor_list_start_decode(state) && ((((decode_digest(state, (&(*result).corim_thumbprint_digest_m_l_digest_m))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))) && (((*result).corim_locator_map_corim_thumbprint_choice = corim_thumbprint_digest_m_l_digest_m_c), true)))), zcbor_union_end_code(state), int_res))
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

static bool decode_corim_locator_map(
		zcbor_state_t *state, struct corim_locator_map *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (zcbor_union_start_code(state) && (int_res = ((((decode_uri(state, (&(*result).corim_locator_map_corim_href_uri_m)))) && (((*result).corim_locator_map_corim_href_choice = corim_locator_map_corim_href_uri_m_c), true))
	|| (zcbor_union_elem_code(state) && (((zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).corim_href_uri_m_l_uri_m_count, ZCBOR_CUSTOM_CAST_FP(decode_uri), state, (*&(*result).corim_href_uri_m_l_uri_m), sizeof(struct zcbor_string))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))) && (((*result).corim_locator_map_corim_href_choice = corim_href_uri_m_l_c), true)))), zcbor_union_end_code(state), int_res))
	&& zcbor_elem_processed(state))
	&& (zcbor_present_decode_w_backup(&((*result).corim_locator_map_corim_thumbprint_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_corim_locator_map_corim_thumbprint), state, (&(*result).corim_locator_map_corim_thumbprint)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_uri(state, (*&(*result).corim_href_uri_m_l_uri_m));
		decode_repeated_corim_locator_map_corim_thumbprint(state, (&(*result).corim_locator_map_corim_thumbprint));
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_eat_claims_map_rim_locators(
		zcbor_state_t *state, struct eat_claims_map_rim_locators_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_int32_pexpect), state, (&(int32_t){-70001}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, 8, &(*result).eat_claims_map_rim_locators_corim_locator_map_m_count, ZCBOR_CUSTOM_CAST_FP(decode_corim_locator_map), state, (*&(*result).eat_claims_map_rim_locators_corim_locator_map_m), sizeof(struct corim_locator_map))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_corim_locator_map(state, (*&(*result).eat_claims_map_rim_locators_corim_locator_map_m));
		zcbor_int32_pexpect(state, (&(int32_t){-70001}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_eat_claims_map_intany(
		zcbor_state_t *state, struct eat_claims_map_intany_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_int32_decode), state, (&(*result).eat_claims_map_intany_key))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_int32_decode(state, (&(*result).eat_claims_map_intany_key));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_corim_id_type_choice(
		zcbor_state_t *state, struct corim_id_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_tstr_decode(state, (&(*result).corim_id_type_choice_tstr)))) && (((*result).corim_id_type_choice_choice = corim_id_type_choice_tstr_c), true))
	|| (((zcbor_bstr_decode(state, (&(*result).corim_id_type_choice_uuid_type_m)))
	&& ((((((*result).corim_id_type_choice_uuid_type_m.len == 16)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) && (((*result).corim_id_type_choice_choice = corim_id_type_choice_uuid_type_m_c), true))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_tagged_concise_swid_tag(
		zcbor_state_t *state, struct zcbor_string *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 505)
	&& (zcbor_bstr_decode(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_tagged_concise_mid_tag(
		zcbor_state_t *state, struct zcbor_string *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 506)
	&& (zcbor_bstr_decode(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_tagged_concise_tl_tag(
		zcbor_state_t *state, struct zcbor_string *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 508)
	&& (zcbor_bstr_decode(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_concise_tag_type_choice(
		zcbor_state_t *state, struct concise_tag_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_tagged_concise_swid_tag(state, (&(*result).concise_tag_type_choice_tagged_concise_swid_tag_m)))) && (((*result).concise_tag_type_choice_choice = concise_tag_type_choice_tagged_concise_swid_tag_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_tagged_concise_mid_tag(state, (&(*result).concise_tag_type_choice_tagged_concise_mid_tag_m)))) && (((*result).concise_tag_type_choice_choice = concise_tag_type_choice_tagged_concise_mid_tag_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_tagged_concise_tl_tag(state, (&(*result).concise_tag_type_choice_tagged_concise_tl_tag_m)))) && (((*result).concise_tag_type_choice_choice = concise_tag_type_choice_tagged_concise_tl_tag_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_corim_map_dependent_rims(
		zcbor_state_t *state, struct corim_map_dependent_rims_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).corim_map_dependent_rims_corim_locator_map_m_count, ZCBOR_CUSTOM_CAST_FP(decode_corim_locator_map), state, (*&(*result).corim_map_dependent_rims_corim_locator_map_m), sizeof(struct corim_locator_map))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_corim_locator_map(state, (*&(*result).corim_map_dependent_rims_corim_locator_map_m));
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_tagged_oid_type(
		zcbor_state_t *state, struct zcbor_string *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 111)
	&& (zcbor_bstr_decode(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_profile_type_choice(
		zcbor_state_t *state, struct profile_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_uri(state, (&(*result).profile_type_choice_uri_m)))) && (((*result).profile_type_choice_choice = profile_type_choice_uri_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_tagged_oid_type(state, (&(*result).profile_type_choice_tagged_oid_type_m)))) && (((*result).profile_type_choice_choice = profile_type_choice_tagged_oid_type_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_corim_map_profile(
		zcbor_state_t *state, struct corim_map_profile_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){3}))
	&& (decode_profile_type_choice(state, (&(*result).corim_map_profile)))
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

static bool decode_number(
		zcbor_state_t *state, struct number *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).number_int)))) && (((*result).number_choice = number_int_c), true))
	|| (((zcbor_float_decode(state, (&(*result).number_float)))) && (((*result).number_choice = number_float_c), true))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_time(
		zcbor_state_t *state, struct number *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 1)
	&& (decode_number(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_validity_map_not_before(
		zcbor_state_t *state, struct validity_map_not_before_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (decode_time(state, (&(*result).validity_map_not_before)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_validity_map(
		zcbor_state_t *state, struct validity_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_present_decode_w_backup(&((*result).validity_map_not_before_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_validity_map_not_before), state, (&(*result).validity_map_not_before)))
	&& (zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (decode_time(state, (&(*result).validity_map_not_after)))
	&& zcbor_elem_processed(state))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_validity_map_not_before(state, (&(*result).validity_map_not_before));
		zcbor_uint8_pexpect(state, (&(uint8_t){1}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_corim_map_rim_validity(
		zcbor_state_t *state, struct corim_map_rim_validity_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){4}))
	&& (decode_validity_map(state, (&(*result).corim_map_rim_validity)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){4}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_corim_entity_map_corim_reg_id(
		zcbor_state_t *state, struct corim_entity_map_corim_reg_id_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (decode_uri(state, (&(*result).corim_entity_map_corim_reg_id)))
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

static bool decode_corim_role_type_choice(
		zcbor_state_t *state, struct corim_role_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((zcbor_uint_decode(state, &(*result).corim_role_type_choice_choice, sizeof((*result).corim_role_type_choice_choice)))) && ((((((*result).corim_role_type_choice_choice == corim_role_type_choice_manifest_creator_m_c) && ((1)))
	|| (((*result).corim_role_type_choice_choice == corim_role_type_choice_manifest_signer_m_c) && ((1)))) || (zcbor_error(state, ZCBOR_ERR_WRONG_VALUE), false))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_corim_entity_map(
		zcbor_state_t *state, struct corim_entity_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (zcbor_tstr_decode(state, (&(*result).corim_entity_map_corim_entity_name)))
	&& zcbor_elem_processed(state))
	&& (zcbor_present_decode_w_backup(&((*result).corim_entity_map_corim_reg_id_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_corim_entity_map_corim_reg_id), state, (&(*result).corim_entity_map_corim_reg_id)))
	&& (zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).corim_entity_map_corim_role_corim_role_type_choice_m_count, ZCBOR_CUSTOM_CAST_FP(decode_corim_role_type_choice), state, (*&(*result).corim_entity_map_corim_role_corim_role_type_choice_m), sizeof(struct corim_role_type_choice))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_corim_role_type_choice(state, (*&(*result).corim_entity_map_corim_role_corim_role_type_choice_m));
		decode_repeated_corim_entity_map_corim_reg_id(state, (&(*result).corim_entity_map_corim_reg_id));
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_corim_map_entities(
		zcbor_state_t *state, struct corim_map_entities_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){5}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).corim_map_entities_corim_entity_map_m_count, ZCBOR_CUSTOM_CAST_FP(decode_corim_entity_map), state, (*&(*result).corim_map_entities_corim_entity_map_m), sizeof(struct corim_entity_map))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_corim_entity_map(state, (*&(*result).corim_map_entities_corim_entity_map_m));
		zcbor_uint8_pexpect(state, (&(uint8_t){5}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_extension_key(
		zcbor_state_t *state, struct extension_key *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).extension_key_int)))) && (((*result).extension_key_choice = extension_key_int_c), true))
	|| (((zcbor_tstr_decode(state, (&(*result).extension_key_tstr)))) && (((*result).extension_key_choice = extension_key_tstr_c), true))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_corim_map_extension_key(
		zcbor_state_t *state, struct corim_map_extension_key_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(decode_extension_key), state, (&(*result).corim_map_extension_key_key))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_extension_key(state, (&(*result).corim_map_extension_key_key));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_corim_map(
		zcbor_state_t *state, struct corim_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (decode_corim_id_type_choice(state, (&(*result).corim_map_id)))
	&& zcbor_elem_processed(state))
	&& (zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, 25, &(*result).corim_map_tags_concise_tag_type_choice_m_count, ZCBOR_CUSTOM_CAST_FP(decode_concise_tag_type_choice), state, (*&(*result).corim_map_tags_concise_tag_type_choice_m), sizeof(struct concise_tag_type_choice))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state))
	&& (zcbor_present_decode_w_backup(&((*result).corim_map_dependent_rims_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_corim_map_dependent_rims), state, (&(*result).corim_map_dependent_rims)))
	&& (zcbor_present_decode_w_backup(&((*result).corim_map_profile_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_corim_map_profile), state, (&(*result).corim_map_profile)))
	&& (zcbor_present_decode_w_backup(&((*result).corim_map_rim_validity_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_corim_map_rim_validity), state, (&(*result).corim_map_rim_validity)))
	&& (zcbor_present_decode_w_backup(&((*result).corim_map_entities_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_corim_map_entities), state, (&(*result).corim_map_entities)))
	&& zcbor_multi_decode_w_backup(0, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).corim_map_extension_key_count, ZCBOR_CUSTOM_CAST_FP(decode_repeated_corim_map_extension_key), state, (*&(*result).corim_map_extension_key), sizeof(struct corim_map_extension_key_r))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_concise_tag_type_choice(state, (*&(*result).corim_map_tags_concise_tag_type_choice_m));
		decode_repeated_corim_map_extension_key(state, (*&(*result).corim_map_extension_key));
		decode_repeated_corim_map_dependent_rims(state, (&(*result).corim_map_dependent_rims));
		decode_repeated_corim_map_profile(state, (&(*result).corim_map_profile));
		decode_repeated_corim_map_rim_validity(state, (&(*result).corim_map_rim_validity));
		decode_repeated_corim_map_entities(state, (&(*result).corim_map_entities));
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
		zcbor_uint8_pexpect(state, (&(uint8_t){1}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_concise_mid_tag_language(
		zcbor_state_t *state, struct concise_mid_tag_language_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (zcbor_tstr_decode(state, (&(*result).concise_mid_tag_language)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_tag_id_type_choice(
		zcbor_state_t *state, struct tag_id_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_tstr_decode(state, (&(*result).tag_id_type_choice_tstr)))) && (((*result).tag_id_type_choice_choice = tag_id_type_choice_tstr_c), true))
	|| (((zcbor_bstr_decode(state, (&(*result).tag_id_type_choice_uuid_type_m)))
	&& ((((((*result).tag_id_type_choice_uuid_type_m.len == 16)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) && (((*result).tag_id_type_choice_choice = tag_id_type_choice_uuid_type_m_c), true))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_tag_identity_map_tag_version(
		zcbor_state_t *state, struct tag_identity_map_tag_version_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){12}))
	&& (zcbor_uint32_decode(state, (&(*result).tag_identity_map_tag_version)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){12}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_tag_identity_map(
		zcbor_state_t *state, struct tag_identity_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (decode_tag_id_type_choice(state, (&(*result).tag_identity_map_tag_id)))
	&& zcbor_elem_processed(state))
	&& (zcbor_present_decode_w_backup(&((*result).tag_identity_map_tag_version_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_tag_identity_map_tag_version), state, (&(*result).tag_identity_map_tag_version)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_tag_identity_map_tag_version(state, (&(*result).tag_identity_map_tag_version));
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_comid_entity_map_comid_reg_id(
		zcbor_state_t *state, struct comid_entity_map_comid_reg_id_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (decode_uri(state, (&(*result).comid_entity_map_comid_reg_id)))
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

static bool decode_comid_role_type_choice(
		zcbor_state_t *state, struct comid_role_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((((zcbor_uint_decode(state, &(*result).comid_role_type_choice_choice, sizeof((*result).comid_role_type_choice_choice)))) && ((((((*result).comid_role_type_choice_choice == comid_role_type_choice_comid_tag_creator_m_c) && ((1)))
	|| (((*result).comid_role_type_choice_choice == comid_role_type_choice_comid_creator_m_c) && ((1)))
	|| (((*result).comid_role_type_choice_choice == comid_role_type_choice_comid_maintainer_m_c) && ((1)))) || (zcbor_error(state, ZCBOR_ERR_WRONG_VALUE), false))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_comid_entity_map(
		zcbor_state_t *state, struct comid_entity_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (zcbor_tstr_decode(state, (&(*result).comid_entity_map_comid_entity_name)))
	&& zcbor_elem_processed(state))
	&& (zcbor_present_decode_w_backup(&((*result).comid_entity_map_comid_reg_id_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_comid_entity_map_comid_reg_id), state, (&(*result).comid_entity_map_comid_reg_id)))
	&& (zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).comid_entity_map_comid_role_comid_role_type_choice_m_count, ZCBOR_CUSTOM_CAST_FP(decode_comid_role_type_choice), state, (*&(*result).comid_entity_map_comid_role_comid_role_type_choice_m), sizeof(struct comid_role_type_choice))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_comid_role_type_choice(state, (*&(*result).comid_entity_map_comid_role_comid_role_type_choice_m));
		decode_repeated_comid_entity_map_comid_reg_id(state, (&(*result).comid_entity_map_comid_reg_id));
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_concise_mid_tag_entities(
		zcbor_state_t *state, struct concise_mid_tag_entities_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).concise_mid_tag_entities_comid_entity_map_m_count, ZCBOR_CUSTOM_CAST_FP(decode_comid_entity_map), state, (*&(*result).concise_mid_tag_entities_comid_entity_map_m), sizeof(struct comid_entity_map))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_comid_entity_map(state, (*&(*result).concise_mid_tag_entities_comid_entity_map_m));
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_concise_mid_tag_linked_tags(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){3}))
	&& (zcbor_any_skip(state, NULL))
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

static bool decode_tagged_uuid_type(
		zcbor_state_t *state, struct zcbor_string *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 37)
	&& (zcbor_bstr_decode(state, (&(*result))))
	&& ((((((*result).len == 16)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_tagged_bytes(
		zcbor_state_t *state, struct zcbor_string *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 560)
	&& (zcbor_bstr_decode(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_class_id_type_choice(
		zcbor_state_t *state, struct class_id_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_tagged_oid_type(state, (&(*result).class_id_type_choice_tagged_oid_type_m)))) && (((*result).class_id_type_choice_choice = class_id_type_choice_tagged_oid_type_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_tagged_uuid_type(state, (&(*result).class_id_type_choice_tagged_uuid_type_m)))) && (((*result).class_id_type_choice_choice = class_id_type_choice_tagged_uuid_type_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_tagged_bytes(state, (&(*result).class_id_type_choice_tagged_bytes_m)))) && (((*result).class_id_type_choice_choice = class_id_type_choice_tagged_bytes_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_class_map_class_id(
		zcbor_state_t *state, struct class_map_class_id_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (decode_class_id_type_choice(state, (&(*result).class_map_class_id)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_class_map_vendor(
		zcbor_state_t *state, struct class_map_vendor_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (zcbor_tstr_decode(state, (&(*result).class_map_vendor)))
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

static bool decode_repeated_class_map_model(
		zcbor_state_t *state, struct class_map_model_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (zcbor_tstr_decode(state, (&(*result).class_map_model)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_class_map_layer(
		zcbor_state_t *state, struct class_map_layer_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){3}))
	&& (zcbor_uint32_decode(state, (&(*result).class_map_layer)))
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

static bool decode_repeated_class_map_index(
		zcbor_state_t *state, struct class_map_index_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){4}))
	&& (zcbor_uint32_decode(state, (&(*result).class_map_index)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){4}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_class_map(
		zcbor_state_t *state, struct class_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_present_decode_w_backup(&((*result).class_map_class_id_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_class_map_class_id), state, (&(*result).class_map_class_id)))
	&& (zcbor_present_decode_w_backup(&((*result).class_map_vendor_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_class_map_vendor), state, (&(*result).class_map_vendor)))
	&& (zcbor_present_decode_w_backup(&((*result).class_map_model_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_class_map_model), state, (&(*result).class_map_model)))
	&& (zcbor_present_decode_w_backup(&((*result).class_map_layer_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_class_map_layer), state, (&(*result).class_map_layer)))
	&& (zcbor_present_decode_w_backup(&((*result).class_map_index_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_class_map_index), state, (&(*result).class_map_index)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_class_map_class_id(state, (&(*result).class_map_class_id));
		decode_repeated_class_map_vendor(state, (&(*result).class_map_vendor));
		decode_repeated_class_map_model(state, (&(*result).class_map_model));
		decode_repeated_class_map_layer(state, (&(*result).class_map_layer));
		decode_repeated_class_map_index(state, (&(*result).class_map_index));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_environment_map_class(
		zcbor_state_t *state, struct environment_map_class_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (decode_class_map(state, (&(*result).environment_map_class)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_tagged_ueid_type(
		zcbor_state_t *state, struct zcbor_string *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 550)
	&& (zcbor_bstr_decode(state, (&(*result))))
	&& ((((((*result).len >= 7)
	&& ((*result).len <= 33)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_instance_id_type_choice(
		zcbor_state_t *state, struct instance_id_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_tagged_ueid_type(state, (&(*result).instance_id_type_choice_tagged_ueid_type_m)))) && (((*result).instance_id_type_choice_choice = instance_id_type_choice_tagged_ueid_type_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_tagged_uuid_type(state, (&(*result).instance_id_type_choice_tagged_uuid_type_m)))) && (((*result).instance_id_type_choice_choice = instance_id_type_choice_tagged_uuid_type_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((decode_tagged_bytes(state, (&(*result).instance_id_type_choice_tagged_bytes_m)))) && (((*result).instance_id_type_choice_choice = instance_id_type_choice_tagged_bytes_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_environment_map_instance(
		zcbor_state_t *state, struct environment_map_instance_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (decode_instance_id_type_choice(state, (&(*result).environment_map_instance)))
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

static bool decode_group_id_type_choice(
		zcbor_state_t *state, struct group_id_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_tagged_uuid_type(state, (&(*result).group_id_type_choice_tagged_uuid_type_m)))) && (((*result).group_id_type_choice_choice = group_id_type_choice_tagged_uuid_type_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_tagged_bytes(state, (&(*result).group_id_type_choice_tagged_bytes_m)))) && (((*result).group_id_type_choice_choice = group_id_type_choice_tagged_bytes_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_environment_map_group(
		zcbor_state_t *state, struct environment_map_group_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (decode_group_id_type_choice(state, (&(*result).environment_map_group)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_environment_map(
		zcbor_state_t *state, struct environment_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_present_decode_w_backup(&((*result).environment_map_class_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_environment_map_class), state, (&(*result).environment_map_class)))
	&& (zcbor_present_decode_w_backup(&((*result).environment_map_instance_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_environment_map_instance), state, (&(*result).environment_map_instance)))
	&& (zcbor_present_decode_w_backup(&((*result).environment_map_group_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_environment_map_group), state, (&(*result).environment_map_group)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_environment_map_class(state, (&(*result).environment_map_class));
		decode_repeated_environment_map_instance(state, (&(*result).environment_map_instance));
		decode_repeated_environment_map_group(state, (&(*result).environment_map_group));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_measured_element_type_choice(
		zcbor_state_t *state, struct measured_element_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_tagged_oid_type(state, (&(*result).measured_element_type_choice_tagged_oid_type_m)))) && (((*result).measured_element_type_choice_choice = measured_element_type_choice_tagged_oid_type_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_tagged_uuid_type(state, (&(*result).measured_element_type_choice_tagged_uuid_type_m)))) && (((*result).measured_element_type_choice_choice = measured_element_type_choice_tagged_uuid_type_m_c), true)))
	|| (zcbor_union_elem_code(state) && (((zcbor_uint32_decode(state, (&(*result).measured_element_type_choice_uint)))) && (((*result).measured_element_type_choice_choice = measured_element_type_choice_uint_c), true)))
	|| (((zcbor_tstr_decode(state, (&(*result).measured_element_type_choice_tstr)))) && (((*result).measured_element_type_choice_choice = measured_element_type_choice_tstr_c), true))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_map_mkey(
		zcbor_state_t *state, struct measurement_map_mkey_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (decode_measured_element_type_choice(state, (&(*result).measurement_map_mkey)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_version_scheme_type_choice(
		zcbor_state_t *state, struct version_scheme_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_uint8_expect_union(state, (1)))) && (((*result).version_scheme_type_choice_choice = version_scheme_type_choice_multipartnumeric_m_c), true))
	|| (((zcbor_uint8_expect_union(state, (2)))) && (((*result).version_scheme_type_choice_choice = version_scheme_type_choice_multipartnumeric_suffix_m_c), true))
	|| (((zcbor_uint8_expect_union(state, (3)))) && (((*result).version_scheme_type_choice_choice = version_scheme_type_choice_alphanumeric_m_c), true))
	|| (((zcbor_uint8_expect_union(state, (4)))) && (((*result).version_scheme_type_choice_choice = version_scheme_type_choice_decimal_m_c), true))
	|| (((zcbor_uint16_expect_union(state, (16384)))) && (((*result).version_scheme_type_choice_choice = version_scheme_type_choice_semver_m_c), true))
	|| (((zcbor_int32_decode(state, (&(*result).version_scheme_type_choice_int)))) && (((*result).version_scheme_type_choice_choice = version_scheme_type_choice_int_c), true))
	|| (((zcbor_tstr_decode(state, (&(*result).version_scheme_type_choice_text_m)))) && (((*result).version_scheme_type_choice_choice = version_scheme_type_choice_text_m_c), true))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_version_map_scheme(
		zcbor_state_t *state, struct version_map_scheme_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (decode_version_scheme_type_choice(state, (&(*result).version_map_scheme)))
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

static bool decode_version_map(
		zcbor_state_t *state, struct version_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (zcbor_tstr_decode(state, (&(*result).version_map_version)))
	&& zcbor_elem_processed(state))
	&& (zcbor_present_decode_w_backup(&((*result).version_map_scheme_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_version_map_scheme), state, (&(*result).version_map_scheme)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_version_map_scheme(state, (&(*result).version_map_scheme));
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_version(
		zcbor_state_t *state, struct measurement_values_map_version_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (decode_version_map(state, (&(*result).measurement_values_map_version)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_tagged_svn(
		zcbor_state_t *state, uint32_t *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 552)
	&& (zcbor_uint32_decode(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_tagged_min_svn(
		zcbor_state_t *state, uint32_t *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 553)
	&& (zcbor_uint32_decode(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_svn_type_choice(
		zcbor_state_t *state, struct svn_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_uint32_decode(state, (&(*result).svn_type_choice_svn_val_m)))) && (((*result).svn_type_choice_choice = svn_type_choice_svn_val_m_c), true))
	|| (((decode_tagged_svn(state, (&(*result).svn_type_choice_tagged_svn_m)))) && (((*result).svn_type_choice_choice = svn_type_choice_tagged_svn_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_tagged_min_svn(state, (&(*result).svn_type_choice_tagged_min_svn_m)))) && (((*result).svn_type_choice_choice = svn_type_choice_tagged_min_svn_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_svn(
		zcbor_state_t *state, struct measurement_values_map_svn_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (decode_svn_type_choice(state, (&(*result).measurement_values_map_svn)))
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

static bool decode_digests_type(
		zcbor_state_t *state, struct digests_type *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).digests_type_digest_m_count, ZCBOR_CUSTOM_CAST_FP(decode_digest), state, (*&(*result).digests_type_digest_m), sizeof(struct digest))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_digest(state, (*&(*result).digests_type_digest_m));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_digests(
		zcbor_state_t *state, struct measurement_values_map_digests_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (decode_digests_type(state, (&(*result).measurement_values_map_digests)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_flags_map_is_configured(
		zcbor_state_t *state, struct flags_map_is_configured_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (zcbor_bool_decode(state, (&(*result).flags_map_is_configured)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_flags_map_is_secure(
		zcbor_state_t *state, struct flags_map_is_secure_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (zcbor_bool_decode(state, (&(*result).flags_map_is_secure)))
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

static bool decode_repeated_flags_map_is_recovery(
		zcbor_state_t *state, struct flags_map_is_recovery_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (zcbor_bool_decode(state, (&(*result).flags_map_is_recovery)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_flags_map_is_debug(
		zcbor_state_t *state, struct flags_map_is_debug_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){3}))
	&& (zcbor_bool_decode(state, (&(*result).flags_map_is_debug)))
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

static bool decode_repeated_flags_map_is_replay_protected(
		zcbor_state_t *state, struct flags_map_is_replay_protected_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){4}))
	&& (zcbor_bool_decode(state, (&(*result).flags_map_is_replay_protected)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){4}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_flags_map_is_integrity_protected(
		zcbor_state_t *state, struct flags_map_is_integrity_protected_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){5}))
	&& (zcbor_bool_decode(state, (&(*result).flags_map_is_integrity_protected)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){5}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_flags_map_is_runtime_meas(
		zcbor_state_t *state, struct flags_map_is_runtime_meas_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){6}))
	&& (zcbor_bool_decode(state, (&(*result).flags_map_is_runtime_meas)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){6}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_flags_map_is_immutable(
		zcbor_state_t *state, struct flags_map_is_immutable_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){7}))
	&& (zcbor_bool_decode(state, (&(*result).flags_map_is_immutable)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){7}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_flags_map_is_tcb(
		zcbor_state_t *state, struct flags_map_is_tcb_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){8}))
	&& (zcbor_bool_decode(state, (&(*result).flags_map_is_tcb)))
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

static bool decode_repeated_flags_map_is_confidentiality_protected(
		zcbor_state_t *state, struct flags_map_is_confidentiality_protected_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){9}))
	&& (zcbor_bool_decode(state, (&(*result).flags_map_is_confidentiality_protected)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){9}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_flags_map(
		zcbor_state_t *state, struct flags_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_present_decode_w_backup(&((*result).flags_map_is_configured_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_flags_map_is_configured), state, (&(*result).flags_map_is_configured)))
	&& (zcbor_present_decode_w_backup(&((*result).flags_map_is_secure_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_flags_map_is_secure), state, (&(*result).flags_map_is_secure)))
	&& (zcbor_present_decode_w_backup(&((*result).flags_map_is_recovery_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_flags_map_is_recovery), state, (&(*result).flags_map_is_recovery)))
	&& (zcbor_present_decode_w_backup(&((*result).flags_map_is_debug_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_flags_map_is_debug), state, (&(*result).flags_map_is_debug)))
	&& (zcbor_present_decode_w_backup(&((*result).flags_map_is_replay_protected_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_flags_map_is_replay_protected), state, (&(*result).flags_map_is_replay_protected)))
	&& (zcbor_present_decode_w_backup(&((*result).flags_map_is_integrity_protected_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_flags_map_is_integrity_protected), state, (&(*result).flags_map_is_integrity_protected)))
	&& (zcbor_present_decode_w_backup(&((*result).flags_map_is_runtime_meas_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_flags_map_is_runtime_meas), state, (&(*result).flags_map_is_runtime_meas)))
	&& (zcbor_present_decode_w_backup(&((*result).flags_map_is_immutable_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_flags_map_is_immutable), state, (&(*result).flags_map_is_immutable)))
	&& (zcbor_present_decode_w_backup(&((*result).flags_map_is_tcb_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_flags_map_is_tcb), state, (&(*result).flags_map_is_tcb)))
	&& (zcbor_present_decode_w_backup(&((*result).flags_map_is_confidentiality_protected_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_flags_map_is_confidentiality_protected), state, (&(*result).flags_map_is_confidentiality_protected)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_flags_map_is_configured(state, (&(*result).flags_map_is_configured));
		decode_repeated_flags_map_is_secure(state, (&(*result).flags_map_is_secure));
		decode_repeated_flags_map_is_recovery(state, (&(*result).flags_map_is_recovery));
		decode_repeated_flags_map_is_debug(state, (&(*result).flags_map_is_debug));
		decode_repeated_flags_map_is_replay_protected(state, (&(*result).flags_map_is_replay_protected));
		decode_repeated_flags_map_is_integrity_protected(state, (&(*result).flags_map_is_integrity_protected));
		decode_repeated_flags_map_is_runtime_meas(state, (&(*result).flags_map_is_runtime_meas));
		decode_repeated_flags_map_is_immutable(state, (&(*result).flags_map_is_immutable));
		decode_repeated_flags_map_is_tcb(state, (&(*result).flags_map_is_tcb));
		decode_repeated_flags_map_is_confidentiality_protected(state, (&(*result).flags_map_is_confidentiality_protected));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_flags(
		zcbor_state_t *state, struct measurement_values_map_flags_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){3}))
	&& (decode_flags_map(state, (&(*result).measurement_values_map_flags)))
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

static bool decode_tagged_masked_raw_value(
		zcbor_state_t *state, struct tagged_masked_raw_value *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 563)
	&& (zcbor_list_start_decode(state) && ((((zcbor_bstr_decode(state, (&(*result).tagged_masked_raw_value_value))))
	&& ((zcbor_bstr_decode(state, (&(*result).tagged_masked_raw_value_mask))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_raw_value_type_choice(
		zcbor_state_t *state, struct raw_value_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_tagged_bytes(state, (&(*result).raw_value_type_choice_tagged_bytes_m)))) && (((*result).raw_value_type_choice_choice = raw_value_type_choice_tagged_bytes_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_tagged_masked_raw_value(state, (&(*result).raw_value_type_choice_tagged_masked_raw_value_m)))) && (((*result).raw_value_type_choice_choice = raw_value_type_choice_tagged_masked_raw_value_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_raw_value(
		zcbor_state_t *state, struct measurement_values_map_raw_value_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){4}))
	&& (decode_raw_value_type_choice(state, (&(*result).measurement_values_map_raw_value)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){4}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_raw_value_mask_DEPRECATED(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){5}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){5}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_mac_addr(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){6}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){6}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_ip_addr(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){7}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){7}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_serial_number(
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

static bool decode_repeated_measurement_values_map_ueid(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){9}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){9}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_uuid(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){10}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){10}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_name(
		zcbor_state_t *state, struct measurement_values_map_name_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){11}))
	&& (zcbor_tstr_decode(state, (&(*result).measurement_values_map_name)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){11}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_spdm_indirect_map_index(
		zcbor_state_t *state, struct spdm_indirect_map_index_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, 64, &(*result).spdm_indirect_map_index_uint_count, ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_decode), state, (*&(*result).spdm_indirect_map_index_uint), sizeof(uint32_t))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint32_decode(state, (*&(*result).spdm_indirect_map_index_uint));
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_spdm_indirect_map_intany(
		zcbor_state_t *state, struct spdm_indirect_map_intany_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_int32_decode), state, (&(*result).spdm_indirect_map_intany_key))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_int32_decode(state, (&(*result).spdm_indirect_map_intany_key));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_spdm_indirect_map(
		zcbor_state_t *state, struct spdm_indirect_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_present_decode_w_backup(&((*result).spdm_indirect_map_index_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_spdm_indirect_map_index), state, (&(*result).spdm_indirect_map_index)))
	&& zcbor_multi_decode_w_backup(0, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).spdm_indirect_map_intany_count, ZCBOR_CUSTOM_CAST_FP(decode_repeated_spdm_indirect_map_intany), state, (*&(*result).spdm_indirect_map_intany), sizeof(struct spdm_indirect_map_intany_r))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_spdm_indirect_map_intany(state, (*&(*result).spdm_indirect_map_intany));
		decode_repeated_spdm_indirect_map_index(state, (&(*result).spdm_indirect_map_index));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_spdm_indirect(
		zcbor_state_t *state, struct measurement_values_map_spdm_indirect_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){12}))
	&& (decode_spdm_indirect_map(state, (&(*result).measurement_values_map_spdm_indirect)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){12}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_cryptokeys(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){13}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){13}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_integrity_registers(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){14}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){14}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_int_range_type(
		zcbor_state_t *state, struct int_range_type *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_list_start_decode(state) && ((((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).int_range_type_min_int)))) && (((*result).int_range_type_min_choice = int_range_type_min_int_c), true))
	|| (((zcbor_nil_expect(state, NULL))) && (((*result).int_range_type_min_choice = int_range_type_min_negative_inf_m_c), true))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).int_range_type_max_int)))) && (((*result).int_range_type_max_choice = int_range_type_max_int_c), true))
	|| (((zcbor_nil_expect(state, NULL))) && (((*result).int_range_type_max_choice = int_range_type_max_positive_inf_m_c), true))), zcbor_union_end_code(state), int_res)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_tagged_int_range(
		zcbor_state_t *state, struct int_range_type *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 564)
	&& (decode_int_range_type(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_int_range_type_choice(
		zcbor_state_t *state, struct int_range_type_choice *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).int_range_type_choice_int)))) && (((*result).int_range_type_choice_choice = int_range_type_choice_int_c), true))
	|| (((decode_tagged_int_range(state, (&(*result).int_range_type_choice_tagged_int_range_m)))) && (((*result).int_range_type_choice_choice = int_range_type_choice_tagged_int_range_m_c), true))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_values_map_int_range(
		zcbor_state_t *state, struct measurement_values_map_int_range_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){15}))
	&& (decode_int_range_type_choice(state, (&(*result).measurement_values_map_int_range)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){15}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_measurement_values_map(
		zcbor_state_t *state, struct measurement_values_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_present_decode_w_backup(&((*result).measurement_values_map_version_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_version), state, (&(*result).measurement_values_map_version)))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_svn_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_svn), state, (&(*result).measurement_values_map_svn)))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_digests_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_digests), state, (&(*result).measurement_values_map_digests)))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_flags_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_flags), state, (&(*result).measurement_values_map_flags)))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_raw_value_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_raw_value), state, (&(*result).measurement_values_map_raw_value)))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_raw_value_mask_DEPRECATED_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_raw_value_mask_DEPRECATED), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_mac_addr_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_mac_addr), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_ip_addr_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_ip_addr), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_serial_number_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_serial_number), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_ueid_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_ueid), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_uuid_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_uuid), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_name_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_name), state, (&(*result).measurement_values_map_name)))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_spdm_indirect_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_spdm_indirect), state, (&(*result).measurement_values_map_spdm_indirect)))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_cryptokeys_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_cryptokeys), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_integrity_registers_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_integrity_registers), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_values_map_int_range_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_values_map_int_range), state, (&(*result).measurement_values_map_int_range)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_measurement_values_map_version(state, (&(*result).measurement_values_map_version));
		decode_repeated_measurement_values_map_svn(state, (&(*result).measurement_values_map_svn));
		decode_repeated_measurement_values_map_digests(state, (&(*result).measurement_values_map_digests));
		decode_repeated_measurement_values_map_flags(state, (&(*result).measurement_values_map_flags));
		decode_repeated_measurement_values_map_raw_value(state, (&(*result).measurement_values_map_raw_value));
		decode_repeated_measurement_values_map_raw_value_mask_DEPRECATED(state, NULL);
		decode_repeated_measurement_values_map_mac_addr(state, NULL);
		decode_repeated_measurement_values_map_ip_addr(state, NULL);
		decode_repeated_measurement_values_map_serial_number(state, NULL);
		decode_repeated_measurement_values_map_ueid(state, NULL);
		decode_repeated_measurement_values_map_uuid(state, NULL);
		decode_repeated_measurement_values_map_name(state, (&(*result).measurement_values_map_name));
		decode_repeated_measurement_values_map_spdm_indirect(state, (&(*result).measurement_values_map_spdm_indirect));
		decode_repeated_measurement_values_map_cryptokeys(state, NULL);
		decode_repeated_measurement_values_map_integrity_registers(state, NULL);
		decode_repeated_measurement_values_map_int_range(state, (&(*result).measurement_values_map_int_range));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_measurement_map_authorized_by(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_measurement_map(
		zcbor_state_t *state, struct measurement_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_present_decode_w_backup(&((*result).measurement_map_mkey_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_map_mkey), state, (&(*result).measurement_map_mkey)))
	&& (zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (decode_measurement_values_map(state, (&(*result).measurement_map_mval)))
	&& zcbor_elem_processed(state))
	&& (zcbor_present_decode_w_backup(&((*result).measurement_map_authorized_by_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_measurement_map_authorized_by), state, NULL))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_measurement_map_mkey(state, (&(*result).measurement_map_mkey));
		decode_repeated_measurement_map_authorized_by(state, NULL);
		zcbor_uint8_pexpect(state, (&(uint8_t){1}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_reference_triple_record(
		zcbor_state_t *state, struct reference_triple_record *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((decode_environment_map(state, (&(*result).reference_triple_record_ref_env))))
	&& ((zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, 50, &(*result).reference_triple_record_ref_claims_measurement_map_m_count, ZCBOR_CUSTOM_CAST_FP(decode_measurement_map), state, (*&(*result).reference_triple_record_ref_claims_measurement_map_m), sizeof(struct measurement_map))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_measurement_map(state, (*&(*result).reference_triple_record_ref_claims_measurement_map_m));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_triples_map_reference_triples(
		zcbor_state_t *state, struct triples_map_reference_triples_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, 50, &(*result).triples_map_reference_triples_reference_triple_record_m_count, ZCBOR_CUSTOM_CAST_FP(decode_reference_triple_record), state, (*&(*result).triples_map_reference_triples_reference_triple_record_m), sizeof(struct reference_triple_record))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_reference_triple_record(state, (*&(*result).triples_map_reference_triples_reference_triple_record_m));
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_triples_map_endorsed_triples(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (zcbor_any_skip(state, NULL))
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

static bool decode_repeated_triples_map_identity_triples(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_triples_map_attest_key_triples(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){3}))
	&& (zcbor_any_skip(state, NULL))
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

static bool decode_domain_dependency_triple_record(
		zcbor_state_t *state, struct domain_dependency_triple_record *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((decode_environment_map(state, (&(*result).domain_dependency_triple_record_domain_id))))
	&& ((zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, 64, &(*result).domain_dependency_triple_record_trustees_domain_type_m_count, ZCBOR_CUSTOM_CAST_FP(decode_environment_map), state, (*&(*result).domain_dependency_triple_record_trustees_domain_type_m), sizeof(struct environment_map))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_environment_map(state, (*&(*result).domain_dependency_triple_record_trustees_domain_type_m));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_triples_map_dependency_triples(
		zcbor_state_t *state, struct triples_map_dependency_triples_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){4}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).triples_map_dependency_triples_domain_dependency_triple_record_m_count, ZCBOR_CUSTOM_CAST_FP(decode_domain_dependency_triple_record), state, (*&(*result).triples_map_dependency_triples_domain_dependency_triple_record_m), sizeof(struct domain_dependency_triple_record))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_domain_dependency_triple_record(state, (*&(*result).triples_map_dependency_triples_domain_dependency_triple_record_m));
		zcbor_uint8_pexpect(state, (&(uint8_t){4}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_triples_map_membership_triples(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){5}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){5}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_triples_map_coswid_triples(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){6}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){6}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_triples_map_conditional_endorsement_series_triples(
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

static bool decode_repeated_triples_map_conditional_endorsement_triples(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){10}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){10}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_triples_map(
		zcbor_state_t *state, struct triples_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_present_decode_w_backup(&((*result).triples_map_reference_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_triples_map_reference_triples), state, (&(*result).triples_map_reference_triples)))
	&& (zcbor_present_decode_w_backup(&((*result).triples_map_endorsed_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_triples_map_endorsed_triples), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).triples_map_identity_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_triples_map_identity_triples), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).triples_map_attest_key_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_triples_map_attest_key_triples), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).triples_map_dependency_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_triples_map_dependency_triples), state, (&(*result).triples_map_dependency_triples)))
	&& (zcbor_present_decode_w_backup(&((*result).triples_map_membership_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_triples_map_membership_triples), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).triples_map_coswid_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_triples_map_coswid_triples), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).triples_map_conditional_endorsement_series_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_triples_map_conditional_endorsement_series_triples), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).triples_map_conditional_endorsement_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_triples_map_conditional_endorsement_triples), state, NULL))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_triples_map_reference_triples(state, (&(*result).triples_map_reference_triples));
		decode_repeated_triples_map_endorsed_triples(state, NULL);
		decode_repeated_triples_map_identity_triples(state, NULL);
		decode_repeated_triples_map_attest_key_triples(state, NULL);
		decode_repeated_triples_map_dependency_triples(state, (&(*result).triples_map_dependency_triples));
		decode_repeated_triples_map_membership_triples(state, NULL);
		decode_repeated_triples_map_coswid_triples(state, NULL);
		decode_repeated_triples_map_conditional_endorsement_series_triples(state, NULL);
		decode_repeated_triples_map_conditional_endorsement_triples(state, NULL);
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_concise_mid_tag_extension_key(
		zcbor_state_t *state, struct concise_mid_tag_extension_key_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(decode_extension_key), state, (&(*result).concise_mid_tag_extension_key_key))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_extension_key(state, (&(*result).concise_mid_tag_extension_key_key));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_evidence_triple_record(
		zcbor_state_t *state, struct evidence_triple_record *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_list_start_decode(state) && ((((decode_environment_map(state, (&(*result).evidence_triple_record_environment_map_m))))
	&& ((zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, 50, &(*result).evidence_triple_record_measurement_map_m_l_measurement_map_m_count, ZCBOR_CUSTOM_CAST_FP(decode_measurement_map), state, (*&(*result).evidence_triple_record_measurement_map_m_l_measurement_map_m), sizeof(struct measurement_map))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true)))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_measurement_map(state, (*&(*result).evidence_triple_record_measurement_map_m_l_measurement_map_m));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_ev_triples_map_evidence_triples(
		zcbor_state_t *state, struct ev_triples_map_evidence_triples_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, 100, &(*result).ev_triples_map_evidence_triples_evidence_triple_record_m_count, ZCBOR_CUSTOM_CAST_FP(decode_evidence_triple_record), state, (*&(*result).ev_triples_map_evidence_triples_evidence_triple_record_m), sizeof(struct evidence_triple_record))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_evidence_triple_record(state, (*&(*result).ev_triples_map_evidence_triples_evidence_triple_record_m));
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_ev_triples_map_identity_triples(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (zcbor_any_skip(state, NULL))
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

static bool decode_repeated_ev_triples_map_dependency_triples(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_ev_triples_map_membership_triples(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){3}))
	&& (zcbor_any_skip(state, NULL))
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

static bool decode_repeated_ev_triples_map_coswid_triples(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){4}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){4}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_ev_triples_map_attest_key_triples(
		zcbor_state_t *state, void *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){5}))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){5}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_ev_triples_map_intany(
		zcbor_state_t *state, struct ev_triples_map_intany_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_int32_decode), state, (&(*result).ev_triples_map_intany_key))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_int32_decode(state, (&(*result).ev_triples_map_intany_key));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_ev_triples_map(
		zcbor_state_t *state, struct ev_triples_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_present_decode_w_backup(&((*result).ev_triples_map_evidence_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_ev_triples_map_evidence_triples), state, (&(*result).ev_triples_map_evidence_triples)))
	&& (zcbor_present_decode_w_backup(&((*result).ev_triples_map_identity_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_ev_triples_map_identity_triples), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).ev_triples_map_dependency_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_ev_triples_map_dependency_triples), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).ev_triples_map_membership_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_ev_triples_map_membership_triples), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).ev_triples_map_coswid_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_ev_triples_map_coswid_triples), state, NULL))
	&& (zcbor_present_decode_w_backup(&((*result).ev_triples_map_attest_key_triples_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_ev_triples_map_attest_key_triples), state, NULL))
	&& zcbor_multi_decode_w_backup(0, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).ev_triples_map_intany_count, ZCBOR_CUSTOM_CAST_FP(decode_repeated_ev_triples_map_intany), state, (*&(*result).ev_triples_map_intany), sizeof(struct ev_triples_map_intany_r))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_ev_triples_map_intany(state, (*&(*result).ev_triples_map_intany));
		decode_repeated_ev_triples_map_evidence_triples(state, (&(*result).ev_triples_map_evidence_triples));
		decode_repeated_ev_triples_map_identity_triples(state, NULL);
		decode_repeated_ev_triples_map_dependency_triples(state, NULL);
		decode_repeated_ev_triples_map_membership_triples(state, NULL);
		decode_repeated_ev_triples_map_coswid_triples(state, NULL);
		decode_repeated_ev_triples_map_attest_key_triples(state, NULL);
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_concise_evidence_map_evidence_id(
		zcbor_state_t *state, struct concise_evidence_map_evidence_id_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (decode_tagged_uuid_type(state, (&(*result).concise_evidence_map_evidence_id)))
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

static bool decode_repeated_concise_evidence_map_profile(
		zcbor_state_t *state, struct concise_evidence_map_profile_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (decode_profile_type_choice(state, (&(*result).concise_evidence_map_profile)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_concise_evidence_map_intany(
		zcbor_state_t *state, struct concise_evidence_map_intany_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_int32_decode), state, (&(*result).concise_evidence_map_intany_key))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_int32_decode(state, (&(*result).concise_evidence_map_intany_key));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_concise_evidence_map(
		zcbor_state_t *state, struct concise_evidence_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (decode_ev_triples_map(state, (&(*result).concise_evidence_map_ev_triples)))
	&& zcbor_elem_processed(state))
	&& (zcbor_present_decode_w_backup(&((*result).concise_evidence_map_evidence_id_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_concise_evidence_map_evidence_id), state, (&(*result).concise_evidence_map_evidence_id)))
	&& (zcbor_present_decode_w_backup(&((*result).concise_evidence_map_profile_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_concise_evidence_map_profile), state, (&(*result).concise_evidence_map_profile)))
	&& zcbor_multi_decode_w_backup(0, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).concise_evidence_map_intany_count, ZCBOR_CUSTOM_CAST_FP(decode_repeated_concise_evidence_map_intany), state, (*&(*result).concise_evidence_map_intany), sizeof(struct concise_evidence_map_intany_r))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_concise_evidence_map_intany(state, (*&(*result).concise_evidence_map_intany));
		decode_repeated_concise_evidence_map_evidence_id(state, (&(*result).concise_evidence_map_evidence_id));
		decode_repeated_concise_evidence_map_profile(state, (&(*result).concise_evidence_map_profile));
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_tagged_concise_evidence(
		zcbor_state_t *state, struct concise_evidence_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 571)
	&& (decode_concise_evidence_map(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_spdm_toc_map_rim_locators(
		zcbor_state_t *state, struct spdm_toc_map_rim_locators_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, 8, &(*result).spdm_toc_map_rim_locators_corim_locator_map_m_count, ZCBOR_CUSTOM_CAST_FP(decode_corim_locator_map), state, (*&(*result).spdm_toc_map_rim_locators_corim_locator_map_m), sizeof(struct corim_locator_map))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_corim_locator_map(state, (*&(*result).spdm_toc_map_rim_locators_corim_locator_map_m));
		zcbor_uint8_pexpect(state, (&(uint8_t){1}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_spdm_toc_map_profile(
		zcbor_state_t *state, struct spdm_toc_map_profile_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){2}))
	&& (decode_profile_type_choice(state, (&(*result).spdm_toc_map_profile)))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_uint8_pexpect(state, (&(uint8_t){2}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_repeated_spdm_toc_map_intany(
		zcbor_state_t *state, struct spdm_toc_map_intany_r *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_int32_decode), state, (&(*result).spdm_toc_map_intany_key))
	&& (zcbor_any_skip(state, NULL))
	&& zcbor_elem_processed(state)));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		zcbor_int32_decode(state, (&(*result).spdm_toc_map_intany_key));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_spdm_toc_map(
		zcbor_state_t *state, struct spdm_toc_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint32_pexpect), state, (&(uint32_t){0}))
	&& (zcbor_list_start_decode(state) && ((zcbor_multi_decode(1, 8, &(*result).spdm_toc_map_tagged_evidence_tagged_concise_evidence_m_count, ZCBOR_CUSTOM_CAST_FP(decode_tagged_concise_evidence), state, (*&(*result).spdm_toc_map_tagged_evidence_tagged_concise_evidence_m), sizeof(struct concise_evidence_map))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state, true))
	&& zcbor_elem_processed(state))
	&& (zcbor_present_decode_w_backup(&((*result).spdm_toc_map_rim_locators_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_spdm_toc_map_rim_locators), state, (&(*result).spdm_toc_map_rim_locators)))
	&& (zcbor_present_decode_w_backup(&((*result).spdm_toc_map_profile_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_spdm_toc_map_profile), state, (&(*result).spdm_toc_map_profile)))
	&& zcbor_multi_decode_w_backup(0, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).spdm_toc_map_intany_count, ZCBOR_CUSTOM_CAST_FP(decode_repeated_spdm_toc_map_intany), state, (*&(*result).spdm_toc_map_intany), sizeof(struct spdm_toc_map_intany_r))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_tagged_concise_evidence(state, (*&(*result).spdm_toc_map_tagged_evidence_tagged_concise_evidence_m));
		decode_repeated_spdm_toc_map_intany(state, (*&(*result).spdm_toc_map_intany));
		decode_repeated_spdm_toc_map_rim_locators(state, (&(*result).spdm_toc_map_rim_locators));
		decode_repeated_spdm_toc_map_profile(state, (&(*result).spdm_toc_map_profile));
		zcbor_uint32_pexpect(state, (&(uint32_t){0}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_eat_claims_map(
		zcbor_state_t *state, struct eat_claims_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){10}))
	&& (zcbor_bstr_decode(state, (&(*result).eat_claims_map_nonce)))
	&& ((((*result).eat_claims_map_nonce.len >= 8)
	&& ((*result).eat_claims_map_nonce.len <= 64)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& zcbor_elem_processed(state))
	&& (zcbor_present_decode_w_backup(&((*result).eat_claims_map_dbgstat_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_eat_claims_map_dbgstat), state, (&(*result).eat_claims_map_dbgstat)))
	&& (zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint16_pexpect), state, (&(uint16_t){265}))
	&& (decode_eat_profile_type_choice(state, (&(*result).eat_claims_map_eat_profile)))
	&& zcbor_elem_processed(state))
	&& (zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint16_pexpect), state, (&(uint16_t){273}))
	&& (decode_measurements_type(state, (&(*result).eat_claims_map_measurements)))
	&& zcbor_elem_processed(state))
	&& (zcbor_present_decode_w_backup(&((*result).eat_claims_map_iss_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_eat_claims_map_iss), state, (&(*result).eat_claims_map_iss)))
	&& (zcbor_present_decode_w_backup(&((*result).eat_claims_map_cti_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_eat_claims_map_cti), state, (&(*result).eat_claims_map_cti)))
	&& (zcbor_present_decode_w_backup(&((*result).eat_claims_map_ueid_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_eat_claims_map_ueid), state, (&(*result).eat_claims_map_ueid)))
	&& (zcbor_present_decode_w_backup(&((*result).eat_claims_map_sueid_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_eat_claims_map_sueid), state, (&(*result).eat_claims_map_sueid)))
	&& (zcbor_present_decode_w_backup(&((*result).eat_claims_map_oemid_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_eat_claims_map_oemid), state, (&(*result).eat_claims_map_oemid)))
	&& (zcbor_present_decode_w_backup(&((*result).eat_claims_map_hwmodel_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_eat_claims_map_hwmodel), state, (&(*result).eat_claims_map_hwmodel)))
	&& (zcbor_present_decode_w_backup(&((*result).eat_claims_map_uptime_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_eat_claims_map_uptime), state, (&(*result).eat_claims_map_uptime)))
	&& (zcbor_present_decode_w_backup(&((*result).eat_claims_map_bootcount_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_eat_claims_map_bootcount), state, (&(*result).eat_claims_map_bootcount)))
	&& (zcbor_present_decode_w_backup(&((*result).eat_claims_map_bootseed_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_eat_claims_map_bootseed), state, (&(*result).eat_claims_map_bootseed)))
	&& (zcbor_present_decode_w_backup(&((*result).eat_claims_map_rim_locators_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_eat_claims_map_rim_locators), state, (&(*result).eat_claims_map_rim_locators)))
	&& zcbor_multi_decode_w_backup(0, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).eat_claims_map_intany_count, ZCBOR_CUSTOM_CAST_FP(decode_repeated_eat_claims_map_intany), state, (*&(*result).eat_claims_map_intany), sizeof(struct eat_claims_map_intany_r))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_eat_claims_map_intany(state, (*&(*result).eat_claims_map_intany));
		decode_repeated_eat_claims_map_dbgstat(state, (&(*result).eat_claims_map_dbgstat));
		decode_repeated_eat_claims_map_iss(state, (&(*result).eat_claims_map_iss));
		decode_repeated_eat_claims_map_cti(state, (&(*result).eat_claims_map_cti));
		decode_repeated_eat_claims_map_ueid(state, (&(*result).eat_claims_map_ueid));
		decode_repeated_eat_claims_map_sueid(state, (&(*result).eat_claims_map_sueid));
		decode_repeated_eat_claims_map_oemid(state, (&(*result).eat_claims_map_oemid));
		decode_repeated_eat_claims_map_hwmodel(state, (&(*result).eat_claims_map_hwmodel));
		decode_repeated_eat_claims_map_uptime(state, (&(*result).eat_claims_map_uptime));
		decode_repeated_eat_claims_map_bootcount(state, (&(*result).eat_claims_map_bootcount));
		decode_repeated_eat_claims_map_bootseed(state, (&(*result).eat_claims_map_bootseed));
		decode_repeated_eat_claims_map_rim_locators(state, (&(*result).eat_claims_map_rim_locators));
		zcbor_uint8_pexpect(state, (&(uint8_t){10}));
		zcbor_uint16_pexpect(state, (&(uint16_t){265}));
		zcbor_uint16_pexpect(state, (&(uint16_t){273}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_concise_evidence(
		zcbor_state_t *state, struct concise_evidence *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool res = (((zcbor_union_start_code(state) && (int_res = ((((decode_concise_evidence_map(state, (&(*result).concise_evidence_map_m)))) && (((*result).concise_evidence_choice = concise_evidence_map_m_c), true))
	|| (zcbor_union_elem_code(state) && (((decode_tagged_concise_evidence(state, (&(*result).tagged_concise_evidence_m)))) && (((*result).concise_evidence_choice = tagged_concise_evidence_m_c), true)))), zcbor_union_end_code(state), int_res))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_tagged_spdm_toc(
		zcbor_state_t *state, struct spdm_toc_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 570)
	&& (decode_spdm_toc_map(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_concise_mid_tag(
		zcbor_state_t *state, struct concise_mid_tag *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((zcbor_unordered_map_start_decode(state) && (((zcbor_present_decode_w_backup(&((*result).concise_mid_tag_language_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_concise_mid_tag_language), state, (&(*result).concise_mid_tag_language)))
	&& (zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){1}))
	&& (decode_tag_identity_map(state, (&(*result).concise_mid_tag_tag_identity)))
	&& zcbor_elem_processed(state))
	&& (zcbor_present_decode_w_backup(&((*result).concise_mid_tag_entities_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_concise_mid_tag_entities), state, (&(*result).concise_mid_tag_entities)))
	&& (zcbor_present_decode_w_backup(&((*result).concise_mid_tag_linked_tags_present), ZCBOR_CUSTOM_CAST_FP(decode_repeated_concise_mid_tag_linked_tags), state, NULL))
	&& (zcbor_unordered_map_search(ZCBOR_CUSTOM_CAST_FP(zcbor_uint8_pexpect), state, (&(uint8_t){4}))
	&& (decode_triples_map(state, (&(*result).concise_mid_tag_triples)))
	&& zcbor_elem_processed(state))
	&& zcbor_multi_decode_w_backup(0, ZCBOR_CORIM_DEFAULT_MAX_QTY, &(*result).concise_mid_tag_extension_key_count, ZCBOR_CUSTOM_CAST_FP(decode_repeated_concise_mid_tag_extension_key), state, (*&(*result).concise_mid_tag_extension_key), sizeof(struct concise_mid_tag_extension_key_r))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_unordered_map_end_decode(state, true))));

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_repeated_concise_mid_tag_extension_key(state, (*&(*result).concise_mid_tag_extension_key));
		decode_repeated_concise_mid_tag_language(state, (&(*result).concise_mid_tag_language));
		decode_repeated_concise_mid_tag_entities(state, (&(*result).concise_mid_tag_entities));
		decode_repeated_concise_mid_tag_linked_tags(state, NULL);
		zcbor_uint8_pexpect(state, (&(uint8_t){1}));
		zcbor_uint8_pexpect(state, (&(uint8_t){4}));
	}

	log_result(state, res, __func__);
	return res;
}

static bool decode_tagged_unsigned_corim_map(
		zcbor_state_t *state, struct corim_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = ((zcbor_tag_expect(state, 501)
	&& (decode_corim_map(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}

static bool decode_corim(
		zcbor_state_t *state, struct corim_map *result)
{
	zcbor_log("%s\r\n", __func__);

	bool res = (((decode_tagged_unsigned_corim_map(state, (&(*result))))));

	log_result(state, res, __func__);
	return res;
}



int cbor_decode_corim(
		const uint8_t *payload, size_t payload_len,
		struct corim_map *result,
		size_t *payload_len_out)
{
	const size_t num_flags = (((((24 + ZCBOR_ROUND_UP(1 + 1 + 1 + 1 + 1 + 1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 3)))));
	zcbor_state_t states[9 + ZCBOR_EXTRA_STATES + ZCBOR_FLAG_STATES(num_flags)];

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_corim(states, result);
	}

	return zcbor_entry_function_with_elem_states(payload, payload_len, (void *)result, payload_len_out, states, (zcbor_decoder_t *)ZCBOR_CUSTOM_CAST_FP(decode_corim), sizeof(states) / sizeof(zcbor_state_t), ZCBOR_LARGE_ELEM_COUNT, num_flags);
}


int cbor_decode_tagged_unsigned_corim_map(
		const uint8_t *payload, size_t payload_len,
		struct corim_map *result,
		size_t *payload_len_out)
{
	const size_t num_flags = (((24 + ZCBOR_ROUND_UP(1 + 1 + 1 + 1 + 1 + 1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 3)));
	zcbor_state_t states[9 + ZCBOR_EXTRA_STATES + ZCBOR_FLAG_STATES(num_flags)];

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_tagged_unsigned_corim_map(states, result);
	}

	return zcbor_entry_function_with_elem_states(payload, payload_len, (void *)result, payload_len_out, states, (zcbor_decoder_t *)ZCBOR_CUSTOM_CAST_FP(decode_tagged_unsigned_corim_map), sizeof(states) / sizeof(zcbor_state_t), ZCBOR_LARGE_ELEM_COUNT, num_flags);
}


int cbor_decode_concise_mid_tag(
		const uint8_t *payload, size_t payload_len,
		struct concise_mid_tag *result,
		size_t *payload_len_out)
{
	const size_t num_flags = (MAX(24, MAX(16, ((MAX((((MAX(48, (((((MAX(24, MAX(32, ((ZCBOR_ROUND_UP(1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 2)))) + 48)) + 24))))))), 48) + 32)))) + ZCBOR_ROUND_UP(1 + 1 + 1 + 1 + 1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 2);
	zcbor_state_t states[12 + ZCBOR_EXTRA_STATES + ZCBOR_FLAG_STATES(num_flags)];

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_concise_mid_tag(states, result);
	}

	return zcbor_entry_function_with_elem_states(payload, payload_len, (void *)result, payload_len_out, states, (zcbor_decoder_t *)ZCBOR_CUSTOM_CAST_FP(decode_concise_mid_tag), sizeof(states) / sizeof(zcbor_state_t), ZCBOR_LARGE_ELEM_COUNT, num_flags);
}


int cbor_decode_tagged_spdm_toc(
		const uint8_t *payload, size_t payload_len,
		struct spdm_toc_map *result,
		size_t *payload_len_out)
{
	const size_t num_flags = ((MAX((((((((((MAX(48, (((((MAX(24, MAX(32, ((ZCBOR_ROUND_UP(1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 2)))) + 48)) + 24))))))) + ZCBOR_ROUND_UP(1 + 1 + 1 + 1 + 1 + 1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 2)) + ZCBOR_ROUND_UP(1 + 1 + 1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 3)))), 24) + ZCBOR_ROUND_UP(1 + 1 + 1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 3));
	zcbor_state_t states[14 + ZCBOR_EXTRA_STATES + ZCBOR_FLAG_STATES(num_flags)];

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_tagged_spdm_toc(states, result);
	}

	return zcbor_entry_function_with_elem_states(payload, payload_len, (void *)result, payload_len_out, states, (zcbor_decoder_t *)ZCBOR_CUSTOM_CAST_FP(decode_tagged_spdm_toc), sizeof(states) / sizeof(zcbor_state_t), ZCBOR_LARGE_ELEM_COUNT, num_flags);
}


int cbor_decode_concise_evidence(
		const uint8_t *payload, size_t payload_len,
		struct concise_evidence *result,
		size_t *payload_len_out)
{
	const size_t num_flags = (MAX((((((((MAX(48, (((((MAX(24, MAX(32, ((ZCBOR_ROUND_UP(1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 2)))) + 48)) + 24))))))) + ZCBOR_ROUND_UP(1 + 1 + 1 + 1 + 1 + 1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 2)) + ZCBOR_ROUND_UP(1 + 1 + 1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 3)), ((((((((MAX(48, (((((MAX(24, MAX(32, ((ZCBOR_ROUND_UP(1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 2)))) + 48)) + 24))))))) + ZCBOR_ROUND_UP(1 + 1 + 1 + 1 + 1 + 1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 2)) + ZCBOR_ROUND_UP(1 + 1 + 1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 3)))));
	zcbor_state_t states[13 + ZCBOR_EXTRA_STATES + ZCBOR_FLAG_STATES(num_flags)];

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_concise_evidence(states, result);
	}

	return zcbor_entry_function_with_elem_states(payload, payload_len, (void *)result, payload_len_out, states, (zcbor_decoder_t *)ZCBOR_CUSTOM_CAST_FP(decode_concise_evidence), sizeof(states) / sizeof(zcbor_state_t), ZCBOR_LARGE_ELEM_COUNT, num_flags);
}


int cbor_decode_eat_claims_map(
		const uint8_t *payload, size_t payload_len,
		struct eat_claims_map *result,
		size_t *payload_len_out)
{
	const size_t num_flags = (24 + ZCBOR_ROUND_UP(1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + ZCBOR_CORIM_DEFAULT_MAX_QTY, 8) * 3);
	zcbor_state_t states[9 + ZCBOR_EXTRA_STATES + ZCBOR_FLAG_STATES(num_flags)];

	if (false) {
		/* For testing that the types of the arguments are correct.
		 * A compiler error here means a bug in zcbor.
		 */
		decode_eat_claims_map(states, result);
	}

	return zcbor_entry_function_with_elem_states(payload, payload_len, (void *)result, payload_len_out, states, (zcbor_decoder_t *)ZCBOR_CUSTOM_CAST_FP(decode_eat_claims_map), sizeof(states) / sizeof(zcbor_state_t), ZCBOR_LARGE_ELEM_COUNT, num_flags);
}
