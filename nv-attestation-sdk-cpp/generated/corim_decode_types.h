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

#ifndef CORIM_DECODE_TYPES_H__
#define CORIM_DECODE_TYPES_H__

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
#define ZCBOR_CORIM_DEFAULT_MAX_QTY 10

struct eat_claims_map_dbgstat_r {
	uint8_t eat_claims_map_dbgstat;
};

struct eat_profile_type_choice {
	union {
		struct zcbor_string eat_profile_type_choice_tstr;
		struct zcbor_string eat_profile_type_choice_bstr;
	};
	enum {
		eat_profile_type_choice_tstr_c,
		eat_profile_type_choice_bstr_c,
	} eat_profile_type_choice_choice;
};

struct measurements_format {
	uint16_t measurements_format_content_format;
	struct zcbor_string measurements_format_body;
};

struct measurements_type {
	struct measurements_format measurements_type_measurements_format_m[8];
	size_t measurements_type_measurements_format_m_count;
};

struct eat_claims_map_iss_r {
	struct zcbor_string eat_claims_map_iss;
};

struct eat_claims_map_cti_r {
	struct zcbor_string eat_claims_map_cti;
};

struct eat_claims_map_ueid_r {
	struct zcbor_string eat_claims_map_ueid;
};

struct eat_claims_map_sueid_r {
	struct zcbor_string eat_claims_map_sueid;
};

struct oemid_type {
	union {
		struct zcbor_string oemid_type_bstr;
		int32_t oemid_type_int;
	};
	enum {
		oemid_type_bstr_c,
		oemid_type_int_c,
	} oemid_type_choice;
};

struct eat_claims_map_oemid_r {
	struct oemid_type eat_claims_map_oemid;
};

struct eat_claims_map_hwmodel_r {
	struct zcbor_string eat_claims_map_hwmodel;
};

struct eat_claims_map_uptime_r {
	uint32_t eat_claims_map_uptime;
};

struct eat_claims_map_bootcount_r {
	uint32_t eat_claims_map_bootcount;
};

struct eat_claims_map_bootseed_r {
	struct zcbor_string eat_claims_map_bootseed;
};

struct digest {
	union {
		int32_t digest_alg_int;
		struct zcbor_string digest_alg_text_m;
	};
	enum {
		digest_alg_int_c,
		digest_alg_text_m_c,
	} digest_alg_choice;
	struct zcbor_string digest_val;
};

struct corim_locator_map_corim_thumbprint_r {
	union {
		struct digest corim_locator_map_corim_thumbprint_digest_m;
		struct digest corim_thumbprint_digest_m_l_digest_m;
	};
	enum {
		corim_locator_map_corim_thumbprint_digest_m_c,
		corim_thumbprint_digest_m_l_digest_m_c,
	} corim_locator_map_corim_thumbprint_choice;
};

struct corim_locator_map {
	union {
		struct zcbor_string corim_locator_map_corim_href_uri_m;
		struct {
			struct zcbor_string corim_href_uri_m_l_uri_m[ZCBOR_CORIM_DEFAULT_MAX_QTY];
			size_t corim_href_uri_m_l_uri_m_count;
		};
	};
	enum {
		corim_locator_map_corim_href_uri_m_c,
		corim_href_uri_m_l_c,
	} corim_locator_map_corim_href_choice;
	struct corim_locator_map_corim_thumbprint_r corim_locator_map_corim_thumbprint;
	bool corim_locator_map_corim_thumbprint_present;
};

struct eat_claims_map_rim_locators_r {
	struct corim_locator_map eat_claims_map_rim_locators_corim_locator_map_m[8];
	size_t eat_claims_map_rim_locators_corim_locator_map_m_count;
};

struct eat_claims_map_intany_r {
	int32_t eat_claims_map_intany_key;
};

struct eat_claims_map {
	struct zcbor_string eat_claims_map_nonce;
	struct eat_claims_map_dbgstat_r eat_claims_map_dbgstat;
	bool eat_claims_map_dbgstat_present;
	struct eat_profile_type_choice eat_claims_map_eat_profile;
	struct measurements_type eat_claims_map_measurements;
	struct eat_claims_map_iss_r eat_claims_map_iss;
	bool eat_claims_map_iss_present;
	struct eat_claims_map_cti_r eat_claims_map_cti;
	bool eat_claims_map_cti_present;
	struct eat_claims_map_ueid_r eat_claims_map_ueid;
	bool eat_claims_map_ueid_present;
	struct eat_claims_map_sueid_r eat_claims_map_sueid;
	bool eat_claims_map_sueid_present;
	struct eat_claims_map_oemid_r eat_claims_map_oemid;
	bool eat_claims_map_oemid_present;
	struct eat_claims_map_hwmodel_r eat_claims_map_hwmodel;
	bool eat_claims_map_hwmodel_present;
	struct eat_claims_map_uptime_r eat_claims_map_uptime;
	bool eat_claims_map_uptime_present;
	struct eat_claims_map_bootcount_r eat_claims_map_bootcount;
	bool eat_claims_map_bootcount_present;
	struct eat_claims_map_bootseed_r eat_claims_map_bootseed;
	bool eat_claims_map_bootseed_present;
	struct eat_claims_map_rim_locators_r eat_claims_map_rim_locators;
	bool eat_claims_map_rim_locators_present;
	struct eat_claims_map_intany_r eat_claims_map_intany[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t eat_claims_map_intany_count;
};

struct corim_id_type_choice {
	union {
		struct zcbor_string corim_id_type_choice_tstr;
		struct zcbor_string corim_id_type_choice_uuid_type_m;
	};
	enum {
		corim_id_type_choice_tstr_c,
		corim_id_type_choice_uuid_type_m_c,
	} corim_id_type_choice_choice;
};

struct concise_tag_type_choice {
	union {
		struct zcbor_string concise_tag_type_choice_tagged_concise_swid_tag_m;
		struct zcbor_string concise_tag_type_choice_tagged_concise_mid_tag_m;
		struct zcbor_string concise_tag_type_choice_tagged_concise_tl_tag_m;
	};
	enum {
		concise_tag_type_choice_tagged_concise_swid_tag_m_c,
		concise_tag_type_choice_tagged_concise_mid_tag_m_c,
		concise_tag_type_choice_tagged_concise_tl_tag_m_c,
	} concise_tag_type_choice_choice;
};

struct corim_map_dependent_rims_r {
	struct corim_locator_map corim_map_dependent_rims_corim_locator_map_m[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t corim_map_dependent_rims_corim_locator_map_m_count;
};

struct profile_type_choice {
	union {
		struct zcbor_string profile_type_choice_uri_m;
		struct zcbor_string profile_type_choice_tagged_oid_type_m;
	};
	enum {
		profile_type_choice_uri_m_c,
		profile_type_choice_tagged_oid_type_m_c,
	} profile_type_choice_choice;
};

struct corim_map_profile_r {
	struct profile_type_choice corim_map_profile;
};

struct number {
	union {
		int32_t number_int;
		double number_float;
	};
	enum {
		number_int_c,
		number_float_c,
	} number_choice;
};

struct validity_map_not_before_r {
	struct number validity_map_not_before;
};

struct validity_map {
	struct validity_map_not_before_r validity_map_not_before;
	bool validity_map_not_before_present;
	struct number validity_map_not_after;
};

struct corim_map_rim_validity_r {
	struct validity_map corim_map_rim_validity;
};

struct corim_entity_map_corim_reg_id_r {
	struct zcbor_string corim_entity_map_corim_reg_id;
};

struct corim_role_type_choice {
	enum {
		corim_role_type_choice_manifest_creator_m_c = 1,
		corim_role_type_choice_manifest_signer_m_c = 2,
	} corim_role_type_choice_choice;
};

struct corim_entity_map {
	struct zcbor_string corim_entity_map_corim_entity_name;
	struct corim_entity_map_corim_reg_id_r corim_entity_map_corim_reg_id;
	bool corim_entity_map_corim_reg_id_present;
	struct corim_role_type_choice corim_entity_map_corim_role_corim_role_type_choice_m[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t corim_entity_map_corim_role_corim_role_type_choice_m_count;
};

struct corim_map_entities_r {
	struct corim_entity_map corim_map_entities_corim_entity_map_m[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t corim_map_entities_corim_entity_map_m_count;
};

struct extension_key {
	union {
		int32_t extension_key_int;
		struct zcbor_string extension_key_tstr;
	};
	enum {
		extension_key_int_c,
		extension_key_tstr_c,
	} extension_key_choice;
};

struct corim_map_extension_key_r {
	struct extension_key corim_map_extension_key_key;
};

struct corim_map {
	struct corim_id_type_choice corim_map_id;
	struct concise_tag_type_choice corim_map_tags_concise_tag_type_choice_m[25];
	size_t corim_map_tags_concise_tag_type_choice_m_count;
	struct corim_map_dependent_rims_r corim_map_dependent_rims;
	bool corim_map_dependent_rims_present;
	struct corim_map_profile_r corim_map_profile;
	bool corim_map_profile_present;
	struct corim_map_rim_validity_r corim_map_rim_validity;
	bool corim_map_rim_validity_present;
	struct corim_map_entities_r corim_map_entities;
	bool corim_map_entities_present;
	struct corim_map_extension_key_r corim_map_extension_key[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t corim_map_extension_key_count;
};

struct concise_mid_tag_language_r {
	struct zcbor_string concise_mid_tag_language;
};

struct tag_id_type_choice {
	union {
		struct zcbor_string tag_id_type_choice_tstr;
		struct zcbor_string tag_id_type_choice_uuid_type_m;
	};
	enum {
		tag_id_type_choice_tstr_c,
		tag_id_type_choice_uuid_type_m_c,
	} tag_id_type_choice_choice;
};

struct tag_identity_map_tag_version_r {
	uint32_t tag_identity_map_tag_version;
};

struct tag_identity_map {
	struct tag_id_type_choice tag_identity_map_tag_id;
	struct tag_identity_map_tag_version_r tag_identity_map_tag_version;
	bool tag_identity_map_tag_version_present;
};

struct comid_entity_map_comid_reg_id_r {
	struct zcbor_string comid_entity_map_comid_reg_id;
};

struct comid_role_type_choice {
	enum {
		comid_role_type_choice_comid_tag_creator_m_c = 0,
		comid_role_type_choice_comid_creator_m_c = 1,
		comid_role_type_choice_comid_maintainer_m_c = 2,
	} comid_role_type_choice_choice;
};

struct comid_entity_map {
	struct zcbor_string comid_entity_map_comid_entity_name;
	struct comid_entity_map_comid_reg_id_r comid_entity_map_comid_reg_id;
	bool comid_entity_map_comid_reg_id_present;
	struct comid_role_type_choice comid_entity_map_comid_role_comid_role_type_choice_m[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t comid_entity_map_comid_role_comid_role_type_choice_m_count;
};

struct concise_mid_tag_entities_r {
	struct comid_entity_map concise_mid_tag_entities_comid_entity_map_m[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t concise_mid_tag_entities_comid_entity_map_m_count;
};

struct class_id_type_choice {
	union {
		struct zcbor_string class_id_type_choice_tagged_oid_type_m;
		struct zcbor_string class_id_type_choice_tagged_uuid_type_m;
		struct zcbor_string class_id_type_choice_tagged_bytes_m;
	};
	enum {
		class_id_type_choice_tagged_oid_type_m_c,
		class_id_type_choice_tagged_uuid_type_m_c,
		class_id_type_choice_tagged_bytes_m_c,
	} class_id_type_choice_choice;
};

struct class_map_class_id_r {
	struct class_id_type_choice class_map_class_id;
};

struct class_map_vendor_r {
	struct zcbor_string class_map_vendor;
};

struct class_map_model_r {
	struct zcbor_string class_map_model;
};

struct class_map_layer_r {
	uint32_t class_map_layer;
};

struct class_map_index_r {
	uint32_t class_map_index;
};

struct class_map {
	struct class_map_class_id_r class_map_class_id;
	bool class_map_class_id_present;
	struct class_map_vendor_r class_map_vendor;
	bool class_map_vendor_present;
	struct class_map_model_r class_map_model;
	bool class_map_model_present;
	struct class_map_layer_r class_map_layer;
	bool class_map_layer_present;
	struct class_map_index_r class_map_index;
	bool class_map_index_present;
};

struct environment_map_class_r {
	struct class_map environment_map_class;
};

struct instance_id_type_choice {
	union {
		struct zcbor_string instance_id_type_choice_tagged_ueid_type_m;
		struct zcbor_string instance_id_type_choice_tagged_uuid_type_m;
		struct zcbor_string instance_id_type_choice_tagged_bytes_m;
	};
	enum {
		instance_id_type_choice_tagged_ueid_type_m_c,
		instance_id_type_choice_tagged_uuid_type_m_c,
		instance_id_type_choice_tagged_bytes_m_c,
	} instance_id_type_choice_choice;
};

struct environment_map_instance_r {
	struct instance_id_type_choice environment_map_instance;
};

struct group_id_type_choice {
	union {
		struct zcbor_string group_id_type_choice_tagged_uuid_type_m;
		struct zcbor_string group_id_type_choice_tagged_bytes_m;
	};
	enum {
		group_id_type_choice_tagged_uuid_type_m_c,
		group_id_type_choice_tagged_bytes_m_c,
	} group_id_type_choice_choice;
};

struct environment_map_group_r {
	struct group_id_type_choice environment_map_group;
};

struct environment_map {
	struct environment_map_class_r environment_map_class;
	bool environment_map_class_present;
	struct environment_map_instance_r environment_map_instance;
	bool environment_map_instance_present;
	struct environment_map_group_r environment_map_group;
	bool environment_map_group_present;
};

struct measured_element_type_choice {
	union {
		struct zcbor_string measured_element_type_choice_tagged_oid_type_m;
		struct zcbor_string measured_element_type_choice_tagged_uuid_type_m;
		uint32_t measured_element_type_choice_uint;
		struct zcbor_string measured_element_type_choice_tstr;
	};
	enum {
		measured_element_type_choice_tagged_oid_type_m_c,
		measured_element_type_choice_tagged_uuid_type_m_c,
		measured_element_type_choice_uint_c,
		measured_element_type_choice_tstr_c,
	} measured_element_type_choice_choice;
};

struct measurement_map_mkey_r {
	struct measured_element_type_choice measurement_map_mkey;
};

struct version_scheme_type_choice {
	union {
		int32_t version_scheme_type_choice_int;
		struct zcbor_string version_scheme_type_choice_text_m;
	};
	enum {
		version_scheme_type_choice_multipartnumeric_m_c,
		version_scheme_type_choice_multipartnumeric_suffix_m_c,
		version_scheme_type_choice_alphanumeric_m_c,
		version_scheme_type_choice_decimal_m_c,
		version_scheme_type_choice_semver_m_c,
		version_scheme_type_choice_int_c,
		version_scheme_type_choice_text_m_c,
	} version_scheme_type_choice_choice;
};

struct version_map_scheme_r {
	struct version_scheme_type_choice version_map_scheme;
};

struct version_map {
	struct zcbor_string version_map_version;
	struct version_map_scheme_r version_map_scheme;
	bool version_map_scheme_present;
};

struct measurement_values_map_version_r {
	struct version_map measurement_values_map_version;
};

struct svn_type_choice {
	union {
		uint32_t svn_type_choice_svn_val_m;
		uint32_t svn_type_choice_tagged_svn_m;
		uint32_t svn_type_choice_tagged_min_svn_m;
	};
	enum {
		svn_type_choice_svn_val_m_c,
		svn_type_choice_tagged_svn_m_c,
		svn_type_choice_tagged_min_svn_m_c,
	} svn_type_choice_choice;
};

struct measurement_values_map_svn_r {
	struct svn_type_choice measurement_values_map_svn;
};

struct digests_type {
	struct digest digests_type_digest_m[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t digests_type_digest_m_count;
};

struct measurement_values_map_digests_r {
	struct digests_type measurement_values_map_digests;
};

struct flags_map_is_configured_r {
	bool flags_map_is_configured;
};

struct flags_map_is_secure_r {
	bool flags_map_is_secure;
};

struct flags_map_is_recovery_r {
	bool flags_map_is_recovery;
};

struct flags_map_is_debug_r {
	bool flags_map_is_debug;
};

struct flags_map_is_replay_protected_r {
	bool flags_map_is_replay_protected;
};

struct flags_map_is_integrity_protected_r {
	bool flags_map_is_integrity_protected;
};

struct flags_map_is_runtime_meas_r {
	bool flags_map_is_runtime_meas;
};

struct flags_map_is_immutable_r {
	bool flags_map_is_immutable;
};

struct flags_map_is_tcb_r {
	bool flags_map_is_tcb;
};

struct flags_map_is_confidentiality_protected_r {
	bool flags_map_is_confidentiality_protected;
};

struct flags_map {
	struct flags_map_is_configured_r flags_map_is_configured;
	bool flags_map_is_configured_present;
	struct flags_map_is_secure_r flags_map_is_secure;
	bool flags_map_is_secure_present;
	struct flags_map_is_recovery_r flags_map_is_recovery;
	bool flags_map_is_recovery_present;
	struct flags_map_is_debug_r flags_map_is_debug;
	bool flags_map_is_debug_present;
	struct flags_map_is_replay_protected_r flags_map_is_replay_protected;
	bool flags_map_is_replay_protected_present;
	struct flags_map_is_integrity_protected_r flags_map_is_integrity_protected;
	bool flags_map_is_integrity_protected_present;
	struct flags_map_is_runtime_meas_r flags_map_is_runtime_meas;
	bool flags_map_is_runtime_meas_present;
	struct flags_map_is_immutable_r flags_map_is_immutable;
	bool flags_map_is_immutable_present;
	struct flags_map_is_tcb_r flags_map_is_tcb;
	bool flags_map_is_tcb_present;
	struct flags_map_is_confidentiality_protected_r flags_map_is_confidentiality_protected;
	bool flags_map_is_confidentiality_protected_present;
};

struct measurement_values_map_flags_r {
	struct flags_map measurement_values_map_flags;
};

struct tagged_masked_raw_value {
	struct zcbor_string tagged_masked_raw_value_value;
	struct zcbor_string tagged_masked_raw_value_mask;
};

struct raw_value_type_choice {
	union {
		struct zcbor_string raw_value_type_choice_tagged_bytes_m;
		struct tagged_masked_raw_value raw_value_type_choice_tagged_masked_raw_value_m;
	};
	enum {
		raw_value_type_choice_tagged_bytes_m_c,
		raw_value_type_choice_tagged_masked_raw_value_m_c,
	} raw_value_type_choice_choice;
};

struct measurement_values_map_raw_value_r {
	struct raw_value_type_choice measurement_values_map_raw_value;
};

struct measurement_values_map_name_r {
	struct zcbor_string measurement_values_map_name;
};

struct spdm_indirect_map_index_r {
	uint32_t spdm_indirect_map_index_uint[64];
	size_t spdm_indirect_map_index_uint_count;
};

struct spdm_indirect_map_intany_r {
	int32_t spdm_indirect_map_intany_key;
};

struct spdm_indirect_map {
	struct spdm_indirect_map_index_r spdm_indirect_map_index;
	bool spdm_indirect_map_index_present;
	struct spdm_indirect_map_intany_r spdm_indirect_map_intany[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t spdm_indirect_map_intany_count;
};

struct measurement_values_map_spdm_indirect_r {
	struct spdm_indirect_map measurement_values_map_spdm_indirect;
};

struct int_range_type {
	union {
		int32_t int_range_type_min_int;
	};
	enum {
		int_range_type_min_int_c,
		int_range_type_min_negative_inf_m_c,
	} int_range_type_min_choice;
	union {
		int32_t int_range_type_max_int;
	};
	enum {
		int_range_type_max_int_c,
		int_range_type_max_positive_inf_m_c,
	} int_range_type_max_choice;
};

struct int_range_type_choice {
	union {
		int32_t int_range_type_choice_int;
		struct int_range_type int_range_type_choice_tagged_int_range_m;
	};
	enum {
		int_range_type_choice_int_c,
		int_range_type_choice_tagged_int_range_m_c,
	} int_range_type_choice_choice;
};

struct measurement_values_map_int_range_r {
	struct int_range_type_choice measurement_values_map_int_range;
};

struct measurement_values_map {
	struct measurement_values_map_version_r measurement_values_map_version;
	bool measurement_values_map_version_present;
	struct measurement_values_map_svn_r measurement_values_map_svn;
	bool measurement_values_map_svn_present;
	struct measurement_values_map_digests_r measurement_values_map_digests;
	bool measurement_values_map_digests_present;
	struct measurement_values_map_flags_r measurement_values_map_flags;
	bool measurement_values_map_flags_present;
	struct measurement_values_map_raw_value_r measurement_values_map_raw_value;
	bool measurement_values_map_raw_value_present;
	bool measurement_values_map_raw_value_mask_DEPRECATED_present;
	bool measurement_values_map_mac_addr_present;
	bool measurement_values_map_ip_addr_present;
	bool measurement_values_map_serial_number_present;
	bool measurement_values_map_ueid_present;
	bool measurement_values_map_uuid_present;
	struct measurement_values_map_name_r measurement_values_map_name;
	bool measurement_values_map_name_present;
	struct measurement_values_map_spdm_indirect_r measurement_values_map_spdm_indirect;
	bool measurement_values_map_spdm_indirect_present;
	bool measurement_values_map_cryptokeys_present;
	bool measurement_values_map_integrity_registers_present;
	struct measurement_values_map_int_range_r measurement_values_map_int_range;
	bool measurement_values_map_int_range_present;
};

struct measurement_map {
	struct measurement_map_mkey_r measurement_map_mkey;
	bool measurement_map_mkey_present;
	struct measurement_values_map measurement_map_mval;
	bool measurement_map_authorized_by_present;
};

struct reference_triple_record {
	struct environment_map reference_triple_record_ref_env;
	struct measurement_map reference_triple_record_ref_claims_measurement_map_m[50];
	size_t reference_triple_record_ref_claims_measurement_map_m_count;
};

struct triples_map_reference_triples_r {
	struct reference_triple_record triples_map_reference_triples_reference_triple_record_m[50];
	size_t triples_map_reference_triples_reference_triple_record_m_count;
};

struct domain_dependency_triple_record {
	struct environment_map domain_dependency_triple_record_domain_id;
	struct environment_map domain_dependency_triple_record_trustees_domain_type_m[64];
	size_t domain_dependency_triple_record_trustees_domain_type_m_count;
};

struct triples_map_dependency_triples_r {
	struct domain_dependency_triple_record triples_map_dependency_triples_domain_dependency_triple_record_m[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t triples_map_dependency_triples_domain_dependency_triple_record_m_count;
};

struct triples_map {
	struct triples_map_reference_triples_r triples_map_reference_triples;
	bool triples_map_reference_triples_present;
	bool triples_map_endorsed_triples_present;
	bool triples_map_identity_triples_present;
	bool triples_map_attest_key_triples_present;
	struct triples_map_dependency_triples_r triples_map_dependency_triples;
	bool triples_map_dependency_triples_present;
	bool triples_map_membership_triples_present;
	bool triples_map_coswid_triples_present;
	bool triples_map_conditional_endorsement_series_triples_present;
	bool triples_map_conditional_endorsement_triples_present;
};

struct concise_mid_tag_extension_key_r {
	struct extension_key concise_mid_tag_extension_key_key;
};

struct concise_mid_tag {
	struct concise_mid_tag_language_r concise_mid_tag_language;
	bool concise_mid_tag_language_present;
	struct tag_identity_map concise_mid_tag_tag_identity;
	struct concise_mid_tag_entities_r concise_mid_tag_entities;
	bool concise_mid_tag_entities_present;
	bool concise_mid_tag_linked_tags_present;
	struct triples_map concise_mid_tag_triples;
	struct concise_mid_tag_extension_key_r concise_mid_tag_extension_key[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t concise_mid_tag_extension_key_count;
};

struct evidence_triple_record {
	struct environment_map evidence_triple_record_environment_map_m;
	struct measurement_map evidence_triple_record_measurement_map_m_l_measurement_map_m[50];
	size_t evidence_triple_record_measurement_map_m_l_measurement_map_m_count;
};

struct ev_triples_map_evidence_triples_r {
	struct evidence_triple_record ev_triples_map_evidence_triples_evidence_triple_record_m[100];
	size_t ev_triples_map_evidence_triples_evidence_triple_record_m_count;
};

struct ev_triples_map_intany_r {
	int32_t ev_triples_map_intany_key;
};

struct ev_triples_map {
	struct ev_triples_map_evidence_triples_r ev_triples_map_evidence_triples;
	bool ev_triples_map_evidence_triples_present;
	bool ev_triples_map_identity_triples_present;
	bool ev_triples_map_dependency_triples_present;
	bool ev_triples_map_membership_triples_present;
	bool ev_triples_map_coswid_triples_present;
	bool ev_triples_map_attest_key_triples_present;
	struct ev_triples_map_intany_r ev_triples_map_intany[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t ev_triples_map_intany_count;
};

struct concise_evidence_map_evidence_id_r {
	struct zcbor_string concise_evidence_map_evidence_id;
};

struct concise_evidence_map_profile_r {
	struct profile_type_choice concise_evidence_map_profile;
};

struct concise_evidence_map_intany_r {
	int32_t concise_evidence_map_intany_key;
};

struct concise_evidence_map {
	struct ev_triples_map concise_evidence_map_ev_triples;
	struct concise_evidence_map_evidence_id_r concise_evidence_map_evidence_id;
	bool concise_evidence_map_evidence_id_present;
	struct concise_evidence_map_profile_r concise_evidence_map_profile;
	bool concise_evidence_map_profile_present;
	struct concise_evidence_map_intany_r concise_evidence_map_intany[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t concise_evidence_map_intany_count;
};

struct concise_evidence {
	union {
		struct concise_evidence_map concise_evidence_map_m;
		struct concise_evidence_map tagged_concise_evidence_m;
	};
	enum {
		concise_evidence_map_m_c,
		tagged_concise_evidence_m_c,
	} concise_evidence_choice;
};

struct spdm_toc_map_rim_locators_r {
	struct corim_locator_map spdm_toc_map_rim_locators_corim_locator_map_m[8];
	size_t spdm_toc_map_rim_locators_corim_locator_map_m_count;
};

struct spdm_toc_map_profile_r {
	struct profile_type_choice spdm_toc_map_profile;
};

struct spdm_toc_map_intany_r {
	int32_t spdm_toc_map_intany_key;
};

struct spdm_toc_map {
	struct concise_evidence_map spdm_toc_map_tagged_evidence_tagged_concise_evidence_m[8];
	size_t spdm_toc_map_tagged_evidence_tagged_concise_evidence_m_count;
	struct spdm_toc_map_rim_locators_r spdm_toc_map_rim_locators;
	bool spdm_toc_map_rim_locators_present;
	struct spdm_toc_map_profile_r spdm_toc_map_profile;
	bool spdm_toc_map_profile_present;
	struct spdm_toc_map_intany_r spdm_toc_map_intany[ZCBOR_CORIM_DEFAULT_MAX_QTY];
	size_t spdm_toc_map_intany_count;
};

#ifdef __cplusplus
}
#endif

#endif /* CORIM_DECODE_TYPES_H__ */
