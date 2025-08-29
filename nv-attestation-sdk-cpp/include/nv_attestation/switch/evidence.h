/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#pragma once

#include <string>
#include <memory>
#include <vector>
#include <cstdint>

#include "nv_attestation/nv_x509.h"
#include "nv_attestation/error.h"


#ifdef ENABLE_NSCQ
#include "nv_attestation/switch/nscq_attestation.h"
#endif

#include "nv_attestation/spdm/spdm_resp.hpp"
#include "nv_attestation/spdm/spdm_req.hpp"
#include "nv_attestation/switch/spdm/switch_opaque_data_parser.hpp"
#include "nv_attestation/nv_x509.h"

namespace nvattestation {

enum class SwitchArchitecture {
    Unknown,
    LS10,
    SV10,
    LR10,
};

class SwitchArchitectureData {
    public: 
        SwitchArchitecture m_arch;
        const EVP_MD* m_ar_signature_hash_algorithm;
        size_t m_ar_signature_length; // bytes
        std::string project;
        std::string project_sku;
        std::string chip_sku;
        X509CertChain::FWIDType m_fwid_type;

        SwitchArchitectureData() = default;
        static Error create(SwitchArchitecture arch, SwitchArchitectureData& out_arch_data);
        const EVP_MD* get_ar_signature_hash_algorithm() const { return m_ar_signature_hash_algorithm; }
        size_t get_ar_signature_length() const { return m_ar_signature_length; }
    private: 
        static const std::vector<SwitchArchitecture> m_supported_architectures;

};

std::string to_string(SwitchArchitecture arch);
void from_string(const std::string& arch_str, SwitchArchitecture& out_arch);

class SwitchEvidenceClaims {
    public:
        class AttestationReportClaims {
            public:
                CertChainClaims m_cert_chain_claims;
                bool m_fwid_match;
                bool m_parsed;
                bool m_signature_verified;
        };
        bool m_switch_arch_match;
        std::string m_switch_bios_version;
        bool m_switch_ar_nonce_match; // true if nonce matches between switch evidence and switch attestation report
        AttestationReportClaims m_attestation_report_claims;
};

/**
 * @brief Represents cryptographically-signed attestation evidence 
 *
 * The Evidence class is the starting point for the attestation workflow, where it is parsed and transformed
 * into [SwitchClaims](@ref SwitchClaims) for policy evaluation.
 */
class SwitchEvidence {
    public:
        class AttestationReport {
            public:
                Error generate_attestation_report_claims(const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, const SwitchArchitectureData& arch_data, SwitchEvidenceClaims::AttestationReportClaims& out_attestation_report_claims) const;
                std::unique_ptr<bool> verify_attestation_report_signature();
                Error get_spdm_response(const SpdmMeasurementResponseMessage11*& out_spdm_response) const;
                Error get_spdm_request(const SpdmMeasurementRequestMessage11*& out_spdm_request) const;
                Error get_fwid(const std::vector<uint8_t>*& out_fwid) const;
                Error get_vbios_version(std::string& out_bios_version) const;
                Error get_vbios_rim_id(std::string& out_vbios_rim_id, SwitchArchitecture architecture) const;
                Error get_spdm_req_nonce(std::vector<uint8_t>& out_nonce) const;
                Error get_measurements(std::unordered_map<int, std::vector<uint8_t>>& out_measurements) const;
                AttestationReport() = default;
                static Error create(const std::vector<uint8_t>& attestation_report, const std::string& ar_cert_chain, SwitchArchitecture architecture, AttestationReport& out_attestation_report);
            private:
            SpdmMeasurementResponseMessage11 m_spdm_response;
            SpdmMeasurementRequestMessage11 m_spdm_request;
            SwitchOpaqueDataParser m_switch_opaque_data_parser;
            X509CertChain m_attestation_cert_chain;
        };

        SwitchEvidence(
            SwitchArchitecture architecture,
            const std::string& uuid,
            const std::vector<uint8_t>& attestation_report,
            const std::string& attestation_cert_chain,
            bool tnvl_mode,
            bool lock_mode, 
            const std::vector<uint8_t>& nonce)
            : m_switch_architecture(architecture),
              m_uuid(uuid),
              m_attestation_report(attestation_report),
              m_attestation_cert_chain(attestation_cert_chain),
              m_tnvl_mode(tnvl_mode),
              m_lock_mode(lock_mode), 
              m_nonce(nonce) {}
        SwitchEvidence() = default;

        Error get_parsed_attestation_report(AttestationReport& out_attestation_report) const;
        Error generate_switch_evidence_claims(const AttestationReport& parsed_attestation_report, const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, SwitchEvidenceClaims& out_switch_evidence_claims) const;

        std::string get_hex_nonce() const;

        Error to_json(std::string& out_string) const;
        static Error collection_to_json(const std::vector<SwitchEvidence>& collection, std::string& out_string);
        static Error collection_from_json(const std::string& json_string, std::vector<SwitchEvidence>& out_collection);
    
        // Getter methods
        SwitchArchitecture get_switch_architecture() const { return m_switch_architecture; }
        const std::string& get_uuid() const { return m_uuid; }
        const std::vector<uint8_t>& get_attestation_report() const { return m_attestation_report; }
        const std::string& get_attestation_cert_chain() const { return m_attestation_cert_chain; }
        bool get_tnvl_mode() const { return m_tnvl_mode; }
        bool get_lock_mode() const { return m_lock_mode; }
        const std::vector<uint8_t>& get_nonce() const { return m_nonce; }

        //setter methods
        void set_switch_architecture(SwitchArchitecture architecture) { m_switch_architecture = architecture; }
        void set_nonce(const std::vector<uint8_t>& nonce) { m_nonce = nonce; }
        void set_attestation_report(const std::vector<uint8_t>& attestation_report) { m_attestation_report = attestation_report; }
        void set_attestation_cert_chain(const std::string& attestation_cert_chain) { m_attestation_cert_chain = attestation_cert_chain; }

    private:
        SwitchArchitecture m_switch_architecture;
        std::string m_uuid;
        std::vector<uint8_t> m_attestation_report;
        std::string m_attestation_cert_chain;
        bool m_tnvl_mode;
        bool m_lock_mode;
        std::vector<uint8_t> m_nonce;
};

/**
 * @brief Provides a source of Switch evidence.
 */
class ISwitchEvidenceSource {
    public:
        virtual ~ISwitchEvidenceSource() = default;
        /**
         * @brief Fallible operation to collect a list of SwitchEvidence.
         * @param nonce_input The nonce input for evidence collection
         * @param out_evidence_list Output vector to populate with SwitchEvidence
         * @return Error indicating success or failure
         */
        virtual Error get_evidence(const std::vector<uint8_t>& nonce_input, std::vector<SwitchEvidence>& out_evidence_list) const = 0;
};

/**
 * @brief Collects Switch evidence using NSCQ library.
 */
class NscqEvidenceCollector : public ISwitchEvidenceSource {
    public:
        Error get_evidence(const std::vector<uint8_t>& nonce_input, std::vector<SwitchEvidence>& out_evidence_list) const override;
};

class SwitchEvidenceSourceFromJsonFile : public ISwitchEvidenceSource {
    public:
        Error get_evidence(const std::vector<uint8_t>& nonce_input, std::vector<SwitchEvidence>& out_evidence_list) const override;
        static Error create(const std::string& file_path, SwitchEvidenceSourceFromJsonFile& out_source);

    private:
        std::vector<SwitchEvidence> m_evidence;
};

}