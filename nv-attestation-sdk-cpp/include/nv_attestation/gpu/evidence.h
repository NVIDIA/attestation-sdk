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

#ifdef ENABLE_NVML
#include <nvml.h>
#endif

#include "nv_attestation/spdm/spdm_resp.hpp"
#include "nv_attestation/spdm/spdm_req.hpp"
#include "nv_attestation/gpu/spdm/gpu_opaque_data_parser.hpp"
#include "nv_attestation/nv_x509.h"

namespace nvattestation {

constexpr const size_t GPU_SPDM_REQ_NONCE_SIZE = 32;
constexpr const size_t SWITCH_SPDM_REQ_NONCE_SIZE = 32;
/**
 * @brief Represents cryptographically-signed attestation evidence 
 *
 * The Evidence class is the starting point for the attestation workflow, where it is parsed and transformed
 * into [GpuClaims](@ref GpuClaims) for policy evaluation.
 */

class RimGpuEvidenceClaims {
    public:
    bool m_measurements_matching;
};


class GpuEvidenceClaims {
    public:
    class AttestationReportClaims {
        public:
        CertChainClaims m_cert_chain_claims;
        bool m_fwid_match;
        std::string m_hwmodel;
        std::string m_ueid;
        bool m_parsed;
        bool m_signature_verified;
    };
    bool m_gpu_ar_arch_match;
    std::string m_driver_version;
    std::string m_vbios_version;
    AttestationReportClaims m_attestation_report_claims;
    bool m_gpu_ar_nonce_match;
};

std::ostream& operator<<(std::ostream& os, const GpuEvidenceClaims& claims);
std::ostream& operator<<(std::ostream& os, const GpuEvidenceClaims::AttestationReportClaims& claims);

enum class GpuArchitecture {
    Unknown,
    Ampere,
    Hopper,
    Blackwell
};

class GpuArchitectureData {
    public: 
        GpuArchitecture m_arch;
        const EVP_MD* m_ar_signature_hash_algorithm;
        size_t m_ar_signature_length; // bytes
        X509CertChain::FWIDType m_fwid_type;

        GpuArchitectureData() = default;
        static Error create(GpuArchitecture arch, GpuArchitectureData& out_arch_data);
        const EVP_MD* get_ar_signature_hash_algorithm() const { return m_ar_signature_hash_algorithm; }
        size_t get_ar_signature_length() const { return m_ar_signature_length; }
    private: 
        static const std::vector<GpuArchitecture> m_supported_architectures;
};

std::string to_string(GpuArchitecture arch);
void from_string(const std::string& arch_str, GpuArchitecture& out_arch);

class GpuEvidence {
    public:
        class AttestationReport {
            public:
                Error generate_attestation_report_claims(const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, GpuArchitectureData arch_data, GpuEvidenceClaims::AttestationReportClaims& out_attestation_report_claims) const;
                std::unique_ptr<bool> verify_attestation_report_signature();
                Error get_spdm_request(const SpdmMeasurementRequestMessage11*& out_spdm_request) const;
                Error get_driver_version(std::string& out_driver_version) const;
                Error get_vbios_version(std::string& out_vbios_version) const;
                Error get_fwid(const std::vector<uint8_t>*& out_fwid) const;
                Error get_driver_rim_id(GpuArchitecture architecture, std::string& out_driver_rim_id) const;
                Error get_vbios_rim_id(std::string& out_vbios_rim_id) const;
                Error get_nvdec0_status(uint8_t& out_nvdec0_status) const;
                Error get_measurements(std::unordered_map<int, std::vector<uint8_t>>& out_measurements) const;
                AttestationReport() = default;
                static Error create(const std::vector<uint8_t>& attestation_report, const std::string& ar_cert_chain, GpuArchitecture architecture, AttestationReport& out_attestation_report);
            private:
            SpdmMeasurementResponseMessage11 m_spdm_response;
            SpdmMeasurementRequestMessage11 m_spdm_request;
            GpuOpaqueDataParser m_gpu_opaque_data_parser;
            X509CertChain m_attestation_cert_chain;
        };
        GpuEvidence(
            GpuArchitecture architecture,
            unsigned int board_id,
            const std::string& uuid,
            const std::string& vbios_version,
            const std::string& driver_version,
            const std::vector<uint8_t>& attestation_report,
            const std::string& attestation_cert_chain,
            const std::vector<uint8_t>& nonce)
            : m_gpu_architecture(architecture),
              m_board_id(board_id),
              m_uuid(uuid),
              m_vbios_version(vbios_version),
              m_driver_version(driver_version),
              m_attestation_report(attestation_report),
              m_attestation_cert_chain(attestation_cert_chain),
              m_nonce(nonce) {}

        GpuEvidence() = default;
    
        Error get_parsed_attestation_report(GpuEvidence::AttestationReport& out_attestation_report) const;
        Error generate_gpu_evidence_claims(const GpuEvidence::AttestationReport& attestation_report, const OcspVerifyOptions& ocsp_verify_options, IOcspHttpClient& ocsp_client, GpuEvidenceClaims& out_gpu_evidence_claims) const;
        const std::string& get_attestation_cert_chain() const { return m_attestation_cert_chain; }

        std::string get_hex_nonce() const;

        Error to_json(std::string& out_string) const;
        Error from_json(const std::string& json_string);
        static Error collection_to_json(const std::vector<std::shared_ptr<GpuEvidence>>& collection, std::string& out_string);
        static Error collection_from_json(const std::string& json_string, std::vector<std::shared_ptr<GpuEvidence>>& out_collection);

        // Getter methods
        GpuArchitecture get_gpu_architecture() const { return m_gpu_architecture; }
        unsigned int get_board_id() const { return m_board_id; }
        const std::string& get_uuid() const { return m_uuid; }
        const std::string& get_vbios_version() const { return m_vbios_version; }
        const std::string& get_driver_version() const { return m_driver_version; }
        const std::vector<uint8_t>& get_attestation_report() const { return m_attestation_report; }
        const std::vector<uint8_t>& get_nonce() const { return m_nonce; }

        void set_gpu_architecture(GpuArchitecture gpu_architecture) { m_gpu_architecture = gpu_architecture; }
        void set_vbios_version(const std::string& vbios_version) { m_vbios_version = vbios_version; }
        void set_driver_version(const std::string& driver_version) { m_driver_version = driver_version; }
        void set_attestation_report(const std::vector<uint8_t>& attestation_report) { m_attestation_report = attestation_report; }
        void set_attestation_cert_chain(const std::string& attestation_cert_chain) { m_attestation_cert_chain = attestation_cert_chain; }
        void set_nonce(const std::vector<uint8_t>& nonce) { m_nonce = nonce; }


    private:
        // TODO(p2): Reduce to minimal info required for attestation.
        //       Know we need attesation report, cert chain, nonce (missing?), and architecture.
        GpuArchitecture m_gpu_architecture;
        unsigned int m_board_id;
        std::string m_uuid;
        std::string m_vbios_version;
        std::string m_driver_version;
        std::vector<uint8_t> m_attestation_report;
        std::string m_attestation_cert_chain;
        std::vector<uint8_t> m_nonce;
};

std::ostream& operator<<(std::ostream& os, const GpuEvidence& evidence);

/**
 * @brief Provides a source of GPU evidence.
 * 
 * Implementations could include:
 * - GpuEvidence created in memory for testing
 * - GpuEvidence collected locally using NVML
 * - GpuEvidence read from a local file
 */
class IGpuEvidenceSource {
    public:
        virtual ~IGpuEvidenceSource() = default;
        /**
         * @brief Fallible operation to collect a list of GpuEvidence.
         * @return A vector of GpuEvidence to submit to a verifier
         */
        virtual Error get_evidence(const std::vector<uint8_t>& nonce_input, std::vector<std::shared_ptr<GpuEvidence>>& out_evidence) const = 0;
};

/**
 * @brief Collects GPU evidence using the [NVIDIA Management Library](https://developer.nvidia.com/management-library-nvml).
 */
class NvmlEvidenceCollector : public IGpuEvidenceSource {
    public:
        Error get_evidence(const std::vector<uint8_t>& nonce_input, std::vector<std::shared_ptr<GpuEvidence>>& out_evidence) const override;

    // TODO: the implementation may need an option to require CC or fail if in dev mode. These can be private vars configured with setters.
};

class GpuEvidenceSourceFromJsonFile : public IGpuEvidenceSource {
    public:
        Error get_evidence(const std::vector<uint8_t>& nonce_input, std::vector<std::shared_ptr<GpuEvidence>>& out_evidence) const override;
        static Error create(const std::string& file_path, GpuEvidenceSourceFromJsonFile& out_source);

    private:
        std::string m_file_path;
        std::vector<std::shared_ptr<GpuEvidence>> m_evidence;
};
}