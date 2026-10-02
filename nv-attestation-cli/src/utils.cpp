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

#include "utils.h"
#include "CLI/Validators.hpp"
#include "logging.h"
#include "nvat.h"
#include "spdlog/spdlog.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <string>

namespace nvattest {

    void trim_ascii_whitespace(std::string& value) {
        constexpr const char* whitespace = " \t\n\r\f\v";
        const std::size_t first = value.find_first_not_of(whitespace);
        if (first == std::string::npos) {
            value.clear();
            return;
        }
        const std::size_t last = value.find_last_not_of(whitespace);
        value = value.substr(first, last - first + 1);
    }

    nvat_rc_t read_binary_file(const std::string& path, std::vector<uint8_t>& out) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) {
            SPDLOG_ERROR("Failed to open file: {}", path);
            return NVAT_RC_BAD_ARGUMENT;
        }
        const std::streamoff size = file.tellg();
        if (size < 0) {
            SPDLOG_ERROR("Failed to stat file: {}", path);
            return NVAT_RC_BAD_ARGUMENT;
        }
        out.resize(static_cast<size_t>(size));
        if (!file.seekg(0)) {
            SPDLOG_ERROR("Failed to rewind file: {}", path);
            return NVAT_RC_BAD_ARGUMENT;
        }
        if (!file.read(reinterpret_cast<char*>(out.data()), size)) {
            SPDLOG_ERROR("Failed to read file: {}", path);
            return NVAT_RC_BAD_ARGUMENT;
        }
        return NVAT_RC_OK;
    }

    nvat_log_level_t CommonOptions::get_log_level() const {
        if (log_level_str == "trace") return NVAT_LOG_LEVEL_TRACE;
        if (log_level_str == "debug") return NVAT_LOG_LEVEL_DEBUG;
        if (log_level_str == "info") return NVAT_LOG_LEVEL_INFO;
        if (log_level_str == "warn") return NVAT_LOG_LEVEL_WARN;
        if (log_level_str == "error") return NVAT_LOG_LEVEL_ERROR;
        if (log_level_str == "off") return NVAT_LOG_LEVEL_OFF;
        return NVAT_LOG_LEVEL_INFO;
    }

    void add_evidence_collection_options(CLI::App* app, EvidenceCollectionOptions& options) {
        app->add_option("--nonce", options.nonce, "Nonce for the attestation in hex format. A nonce will be generated if not supplied.")
            ->default_val("");
        app->add_option("--device,-d", options.device, "Device to attest")
            ->check(CLI::IsMember({"gpu", "nvswitch"}))
            ->default_val("gpu");

        static const char* gpu_evidence_group = "GPU Evidence";
        app->add_option("--gpu-evidence-source", options.gpu_evidence_source,
            "Source of GPU evidence. Used if --device=gpu\n\n"
            "NVML is the default and requires the NVIDIA GPU driver to be installed and the GPU to be in CC mode. "
            "Corelib can be used outside of CC mode and requires the Corelib library to be installed. "
            "Files can be used to appraise previously collected evidence.")
            ->group(gpu_evidence_group)
            ->check(CLI::IsMember({"nvml", "corelib", "file"}))
            ->default_val("nvml");
        app->add_option("--gpu-architecture", options.gpu_architecture,
            "GPU architecture. Required if --gpu-evidence-source=corelib")
            ->group(gpu_evidence_group)
            ->check(CLI::IsMember({"blackwell"}, CLI::ignore_case))
            ->transform([](std::string s) {
                std::transform(s.begin(), s.end(), s.begin(), ::toupper);
                return s;
            })
            ->default_str("");
        app->add_option("--gpu-evidence-file", options.gpu_evidence_file,
            "Path to a file containing GPU evidence. Used if --gpu-evidence-source=file")
            ->group(gpu_evidence_group)
            ->default_str("");

        static const char* switch_evidence_group = "NVSwitch Evidence";
        app->add_option("--nvswitch-evidence-source", options.switch_evidence_source,
            "Source of NVSwitch evidence. Used if --device=nvswitch\n\n"
            "NSCQ is the default and requires NSCQ to be installed. "
            "Files can be used to appraise previously collected evidence.")
            ->group(switch_evidence_group)
            ->check(CLI::IsMember({"nscq", "file"}))
            ->default_val("nscq");
        app->add_option("--nvswitch-evidence-file", options.switch_evidence_file,
            "Path to a file containing NVSwitch evidence. Used if --nvswitch-evidence-source=file")
            ->group(switch_evidence_group)
            ->default_str("");

        app->parse_complete_callback([&options]() {
            if (options.device == "gpu" && options.gpu_evidence_source == "file") {
                if (options.gpu_evidence_file.empty()) {
                    throw CLI::ValidationError("--gpu-evidence-file", "--gpu-evidence-file must be provided when --gpu-evidence-source=file");
                }
                auto validator = CLI::ExistingFile;
                auto result = validator(options.gpu_evidence_file);
                if (!result.empty()) {
                    throw CLI::ValidationError("--gpu-evidence-file", result);
                }
            }
            if (options.device == "gpu" && options.gpu_evidence_source == "corelib") {
                if (options.gpu_architecture.empty()) {
                    throw CLI::ValidationError("--gpu-architecture", "--gpu-architecture is required when --gpu-evidence-source=corelib");
                }
            }
            if (options.device == "nvswitch" && options.switch_evidence_source == "file") {
                if (options.switch_evidence_file.empty()) {
                    throw CLI::ValidationError("--nvswitch-evidence-file", "--nvswitch-evidence-file must be provided when --nvswitch-evidence-source=file");
                }
                auto validator = CLI::ExistingFile;
                auto result = validator(options.switch_evidence_file);
                if (!result.empty()) {
                    throw CLI::ValidationError("--nvswitch-evidence-file", result);
                }
            }
        });
    }

    void add_evidence_policy_options(CLI::App* app, EvidencePolicyOptions& options) {
        static const char* group = "Evidence Appraisal Options";
        app->add_flag("--verify-rim-signatures,!--no-verify-rim-signatures", options.verify_rim_signature, "Whether to verify RIM file signatures")
            ->group(group)
            ->default_val(true);
        app->add_flag("--verify-rim-cert-chain,!--no-verify-rim-cert-chain", options.verify_rim_cert_chain, "Whether to verify RIM file certificate chains")
            ->group(group)
            ->default_val(true);
    }

    void add_evidence_verification_options(CLI::App* app, EvidenceVerificationOptions& options) {
        app->add_option("--verifier", options.verifier, "Appraise evidence using the given verifier type")
            ->check(CLI::IsMember({"local", "remote"}))
            ->default_val("local");
        app->add_option("--relying-party-policy", options.relying_party_policy, "Path to a local file which contains a Relying Party Rego policy")
            ->check(CLI::ExistingFile)
            ->default_str("");
        app->add_option("--rim-store", options.rim_store, "Type of RIM store to use if --verifier=local")
            ->check(CLI::IsMember({"remote", "dir"}))
            ->default_val("remote");
        app->add_option("--rim-url", options.rim_url, "Base URL for the NVIDIA RIM service. Used if --rim-store=remote")
            ->envname("NVAT_RIM_SERVICE_BASE_URL")
            ->default_val("https://rim.attestation.nvidia.com");
        app->add_option("--rim-dir", options.rim_path, "Path to a directory containing RIM files. Used if --rim-store=dir")
            ->check(CLI::ExistingDirectory)
            ->default_val(".");
        app->add_option("--ocsp-url", options.ocsp_url, "Base URL for the OCSP responder")
            ->envname("NVAT_OCSP_BASE_URL")
            ->default_val("https://ocsp.ndis.nvidia.com");
        add_ocsp_cert_id_hash_option(app, options.ocsp_cert_id_hash);
        app->add_option("--nras-url", options.nras_url, "Base URL for the NVIDIA Remote Attestation Service")
            ->envname("NVAT_NRAS_BASE_URL")
            ->default_val("https://nras.attestation.nvidia.com");
        app->add_option("--service-key", options.service_key, "Service key used to authenticate remote service calls to attestation services")
           ->envname("NV_ATTESTATION_SERVICE_KEY")
           ->default_val("");
        app->add_option("--tls-ca-cert", options.tls_ca_cert, "Path to a TLS CA certificate bundle file (PEM)")
           ->envname("NVAT_TLS_CA_CERT")
           ->check(CLI::ExistingFile)
           ->default_str("");
        app->add_option("--tls-ca-path", options.tls_ca_path, "Path to a directory of TLS CA certificates")
           ->envname("NVAT_TLS_CA_PATH")
           ->check(CLI::ExistingDirectory)
           ->default_str("");
    }

    void add_common_options(CLI::App& app, CommonOptions& options) {
        app.fallthrough(true);

        app.add_option("--log-level,-l", options.log_level_str, "Print logs at or above the given level")
            ->envname("NVAT_LOG_LEVEL")
            ->check(CLI::IsMember({"trace", "debug", "info", "warn", "error", "off"}))
            ->default_val("info");

        app.add_option("--format,-f", options.format, "Print output in the given format")
            ->envname("NVAT_FORMAT")
            ->check(CLI::IsMember({"text", "json"}))
            ->default_val("text");
    }

    void print_error_help(const CliLogger& logger, nvat_rc_t rc) {
        if (rc == NVAT_RC_OK) {
            return;
        }

        bool needs_debug_hint = true;
        switch(rc) {
            case NVAT_RC_BAD_ARGUMENT:
                needs_debug_hint = false;
                break;
            case NVAT_RC_RP_POLICY_MISMATCH:
                SPDLOG_CRITICAL("Submitted evidence was appraised by the verifier, but did not match the relying party policy.");
                SPDLOG_CRITICAL("Review the attestation results against the supplied relying party policy.");
                break;
            case NVAT_RC_OVERALL_RESULT_FALSE:
                SPDLOG_CRITICAL("Submitted evidence did not match the verifier evidence appraisal policy.");
                break;
            case NVAT_RC_NVML_INIT_FAILED:
                SPDLOG_CRITICAL("Ensure the NVIDIA Driver is installed and initialized.");
                break;
            case NVAT_RC_NSCQ_INIT_FAILED:
                SPDLOG_CRITICAL("Ensure libnvidia-nscq is installed and an NVSwitch is available on this node.");
                break;
            case NVAT_RC_CORELIB_INIT_FAILED:
                SPDLOG_CRITICAL("Ensure libcorelib.so.1 is installed and available in the library search path.");
                break;
            case NVAT_RC_RATE_LIMITED:
                SPDLOG_CRITICAL("NVIDIA attestation services are rate-limiting requests. Please retry after a few minutes. If the error persists, contact nv-attestation-devs@nvidia.com.");
                break;
        }

        SPDLOG_CRITICAL("");
        SPDLOG_CRITICAL("Error {:03d}: {}", rc, nvat_rc_to_string(rc));
        SPDLOG_CRITICAL("Backtrace:");
        auto errors = logger.get_error_messages();
        if (!errors.empty()) {
            for (auto it = errors.rbegin(); it != errors.rend(); ++it) {
                std::istringstream stream(*it);
                std::string line;
                bool first_line = true;
                while (std::getline(stream, line)) {
                    if (first_line) {
                        SPDLOG_CRITICAL("  | {}", line);
                        first_line = false;
                    } else {
                        SPDLOG_CRITICAL("    {}", line);
                    }
                }
            }
        }

        if (needs_debug_hint) {
            SPDLOG_CRITICAL("");
            SPDLOG_CRITICAL("Run with --log-level=debug for more information.");
        }
    }

    nvat_rc_t make_http_options(
        const EvidenceVerificationOptions& verification_options,
        nvat_http_options_t& http_options_raw) {
        http_options_raw = nullptr;
        if (verification_options.tls_ca_cert.empty() && verification_options.tls_ca_path.empty()) {
            return NVAT_RC_OK;
        }
        nvat_rc_t err = nvat_http_options_create_default(&http_options_raw);
        if (err != NVAT_RC_OK) {
            return err;
        }
        if (!verification_options.tls_ca_cert.empty()) {
            nvat_http_options_set_tls_ca_cert(http_options_raw, verification_options.tls_ca_cert.c_str());
        }
        if (!verification_options.tls_ca_path.empty()) {
            nvat_http_options_set_tls_ca_path(http_options_raw, verification_options.tls_ca_path.c_str());
        }
        return NVAT_RC_OK;
    }

    CLI::Validator ocsp_cert_id_hash_validator() {
        return CLI::Validator(
            [](std::string& value) {
                nvat_ocsp_cert_id_hash_algorithm_t algorithm{};
                return nvat_ocsp_cert_id_hash_algorithm_from_name(
                           value.c_str(), &algorithm) == NVAT_RC_OK
                    ? std::string{}
                    : std::string{"unsupported OCSP CertID hash algorithm"};
            },
            "SHA-1, SHA-256, or SHA-384",
            "OCSP_CERT_ID_HASH");
    }

    void add_ocsp_cert_id_hash_option(CLI::App* app, std::string& value) {
        app->add_option(
               "--ocsp-cert-id-hash", value,
               "Hash algorithm used to construct OCSP CertIDs")
            ->envname("NVAT_OCSP_CERT_ID_HASH_ALGORITHM")
            ->check(ocsp_cert_id_hash_validator())
            ->default_val("sha-256");
    }

    nvat_rc_t make_ocsp_client_options(
        const std::string& name,
        nvat_ocsp_client_options_t& out_options) {
        out_options = nullptr;
        nvat_ocsp_cert_id_hash_algorithm_t algorithm{};
        nvat_rc_t err = nvat_ocsp_cert_id_hash_algorithm_from_name(
            name.c_str(), &algorithm);
        if (err != NVAT_RC_OK) return err;

        err = nvat_ocsp_client_options_create_default(&out_options);
        if (err != NVAT_RC_OK) {
            return err;
        }
        err = nvat_ocsp_client_options_set_cert_id_hash_algorithm(
            out_options, algorithm);
        if (err != NVAT_RC_OK) {
            nvat_ocsp_client_options_free(&out_options);
            return err;
        }
        return NVAT_RC_OK;
    }

    nvat_rc_t load_relying_party_policy(
        const std::string& path,
        nvat_relying_party_policy_t& out_raw_policy) {
        out_raw_policy = nullptr;
        std::ifstream policy_file(path);
        if (!policy_file) {
            SPDLOG_ERROR("Failed to open relying party policy file: {}", path);
            return NVAT_RC_BAD_ARGUMENT;
        }

        std::ostringstream policy_stream;
        policy_stream << policy_file.rdbuf();
        const std::string policy = policy_stream.str();

        nvat_rc_t err = nvat_relying_party_policy_create_rego_from_str(
            &out_raw_policy, policy.c_str());
        if (err != NVAT_RC_OK && out_raw_policy != nullptr) {
            nvat_relying_party_policy_free(&out_raw_policy);
        }
        return err;
    }

    nvat_rc_t init_sdk(CliLogger& logger, const CommonOptions& common_options) {
        nvat_rc_t err;

        nvat_sdk_opts_t raw_opts = nullptr;
        nv_unique_ptr<nvat_sdk_opts_t> opts;
        err = nvat_sdk_opts_create(&raw_opts);
        if (err != NVAT_RC_OK) {
            return err;
        }
        opts.reset(&raw_opts);

        nvat_logger_t nvat_logger;
        err = logger.create_nvat_logger(&nvat_logger);
        if (err != NVAT_RC_OK) {
            return err;
        }
        nvat_sdk_opts_set_logger(*(opts.get()), nvat_logger);
        nvat_logger_free(&nvat_logger);

        return nvat_sdk_init(*(opts.get()));
    }

    nvat_rc_t collect_cmw_json(nvat_gpu_evidence_source_t source,
                               nvat_nonce_t nonce,
                               std::vector<uint8_t>& out_cmw_json) {
        nv_unique_ptr<GpuEvidenceWrapper> evidence_guard(new GpuEvidenceWrapper());
        nvat_rc_t err = nvat_gpu_evidence_collect(
            source, nonce, &evidence_guard->evidences,
            &evidence_guard->num_evidences);
        if (err != NVAT_RC_OK) {
            return err;
        }

        nvat_cmw_collection_t raw_cmw = nullptr;
        nv_unique_ptr<nvat_cmw_collection_t> cmw_guard;
        err = nvat_cmw_collection_create_from_gpu_evidence(
            &raw_cmw, evidence_guard->evidences, evidence_guard->num_evidences,
            nonce);
        if (err != NVAT_RC_OK) {
            return err;
        }
        cmw_guard.reset(&raw_cmw);

        nvat_str_t raw_serialized = nullptr;
        nv_unique_ptr<nvat_str_t> serialized_guard;
        err = nvat_cmw_collection_serialize(raw_cmw, NVAT_CMW_FORMAT_JSON,
                                            &raw_serialized);
        if (err != NVAT_RC_OK) {
            return err;
        }
        serialized_guard.reset(&raw_serialized);

        char* data = nullptr;
        err = nvat_str_get_data(raw_serialized, &data);
        if (err != NVAT_RC_OK) {
            return err;
        }
        size_t length = 0;
        err = nvat_str_length(raw_serialized, &length);
        if (err != NVAT_RC_OK) {
            return err;
        }
        out_cmw_json.assign(data, data + length);
        return NVAT_RC_OK;
    }

    nvat_rc_t collect_cmw_json_from_spdm(const std::string& transcript_file,
                                         const std::string& cert_chain_file,
                                         const std::string& nonce_hex,
                                         std::vector<uint8_t>& out_cmw_json) {
        std::vector<uint8_t> transcript_bytes;
        std::vector<uint8_t> cert_bytes;
        nvat_rc_t err = read_binary_file(transcript_file, transcript_bytes);
        if (err != NVAT_RC_OK) {
            return err;
        }
        err = read_binary_file(cert_chain_file, cert_bytes);
        if (err != NVAT_RC_OK) {
            return err;
        }

        nvat_nonce_t raw_nonce = nullptr;
        nv_unique_ptr<nvat_nonce_t> nonce_guard;
        if (!nonce_hex.empty()) {
            err = nvat_nonce_from_hex(&raw_nonce, nonce_hex.c_str());
            if (err != NVAT_RC_OK) {
                return err;
            }
            nonce_guard.reset(&raw_nonce);
        }

        nvat_cmw_collection_t raw_col = nullptr;
        nv_unique_ptr<nvat_cmw_collection_t> col_guard;
        err = nvat_cmw_collection_create_from_spdm_transcript(
            &raw_col, "device_0",
            transcript_bytes.data(), transcript_bytes.size(),
            cert_bytes.data(), cert_bytes.size(),
            raw_nonce);
        if (err != NVAT_RC_OK) {
            return err;
        }
        col_guard.reset(&raw_col);

        nvat_str_t raw_serialized = nullptr;
        nv_unique_ptr<nvat_str_t> serialized_guard;
        err = nvat_cmw_collection_serialize(raw_col, NVAT_CMW_FORMAT_JSON, &raw_serialized);
        if (err != NVAT_RC_OK) {
            return err;
        }
        serialized_guard.reset(&raw_serialized);

        char* data = nullptr;
        if (nvat_str_get_data(raw_serialized, &data) != NVAT_RC_OK || data == nullptr) {
            return NVAT_RC_INTERNAL_ERROR;
        }
        size_t length = 0;
        err = nvat_str_length(raw_serialized, &length);
        if (err != NVAT_RC_OK) {
            return err;
        }
        out_cmw_json.assign(data, data + length);
        return NVAT_RC_OK;
    }

    nvat_rc_t collect_cmw_json_from_eat(const std::string& eat_file,
                                        const std::string& nonce_hex,
                                        std::vector<uint8_t>& out_cmw_json) {
        std::vector<uint8_t> token_bytes;
        nvat_rc_t err = read_binary_file(eat_file, token_bytes);
        if (err != NVAT_RC_OK) {
            return err;
        }

        nvat_nonce_t raw_nonce = nullptr;
        nv_unique_ptr<nvat_nonce_t> nonce_guard;
        if (!nonce_hex.empty()) {
            err = nvat_nonce_from_hex(&raw_nonce, nonce_hex.c_str());
            if (err != NVAT_RC_OK) {
                return err;
            }
            nonce_guard.reset(&raw_nonce);
        }

        nvat_cmw_collection_t raw_col = nullptr;
        nv_unique_ptr<nvat_cmw_collection_t> col_guard;
        err = nvat_cmw_collection_create_from_eat(
            &raw_col, "device_0",
            token_bytes.data(), token_bytes.size(),
            raw_nonce);
        if (err != NVAT_RC_OK) {
            return err;
        }
        col_guard.reset(&raw_col);

        nvat_str_t raw_serialized = nullptr;
        nv_unique_ptr<nvat_str_t> serialized_guard;
        err = nvat_cmw_collection_serialize(raw_col, NVAT_CMW_FORMAT_JSON, &raw_serialized);
        if (err != NVAT_RC_OK) {
            return err;
        }
        serialized_guard.reset(&raw_serialized);

        char* data = nullptr;
        if (nvat_str_get_data(raw_serialized, &data) != NVAT_RC_OK || data == nullptr) {
            return NVAT_RC_INTERNAL_ERROR;
        }
        size_t length = 0;
        err = nvat_str_length(raw_serialized, &length);
        if (err != NVAT_RC_OK) {
            return err;
        }
        out_cmw_json.assign(data, data + length);
        return NVAT_RC_OK;
    }
}
