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
 */

#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "CLI/Validators.hpp"
#include "attest_v2.h"
#include "ear_status.h"
#include "nvat.h"
#include "nvattest_types.h"
#include "spdlog/spdlog.h"
#include "utils.h"

namespace nvattest {

namespace {

constexpr uint64_t kDefaultCacheBytes   = 10ULL * 1024 * 1024;
constexpr time_t   kDefaultCacheTtlSecs = 3600;

nvat_rc_t collect_cmw_from_nvml(const std::string& nonce_hex,
                                std::vector<uint8_t>& out) {
    nvat_nonce_t raw_nonce = nullptr;
    nv_unique_ptr<nvat_nonce_t> nonce_guard;
    nvat_rc_t err = nonce_hex.empty()
        ? nvat_nonce_create(&raw_nonce, 32)
        : nvat_nonce_from_hex(&raw_nonce, nonce_hex.c_str());
    if (err != NVAT_RC_OK) {
        return err;
    }
    nonce_guard.reset(&raw_nonce);

    nvat_gpu_evidence_source_t raw_source = nullptr;
    nv_unique_ptr<nvat_gpu_evidence_source_t> source_guard;
    err = nvat_gpu_evidence_source_nvml_create(&raw_source);
    if (err != NVAT_RC_OK) {
        return err;
    }
    source_guard.reset(&raw_source);

    return collect_cmw_json(raw_source, raw_nonce, out);
}

nvat_rc_t run_verify(CliLogger& logger, const AttestV2Options& options,
                     const CommonOptions& common_options,
                     std::string& out_ear_json, std::string& out_ear_jwt) {
    nvat_rc_t err = init_sdk(logger, common_options);
    if (err != NVAT_RC_OK) {
        return err;
    }

    std::vector<uint8_t> cmw_bytes;
    if (options.evidence_source == "nvml") {
        SPDLOG_INFO("Collecting GPU evidence from NVML...");
        err = collect_cmw_from_nvml(options.nonce, cmw_bytes);
        if (err != NVAT_RC_OK) {
            return err;
        }
    } else if (options.evidence_source == "spdm-files") {
        err = collect_cmw_json_from_spdm(
            options.spdm_transcript_file, options.cert_chain_file,
            options.nonce, cmw_bytes);
        if (err != NVAT_RC_OK) {
            return err;
        }
    } else if (options.evidence_source == "eat-file") {
        err = collect_cmw_json_from_eat(options.eat_file, options.nonce,
                                        cmw_bytes);
        if (err != NVAT_RC_OK) {
            return err;
        }
    } else {
        err = read_binary_file(options.evidence_file, cmw_bytes);
        if (err != NVAT_RC_OK) {
            return err;
        }
    }

    const char* service_key =
        options.service_key.empty() ? nullptr : options.service_key.c_str();

    nvat_corim_store_t raw_store = nullptr;
    nv_unique_ptr<nvat_corim_store_t> store_guard;
    err = nvat_corim_store_create(&raw_store, service_key, nullptr);
    if (err != NVAT_RC_OK) {
        return err;
    }
    store_guard.reset(&raw_store);

    for (size_t i = 0; i + 1 < options.rim_url_rewrites.size(); i += 2) {
        err = nvat_corim_store_add_url_rewrite(
            raw_store, options.rim_url_rewrites[i].c_str(),
            options.rim_url_rewrites[i + 1].c_str());
        if (err != NVAT_RC_OK) {
            return err;
        }
    }

    err = nvat_corim_store_enable_in_memory_cache(raw_store, kDefaultCacheBytes,
                                        kDefaultCacheTtlSecs);
    if (err != NVAT_RC_OK) {
        return err;
    }

    nvat_ocsp_client_t raw_ocsp = nullptr;
    nvat_ocsp_client_t raw_inner_ocsp = nullptr;
    nv_unique_ptr<nvat_ocsp_client_t> ocsp_guard;
    nv_unique_ptr<nvat_ocsp_client_t> inner_ocsp_guard;
    if (options.verify_revocation) {
        std::vector<const char*> ocsp_patterns;
        std::vector<const char*> ocsp_replacements;
        for (size_t i = 0; i + 1 < options.ocsp_url_rewrites.size(); i += 2) {
            ocsp_patterns.push_back(options.ocsp_url_rewrites[i].c_str());
            ocsp_replacements.push_back(options.ocsp_url_rewrites[i + 1].c_str());
        }
        {
            nvat_ocsp_client_options_t raw_ocsp_options = nullptr;
            nv_unique_ptr<nvat_ocsp_client_options_t> ocsp_options_guard;
            err = make_ocsp_client_options(
                options.ocsp_cert_id_hash, raw_ocsp_options);
            if (err != NVAT_RC_OK) {
                return err;
            }
            ocsp_options_guard.reset(&raw_ocsp_options);
            err = nvat_ocsp_client_create_aia(
                &raw_inner_ocsp, nullptr, service_key, nullptr,
                ocsp_patterns.data(), ocsp_replacements.data(),
                ocsp_patterns.size(), raw_ocsp_options);
            if (err != NVAT_RC_OK) {
                return err;
            }
        }
        inner_ocsp_guard.reset(&raw_inner_ocsp);

        err = nvat_ocsp_client_create_cached(&raw_ocsp, raw_inner_ocsp,
                                             kDefaultCacheBytes,
                                             kDefaultCacheTtlSecs);
        if (err != NVAT_RC_OK) {
            return err;
        }
        ocsp_guard.reset(&raw_ocsp);
    }

    nvat_local_corim_verifier_t raw_verifier = nullptr;
    nv_unique_ptr<nvat_local_corim_verifier_t> verifier_guard;
    err = nvat_local_corim_verifier_create(&raw_verifier, &raw_store, raw_ocsp);
    if (err != NVAT_RC_OK) {
        return err;
    }
    verifier_guard.reset(&raw_verifier);

    err = nvat_local_corim_verifier_set_verify_rim_signature(
        raw_verifier, options.verify_rim_signature);
    if (err != NVAT_RC_OK) {
        return err;
    }

    err = nvat_local_corim_verifier_set_verify_coev_signature(
        raw_verifier, options.verify_rim_signature);
    if (err != NVAT_RC_OK) {
        return err;
    }

    err = nvat_local_corim_verifier_set_verify_evidence_signature(
        raw_verifier, options.verify_evidence_signature);
    if (err != NVAT_RC_OK) {
        return err;
    }

    err = nvat_local_corim_verifier_set_verify_revocation(
        raw_verifier, options.verify_revocation);
    if (err != NVAT_RC_OK) {
        return err;
    }

    if (!options.backup_spdm_coev_file.empty()) {
        std::vector<uint8_t> coev_bytes;
        err = read_binary_file(options.backup_spdm_coev_file, coev_bytes);
        if (err != NVAT_RC_OK) {
            return err;
        }
        err = nvat_local_corim_verifier_set_backup_spdm_coev(
            raw_verifier, coev_bytes.data(), coev_bytes.size());
        if (err != NVAT_RC_OK) {
            return err;
        }
    }
    for (const auto& uri : options.backup_rim_locators) {
        err = nvat_local_corim_verifier_add_backup_rim_locator(raw_verifier, uri.c_str());
        if (err != NVAT_RC_OK) {
            return err;
        }
    }

    nvat_detached_eat_options_t raw_signing_options = nullptr;
    nv_unique_ptr<nvat_detached_eat_options_t> signing_options_guard;
    if (!options.ear_signing_key_file.empty() || !options.ear_signing_issuer.empty()) {
        std::string private_key_pem;
        if (!options.ear_signing_key_file.empty()) {
            std::vector<uint8_t> private_key_pem_bytes;
            err = read_binary_file(options.ear_signing_key_file, private_key_pem_bytes);
            if (err != NVAT_RC_OK) {
                return err;
            }
            private_key_pem.assign(private_key_pem_bytes.begin(), private_key_pem_bytes.end());
        }
        const char* private_key = private_key_pem.empty() ? nullptr : private_key_pem.c_str();
        const char* issuer = options.ear_signing_issuer.empty() ? nullptr : options.ear_signing_issuer.c_str();
        const char* kid = options.ear_signing_kid.empty() ? nullptr : options.ear_signing_kid.c_str();
        err = nvat_detached_eat_options_create(&raw_signing_options, private_key, issuer, kid);
        if (err != NVAT_RC_OK) {
            return err;
        }
        signing_options_guard.reset(&raw_signing_options);
    }

    nvat_str_t raw_result = nullptr;
    nv_unique_ptr<nvat_str_t> result_guard;
    nvat_str_t raw_result_jwt = nullptr;
    nv_unique_ptr<nvat_str_t> result_jwt_guard;
    err = nvat_local_corim_verifier_verify_cmw(
        raw_verifier, cmw_bytes.data(), cmw_bytes.size(),
        NVAT_CMW_FORMAT_JSON, raw_signing_options, &raw_result_jwt, &raw_result);
    if (raw_result != nullptr) {
        result_guard.reset(&raw_result);
        char* data = nullptr;
        if (nvat_str_get_data(raw_result, &data) == NVAT_RC_OK &&
            data != nullptr) {
            out_ear_json = data;
        }
    }
    if (raw_result_jwt != nullptr) {
        result_jwt_guard.reset(&raw_result_jwt);
        char* data = nullptr;
        if (nvat_str_get_data(raw_result_jwt, &data) == NVAT_RC_OK &&
            data != nullptr) {
            out_ear_jwt = data;
        }
    }
    return err;
}

// Exit status of the attest-v2 subcommand.
enum class AttestV2ExitCode : int {
    kAffirming = 0,        // every evidence item was appraised and matched
    kContraindicated = 1,  // appraisal ran but did not affirm
    kVerifierError = 2,    // trust could not be determined
};

AttestV2ExitCode attestation_status(const nlohmann::json& ear) {
    return ear_is_affirming(ear) ? AttestV2ExitCode::kAffirming
                                 : AttestV2ExitCode::kContraindicated;
}

// Renders one EnvironmentMap: optional class (class_id, vendor, model,
// layer, index) plus optional instance/group. No field is guaranteed.
void print_environment(std::ostream& out, const nlohmann::json& env, const std::string& indent) {
    std::string vendor, model, class_id;
    const auto cls = env.find("class");
    if (cls != env.end() && cls->is_object()) {
        vendor = cls->value("vendor", std::string());
        model = cls->value("model", std::string());
        class_id = cls->value("class_id", std::string());
    }

    std::string name = vendor + (vendor.empty() || model.empty() ? "" : " ") + model;
    std::string header = class_id.empty() ? name : (name.empty() ? class_id : name + " (" + class_id + ")");
    if (header.empty()) {
        header = "[no class]";
    }
    out << indent << "- " << header;
    if (cls != env.end() && cls->is_object()) {
        const auto layer = cls->find("layer");
        if (layer != cls->end() && layer->is_number_unsigned()) {
            out << ", layer=" << layer->get<uint32_t>();
        }
        const auto index = cls->find("index");
        if (index != cls->end() && index->is_number_unsigned()) {
            out << ", index=" << index->get<uint32_t>();
        }
    }
    out << "\n";

    if (env.contains("instance") && env["instance"].is_string()) {
        out << indent << "  Instance: " << env["instance"].get<std::string>() << "\n";
    }
    if (env.contains("group") && env["group"].is_string()) {
        out << indent << "  Group: " << env["group"].get<std::string>() << "\n";
    }
}

// Renders a PerCertStatus array (nv_x509.h) — the cert_chain shape shared by
// both ear_nvidia_evidence and each ear_nvidia_rims entry.
void print_cert_chain(std::ostream& out, const nlohmann::json& cert_chain, const std::string& indent) {
    if (!cert_chain.is_array() || cert_chain.empty()) {
        return;
    }
    out << indent << "Cert Chain:" << "\n";
    for (size_t i = 0; i < cert_chain.size(); ++i) {
        const auto& cert = cert_chain[i];
        if (!cert.is_object()) {
            out << indent << "- L" << (i + 1) << ": [invalid]" << "\n";
            continue;
        }
        out << indent << "- L" << (i + 1) << ": "
            << cert.value("cert_check_status", std::string("[unknown]"))
            << ", expires " << cert.value("expiration_date", std::string("[unknown]")) << "\n";
        if (cert.contains("ocsp_crl_status") && cert["ocsp_crl_status"].is_string()) {
            std::string ocsp_status = cert["ocsp_crl_status"].get<std::string>();
            if (cert.contains("revocation_reason") && cert["revocation_reason"].is_string()) {
                out << indent << "  OCSP: " << ocsp_status << " (" << cert["revocation_reason"].get<std::string>() << ")" << "\n";
            } else {
                out << indent << "  OCSP: " << ocsp_status << "\n";
            }
        }
    }
}

// ear_verifier_claims.ear_nvidia_evidence — signature/nonce verdicts on the
// submitted device evidence plus its cert chain.
void print_evidence(std::ostream& out, const nlohmann::json& evidence) {
    if (!evidence.is_object()) {
        return;
    }
    out << "    Evidence:" << "\n";
    if (evidence.contains("signature_verified") && evidence["signature_verified"].is_boolean()) {
        out << "      Signature Verified: " << std::boolalpha << evidence["signature_verified"].get<bool>() << "\n";
    }
    if (evidence.contains("parsed") && evidence["parsed"].is_boolean()) {
        out << "      Parsed: " << std::boolalpha << evidence["parsed"].get<bool>() << "\n";
    }
    if (evidence.contains("nonce_match") && evidence["nonce_match"].is_boolean()) {
        out << "      Nonce Match: " << std::boolalpha << evidence["nonce_match"].get<bool>() << "\n";
    }
    const auto cert_chain = evidence.find("cert_chain");
    if (cert_chain != evidence.end()) {
        print_cert_chain(out, *cert_chain, "      ");
    }
}

// ear_verifier_claims.ear_nvidia_rims — the RIM locators consulted, whether
// each was fetched/signed, and its cert chain when fetched.
void print_rims(std::ostream& out, const nlohmann::json& rims) {
    if (!rims.is_array() || rims.empty()) {
        return;
    }
    out << "    RIM Locators:" << "\n";
    for (const auto& rim : rims) {
        if (!rim.is_object()) {
            out << "    - [invalid]" << "\n";
            continue;
        }
        out << "    - " << rim.value("locator", std::string("[unknown]")) << "\n";
        bool fetched = rim.value("fetched", false);
        out << "      Fetched: " << std::boolalpha << fetched << "\n";
        if (fetched && rim.contains("signature_verified") && rim["signature_verified"].is_boolean()) {
            out << "      Signature Verified: " << std::boolalpha << rim["signature_verified"].get<bool>() << "\n";
        }
        const auto cert_chain = rim.find("cert_chain");
        if (cert_chain != rim.end()) {
            print_cert_chain(out, *cert_chain, "      ");
        }
    }
}

// submod.ear_nvidia_error_details — why a contraindicated submod failed.
void print_error_details(std::ostream& out, const nlohmann::json& body) {
    const auto errors = body.find("ear_nvidia_error_details");
    if (errors == body.end() || !errors->is_array() || errors->empty()) {
        return;
    }
    out << "    Error Details:" << "\n";
    for (const auto& entry : *errors) {
        if (!entry.is_object()) {
            out << "      - [invalid error detail]" << "\n";
            continue;
        }
        out << "      - [" << entry.value("code", 0) << "] "
            << entry.value("message", std::string("[unknown]")) << "\n";
        if (entry.contains("details") && entry["details"].is_string()) {
            out << "          Details: " << entry["details"].get<std::string>() << "\n";
        }
        if (entry.contains("related_envs") && entry["related_envs"].is_array() &&
            !entry["related_envs"].empty()) {
            out << "          Related Environments:\n";
            for (const auto& env : entry["related_envs"]) {
                if (env.is_object()) {
                    print_environment(out, env, "          ");
                }
            }
        }
    }
}

void print_ear_submods(std::ostream& out, const nlohmann::json& ear) {
    out << "EAT Profile: " << ear.value("eat_profile", std::string("[unknown]")) << "\n";
    out << "Nonce: " << ear.value("eat_nonce", std::string("[not set]")) << "\n";
    out << "Overall Status: " << ear.value("ear_status", std::string("[unknown]")) << "\n";
    out << "\n";

    const auto submods = ear.find("submods");
    if (submods == ear.end() || !submods->is_object() || submods->empty()) {
        out << "Submods: [none]" << "\n";
        return;
    }

    out << "Submods:" << "\n";
    for (const auto& submod : submods->items()) {
        out << "- " << submod.key() << ":" << "\n";
        if (!submod.value().is_object()) {
            out << "    [invalid submod format]" << "\n";
            continue;
        }
        const auto& body = submod.value();

        if (body.contains("eat_profile") && body["eat_profile"].is_string()) {
            out << "    Profile: " << body["eat_profile"].get<std::string>() << "\n";
        }
        out << "    Status: " << body.value("ear_status", std::string("[unknown]")) << "\n";
        if (body.contains("ear_nvidia_purpose") && body["ear_nvidia_purpose"].is_string()) {
            out << "    Purpose: " << body["ear_nvidia_purpose"].get<std::string>() << "\n";
        }
        if (body.contains("eat_nonce") && body["eat_nonce"].is_string()) {
            out << "    Nonce: " << body["eat_nonce"].get<std::string>() << "\n";
        }

        print_error_details(out, body);

        const auto attester_claims = body.find("ear_attester_claims");
        if (attester_claims != body.end() && attester_claims->is_object() && !attester_claims->empty()) {
            out << "    Attester Claims:" << "\n";
            for (const auto& claim : attester_claims->items()) {
                if (claim.value().is_string()) {
                    out << "        " << claim.key() << ": " << claim.value().get<std::string>() << "\n";
                } else {
                    out << "        " << claim.key() << ": " << claim.value().dump() << "\n";
                }
            }
        }

        const auto verifier_claims = body.find("ear_verifier_claims");
        if (verifier_claims != body.end() && verifier_claims->is_object()) {
            const auto evidence = verifier_claims->find("ear_nvidia_evidence");
            if (evidence != verifier_claims->end()) {
                print_evidence(out, *evidence);
            }

            const auto rims = verifier_claims->find("ear_nvidia_rims");
            if (rims != verifier_claims->end()) {
                print_rims(out, *rims);
            }

            const auto rim_cmp = verifier_claims->find("ear_nvidia_evidence_rim_cmp");
            if (rim_cmp != verifier_claims->end() && rim_cmp->is_object()) {
                const auto mismatched = rim_cmp->find("mismatched_env");
                if (mismatched != rim_cmp->end() && mismatched->is_array() && !mismatched->empty()) {
                    out << "    Mismatched Environments (" << mismatched->size() << "):" << "\n";
                    for (const auto& env : *mismatched) {
                        print_environment(out, env, "    ");
                    }
                }
                const auto unmatched = rim_cmp->find("unmatched_env");
                if (unmatched != rim_cmp->end() && unmatched->is_array() && !unmatched->empty()) {
                    out << "    Unmatched Environments (" << unmatched->size() << "):" << "\n";
                    for (const auto& env : *unmatched) {
                        print_environment(out, env, "    ");
                    }
                }
            }
        }
    }
    out << "\n";
}

nvat_rc_t apply_relying_party_policy(const std::string& policy_path,
                                     const std::string& ear_json) {
    nvat_relying_party_policy_t raw_policy = nullptr;
    nv_unique_ptr<nvat_relying_party_policy_t> policy_guard;
    nvat_rc_t err = load_relying_party_policy(policy_path, raw_policy);
    if (err != NVAT_RC_OK) {
        return err;
    }
    policy_guard.reset(&raw_policy);

    return nvat_apply_relying_party_policy_to_ear(raw_policy, ear_json.c_str());
}

} // namespace

CLI::App* create_attest_v2_subcommand(CLI::App& app, AttestV2Options& options) {
    auto* subcommand = app.add_subcommand("attest-v2");
    subcommand->group("Experimental Subcommands");
    subcommand->description("[EXPERIMENTAL] Verify device evidence as a CMW input collection.");

    subcommand->add_option(
        "--nonce", options.nonce,
        "Expected attestation nonce in hex. Generated when omitted for nvml; "
        "optional for eat-file and spdm-files. When supplied, the verifier "
        "reports whether the evidence nonce matches.")
        ->default_val("");

    subcommand->add_option("--evidence-source", options.evidence_source,
                           "Where evidence comes from. nvml collects live via NVML; "
                           "file reads a pre-collected CMW JSON; "
                           "spdm-files reads a raw SPDM transcript and PEM cert chain; "
                           "eat-file reads a signed EAT/CWT token.")
        ->check(CLI::IsMember({"nvml", "file", "spdm-files", "eat-file"}))
        ->default_val("nvml");

    subcommand->add_option("--evidence-file", options.evidence_file,
                           "Path to a CMW JSON file. Required when --evidence-source=file.")
        ->default_str("");

    subcommand->add_option(
        "--spdm-transcript-file", options.spdm_transcript_file,
        "Path to a binary SPDM measurement transcript. Required when "
        "--evidence-source=spdm-files.")
        ->check(CLI::ExistingFile);

    subcommand->add_option(
        "--cert-chain-file", options.cert_chain_file,
        "Path to a PEM certificate chain. Required when --evidence-source=spdm-files.")
        ->check(CLI::ExistingFile);

    subcommand->add_option(
        "--eat-file", options.eat_file,
        "Path to a signed EAT/CWT token. Required when "
        "--evidence-source=eat-file. The device-identity chain is embedded "
        "in the token; no separate --cert-chain-file is needed.")
        ->check(CLI::ExistingFile);

    subcommand->add_option(
        "--rim-url-rewrite", options.rim_url_rewrites,
        "Prefix substitution applied to rim-locator URLs before fetching. "
        "Takes two tokens: PATTERN REPLACEMENT. Repeatable; first match wins. "
        "The pre-rewrite URL must still pass the verifier's allowlist, so use "
        "this to redirect https://rim.attestation.nvidia.com/ to a mirror or "
        "local file:// path.")
        ->type_size(2);

    subcommand->add_flag(
        "--verify-rim-signatures,!--no-verify-rim-signatures",
        options.verify_rim_signature,
        "Whether to verify CoRIM signatures, and the signature on any CoEV "
        "fetched alongside a RIM from the RIM service. Pass "
        "--no-verify-rim-signatures to also accept unsigned CoRIMs and "
        "unsigned/tampered RIM-service CoEVs. Not for production.")
        ->default_val(true);

    subcommand->add_flag(
        "--verify-evidence-signatures,!--no-verify-evidence-signatures",
        options.verify_evidence_signature,
        "Whether to verify the evidence payload's own signature (e.g. an "
        "EAT's COSE_Sign1). With --no-verify-evidence-signatures, unsigned, "
        "tampered, or untrusted evidence and parseable chain claims are "
        "retained for diagnostics, but remain contraindicated. Disable only "
        "for development fixtures.")
        ->default_val(true);

    subcommand->add_flag(
        "--verify-revocation,!--no-verify-revocation",
        options.verify_revocation,
        "Check certificate revocation via OCSP. The responder URL is taken "
        "from each certificate's AIA extension. Pass --no-verify-revocation "
        "to skip revocation checks.")
        ->default_val(true);

    add_ocsp_cert_id_hash_option(subcommand, options.ocsp_cert_id_hash);

    subcommand->add_option(
        "--ocsp-url-rewrite", options.ocsp_url_rewrites,
        "Prefix substitution applied to the OCSP responder URL before the "
        "request. Takes two tokens: PATTERN REPLACEMENT. Repeatable; first "
        "match wins. Use to upgrade http:// to https:// or redirect to an "
        "alternate responder, such as Trust Outpost.")
        ->type_size(2);

    subcommand->add_option(
        "--service-key", options.service_key,
        "Service key used to authenticate remote service calls to attestation "
        "services")
        ->envname("NV_ATTESTATION_SERVICE_KEY")
        ->default_val("");

    subcommand->add_option(
        "--backup-spdm-concise-evidence", options.backup_spdm_coev_file,
        "Path to a CBOR ConciseEvidence file. Used when SPDM evidence contains no CoEV.")
        ->check(CLI::ExistingFile);

    subcommand->add_option(
        "--backup-rim-locator", options.backup_rim_locators,
        "RIM locator URI used when evidence contains no locators. Repeatable.");

    subcommand->add_option(
        "--relying-party-policy", options.relying_party_policy,
        "Path to a local file containing a relying-party Rego policy for the EAR.")
        ->check(CLI::ExistingFile)
        ->default_str("");

    auto* ear_signing_key_file_opt = subcommand->add_option(
        "--ear-signing-key-file", options.ear_signing_key_file,
        "Path to a PEM-encoded ES384 private key used to sign the EAR JWT. "
        "If omitted, the EAR is unsigned (alg=none) — test only.")
        ->check(CLI::ExistingFile);

    subcommand->add_option(
        "--ear-signing-issuer", options.ear_signing_issuer,
        "Value for the EAR JWT's 'iss' claim. Omitted if not set. Valid even "
        "without --ear-signing-key-file, on the unsigned EAR — test only.")
        ->default_val("");

    subcommand->add_option(
        "--ear-signing-kid", options.ear_signing_kid,
        "Value for the EAR JWT header's 'kid' claim. Requires --ear-signing-key-file.")
        ->default_val("")
        ->needs(ear_signing_key_file_opt);

    subcommand->parse_complete_callback([&options]() {
        if (options.evidence_source == "file") {
            if (options.evidence_file.empty()) {
                throw CLI::ValidationError(
                    "--evidence-file",
                    "--evidence-file must be provided when --evidence-source=file");
            }
            auto validator = CLI::ExistingFile;
            auto result = validator(options.evidence_file);
            if (!result.empty()) {
                throw CLI::ValidationError("--evidence-file", result);
            }
        } else if (options.evidence_source == "spdm-files") {
            if (options.spdm_transcript_file.empty()) {
                throw CLI::ValidationError(
                    "--spdm-transcript-file",
                    "--spdm-transcript-file must be provided when --evidence-source=spdm-files");
            }
            if (options.cert_chain_file.empty()) {
                throw CLI::ValidationError(
                    "--cert-chain-file",
                    "--cert-chain-file must be provided when --evidence-source=spdm-files");
            }
        } else if (options.evidence_source == "eat-file") {
            if (options.eat_file.empty()) {
                throw CLI::ValidationError(
                    "--eat-file",
                    "--eat-file must be provided when --evidence-source=eat-file");
            }
        }
    });

    return subcommand;
}

int handle_attest_v2_subcommand(
    CliLogger& logger,
    const AttestV2Options& options,
    const CommonOptions& common_options) {

    std::string ear_json;
    std::string ear_jwt;
    nvat_rc_t err = run_verify(logger, options, common_options, ear_json, ear_jwt);

    nlohmann::json result = nlohmann::json::object();
    bool have_result = false;
    if (!ear_json.empty()) {
        nlohmann::json parsed =
            nlohmann::json::parse(ear_json, nullptr, /*allow_exceptions=*/false);
        if (!parsed.is_discarded()) {
            result = std::move(parsed);
            have_result = true;
            result["ear_jwt"] = ear_jwt;
        }
    }

    if (err == NVAT_RC_OK && have_result &&
        !options.relying_party_policy.empty()) {
        err = apply_relying_party_policy(options.relying_party_policy, ear_json);
    }
    nvat_sdk_shutdown();

    const bool text_format = common_options.format == "text";
    if (text_format && have_result) {
        print_ear_submods(std::cout, result);
    }

    AttestV2ExitCode exit_code;
    if (err != NVAT_RC_OK && err != NVAT_RC_RP_POLICY_MISMATCH) {
        SPDLOG_CRITICAL("");
        SPDLOG_CRITICAL("Attestation failed!");
        print_error_help(logger, err);
        exit_code = AttestV2ExitCode::kVerifierError;
    } else if (!have_result) {
        // No appraisal to judge: undetermined, not a failed device.
        SPDLOG_CRITICAL("");
        SPDLOG_CRITICAL("Attestation returned no usable result!");
        exit_code = AttestV2ExitCode::kVerifierError;
    } else {
        exit_code = options.relying_party_policy.empty()
            ? attestation_status(result)
            : (err == NVAT_RC_OK ? AttestV2ExitCode::kAffirming
                                 : AttestV2ExitCode::kContraindicated);
        if (exit_code == AttestV2ExitCode::kAffirming) {
            SPDLOG_INFO("Attestation was successful");
        } else {
            SPDLOG_CRITICAL("");
            SPDLOG_CRITICAL("Attestation did not affirm the device!");
            SPDLOG_CRITICAL(text_format ? "Review submod details above." : "Review submods in the output below.");
        }
    }

    if (common_options.format == "json") {
        std::cout << result.dump(4) << std::endl;
    }
    return static_cast<int>(exit_code);
}

} // namespace nvattest
