/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#include "nv_attestation/corim_evidence/evidence_handler.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <algorithm>
#include <openssl/evp.h>

#include "nv_attestation/cmw.h"
#include "nv_attestation/corim_evidence/coev.h"
#include "nv_attestation/corim_evidence/coev_to_ect.h"
#include "nv_attestation/corim_evidence/eat.h"
#include "nv_attestation/corim_evidence/eat_cwt.h"
#include "nv_attestation/corim_evidence/eat_to_ect.h"
#include "nv_attestation/cose.h"
#include "nv_attestation/log.h"
#include "nv_attestation/spdm/spdm_measurement_records.hpp"
#include "nv_attestation/spdm/spdm_req.hpp"
#include "nv_attestation/spdm/spdm_resp.hpp"
#include "nv_attestation/utils.h"

namespace nvattestation {

namespace {

// Raw SPDM 1.1 GET_MEASUREMENTS + MEASUREMENTS transcript, signed by the chain
// leaf; the companion certificate slot carries the device-identity chain.

constexpr std::size_t kSpdmSignatureLength = 96; // SHA-384, ECDSA P-384

// CBOR tag #6.570 (TCG DICE CoEV-SPDM tagged-spdm-toc), 2-byte tag form.
constexpr uint8_t kSpdmTocCborTagBytes[3] = {0xD9, 0x02, 0x3A};
// TCG DICE Concise Evidence Binding for SPDM v1.1 §§6.2 and 6.4 reserve
// measurement block index 0xFD for the SPDM Measurement Manifest.
constexpr uint8_t kSpdmMeasurementManifestBlockIndex = 0xFD;

// Bytes of each measurement value logged as a hex preview.
constexpr std::size_t kMeasurementLogPreviewBytes = 8;

// DMTF measurement block index carrying the device-identifier measurement
// (apSKU) used by the Blackwell FSP RIM-locator workaround.
constexpr uint8_t kDeviceIdentifierBlockIndex = 52;

constexpr const char *kSpdmMediaTypes[] = {kCmwMediaSpdmTranscript};

// The negotiated algorithm is not in the transcript. SPDM uses one algorithm
// per record, so derive it from the digest length; sha-384 when unusable.
int32_t derive_measurement_hash_alg_id(
    const SpdmMeasurementRecordParser &records) {
    const int32_t fallback = to_ni_algorithm_id(HashAlgorithm::Sha384);
    bool found = false;
    std::size_t digest_size = 0;
    for (const auto &entry : records.get_all_measurement_blocks()) {
        if (entry.second->get_measurement_value_type() > kDmtfTypeDigestMax) {
            continue;
        }
        const std::size_t size = entry.second->get_measurement_value().size();
        if (found && size != digest_size) {
            LOG_WARN("SPDM measurement record mixes digest sizes ("
                     << digest_size << " and " << size
                     << "); assuming sha-384");
            return fallback;
        }
        digest_size = size;
        found = true;
    }
    if (!found) {
        return fallback;
    }
    HashAlgorithm alg = HashAlgorithm::Sha384;
    if (hash_algorithm_from_digest_size(digest_size, alg) != Error::Ok) {
        LOG_WARN("SPDM digest length " << digest_size
                 << " matches no supported hash algorithm; assuming sha-384");
        return fallback;
    }
    LOG_DEBUG("SPDM measurement digests are " << digest_size << " bytes -> "
              << to_algorithm_name(alg));
    return to_ni_algorithm_id(alg);
}

class SpdmEvidenceHandler : public IEvidenceHandler {
  public:
    bool accepts_media_type(const std::string &media_type) const override {
        return std::any_of(
            std::begin(kSpdmMediaTypes), std::end(kSpdmMediaTypes),
            [&](const char *known) { return media_type == known; });
    }

    Error extract_cert_chain(const CmwEvidenceItem &item,
                             const EvidenceHandlerSettings &settings,
                             std::vector<uint8_t> &out_pem) const override;

    Error verify_and_extract_ects(const CmwEvidenceItem &item,
                                  X509CertChain &validated_chain,
                                  const EvidenceHandlerSettings &settings,
                                  EvidenceVerification &out_verification) const override;
};

Error SpdmEvidenceHandler::extract_cert_chain(
    const CmwEvidenceItem &item, const EvidenceHandlerSettings &settings,
    std::vector<uint8_t> &out_pem) const {
    if (!item.certificate) {
        if (!settings.m_verify_evidence_signature) {
            out_pem.clear();
            return Error::Ok;
        }
        LOG_ERROR("SPDM transcript evidence has no companion cert chain");
        return Error::BadArgument;
    }
    if (item.certificate->media_type != kCmwMediaPemCertChain) {
        if (!settings.m_verify_evidence_signature) {
            out_pem.clear();
            return Error::Ok;
        }
        LOG_ERROR("SPDM transcript companion cert media type unexpected: "
                  << item.certificate->media_type);
        return Error::BadArgument;
    }
    out_pem = item.certificate->value;
    return Error::Ok;
}

Error SpdmEvidenceHandler::verify_and_extract_ects(
    const CmwEvidenceItem &item, X509CertChain &validated_chain,
    const EvidenceHandlerSettings &settings, EvidenceVerification &out_verification) const {
    out_verification = EvidenceVerification{};
    const std::vector<uint8_t> &transcript = item.evidence.value;
    const std::size_t spdm_request_len =
        SpdmMeasurementRequestMessage11::get_request_length();
    if (transcript.size() <= kSpdmSignatureLength + spdm_request_len) {
        LOG_ERROR("SPDM transcript too short");
        return Error::EvidenceMalformed;
    }
    out_verification.signature_checked = true;

    std::vector<uint8_t> signed_data(
        transcript.begin(),
        transcript.end() -
            static_cast<std::ptrdiff_t>(kSpdmSignatureLength));
    std::vector<uint8_t> signature(
        transcript.end() -
            static_cast<std::ptrdiff_t>(kSpdmSignatureLength),
        transcript.end());
    // TODO(v2): hash + signature length are hardcoded for SHA-384 /
    // ECDSA P-384, today's NVIDIA standard. When a part diverges, derive
    // these from chain properties / GpuArchitectureData.
    Error sig_err = validated_chain.verify_signature_pkcs11(
        signed_data, signature, EVP_sha384());
    if (sig_err != Error::Ok) {
        LOG_ERROR("SPDM signature verification failed");
        if (settings.m_verify_evidence_signature) {
            return Error::Ok;
        }
    } else {
        out_verification.signature_valid = true;
    }

    // Freshness: the nonce signed into the request must equal the item nonce.
    SpdmMeasurementRequestMessage11 request;
    std::vector<uint8_t> request_bytes(
        transcript.begin(),
        transcript.begin() + static_cast<std::ptrdiff_t>(spdm_request_len));
    Error req_err = SpdmMeasurementRequestMessage11::create(request_bytes,
                                                            request);
    if (req_err != Error::Ok) {
        LOG_ERROR("SPDM request parse failed");
        return req_err;
    }
    const auto &transcript_nonce = request.get_nonce();
    out_verification.eat_nonce.assign(transcript_nonce.begin(), transcript_nonce.end());
    // Freshness is only checked when the RP supplied a per-item nonce.
    if (!item.nonce.empty()) {
        if (item.nonce.size() != transcript_nonce.size() ||
            !std::equal(transcript_nonce.begin(), transcript_nonce.end(),
                        item.nonce.begin())) {
            LOG_ERROR("SPDM transcript nonce does not match the evidence item "
                      "nonce");
            return Error::Ok;
        }
        out_verification.nonce_matches = true;
    }

    SpdmMeasurementResponseMessage11 response;
    std::vector<uint8_t> response_bytes(
        transcript.begin() +
            static_cast<std::ptrdiff_t>(spdm_request_len),
        transcript.end());
    // The CoRIM verifier only needs measurement records, never SPDM opaque data, so skip
    // decoding it here rather than fail on an OpaqueData format this path doesn't use.
    Error resp_err = SpdmMeasurementResponseMessage11::create(
        response_bytes, kSpdmSignatureLength, response, /*parse_opaque_data=*/false);
    if (resp_err != Error::Ok) {
        LOG_ERROR("SPDM response parse failed");
        return resp_err;
    }
    out_verification.parsed = true;

    // A missing tagged-spdm-toc is legitimate (e.g. raw Blackwell transcripts).
    const SpdmMeasurementRecordParser &records =
        response.get_parsed_measurement_records();
    const auto &blocks = records.get_all_measurement_blocks();
    const int32_t hash_alg_id = derive_measurement_hash_alg_id(records);

    out_verification.measurement_records =
        std::make_shared<const SpdmMeasurementRecordParser>(records);
    out_verification.measurement_hash_algorithm_id = hash_alg_id;

    DmtfMeasurementBlock device_identifier_block;
    if (records.get_dmtf_measurement_block(kDeviceIdentifierBlockIndex,
                                            device_identifier_block) ==
        Error::Ok) {
        out_verification.device_identifier_measurement =
            device_identifier_block.get_measurement_value();
    }

    const auto manifest_it =
        blocks.find(kSpdmMeasurementManifestBlockIndex);
    if (manifest_it != blocks.end()) {
        const std::vector<uint8_t> &value =
            manifest_it->second->get_measurement_value();
        std::vector<uint8_t> head(
            value.begin(),
            value.begin() + static_cast<std::ptrdiff_t>(std::min(
                                value.size(), kMeasurementLogPreviewBytes)));
        LOG_DEBUG("SPDM measurement manifest idx="
                  << static_cast<int>(kSpdmMeasurementManifestBlockIndex)
                  << " dmtf_type="
                  << to_hex_string(
                         manifest_it->second->get_measurement_value_type())
                  << " size=" << value.size()
                  << " head=" << to_hex_string(head));
        const bool has_toc_tag =
            value.size() >= sizeof(kSpdmTocCborTagBytes) &&
            value[0] == kSpdmTocCborTagBytes[0] &&
            value[1] == kSpdmTocCborTagBytes[1] &&
            value[2] == kSpdmTocCborTagBytes[2];
        if (has_toc_tag) {
            SpdmToc toc;
            Error toc_err = parse_spdm_toc(value, toc);
            if (toc_err != Error::Ok) {
                LOG_ERROR("CoEV SpdmToc parse failed");
                return toc_err;
            }
            if (!out_verification.evidence_profile &&
                toc.getProfile() != nullptr) {
                out_verification.evidence_profile =
                    std::make_unique<ProfileValue>(*toc.getProfile());
            }
            std::vector<Ect> toc_ects;
            std::vector<CorimLocatorMap> toc_locators;
            Error map_err = spdm_toc_to_ects(toc, records, hash_alg_id,
                                             toc_ects, toc_locators);
            if (map_err != Error::Ok) {
                LOG_ERROR("CoEV TOC -> ECT mapping failed");
                return map_err;
            }
            for (auto &ect : toc_ects) {
                out_verification.ects.push_back(std::move(ect));
            }
            for (const auto &locator : toc_locators) {
                for (const std::string &uri : locator.getUris()) {
                    out_verification.rim_locator_urls.push_back(uri);
                }
            }
        } else {
            LOG_DEBUG("SPDM measurement manifest at index 0xFD has no "
                      "recognized format; skipping");
        }
    }

    if (out_verification.ects.empty() && !settings.m_backup_coev.empty()) {
        const auto &bcoev = settings.m_backup_coev;
        const bool is_toc = bcoev.size() >= sizeof(kSpdmTocCborTagBytes)
            && bcoev[0] == kSpdmTocCborTagBytes[0]
            && bcoev[1] == kSpdmTocCborTagBytes[1]
            && bcoev[2] == kSpdmTocCborTagBytes[2];
        if (is_toc) {
            SpdmToc backup_toc;
            Error toc_err = parse_spdm_toc(bcoev, backup_toc);
            if (toc_err != Error::Ok) {
                LOG_ERROR("backup CoEV (#6.570 SpdmToc) parse failed");
                return toc_err;
            }
            if (!out_verification.evidence_profile &&
                backup_toc.getProfile() != nullptr) {
                out_verification.evidence_profile =
                    std::make_unique<ProfileValue>(*backup_toc.getProfile());
            }
            std::vector<Ect> toc_ects;
            std::vector<CorimLocatorMap> toc_locators;
            Error map_err = spdm_toc_to_ects(backup_toc, records, hash_alg_id,
                                             toc_ects, toc_locators);
            if (map_err != Error::Ok) {
                LOG_ERROR("backup CoEV (#6.570 SpdmToc) -> ECT mapping failed");
                return map_err;
            }
            for (auto &ect : toc_ects) {
                out_verification.ects.push_back(std::move(ect));
            }
            for (const auto &locator : toc_locators) {
                for (const std::string &uri : locator.getUris()) {
                    out_verification.rim_locator_urls.push_back(uri);
                }
            }
        } else {
            ConciseEvidence backup_ce;
            Error ce_err = parse_concise_evidence(bcoev, backup_ce);
            if (ce_err != Error::Ok) {
                LOG_ERROR("backup CoEV (#6.571 ConciseEvidence) parse failed");
                return ce_err;
            }
            if (!out_verification.evidence_profile &&
                backup_ce.getProfile() != nullptr) {
                out_verification.evidence_profile =
                    std::make_unique<ProfileValue>(*backup_ce.getProfile());
            }
            Error coev_err = concise_evidence_to_ects(backup_ce, records,
                                                      hash_alg_id, out_verification.ects);
            if (coev_err != Error::Ok) {
                LOG_ERROR("backup CoEV (#6.571 ConciseEvidence) -> ECT mapping failed");
                return coev_err;
            }
        }
        out_verification.used_backup_coev = true;
        LOG_INFO("backup CoEV injected: " << out_verification.ects.size() << " ECT(s)");
    }

    return Error::Ok;
}

constexpr const char *kEatMediaTypes[] = {kCmwMediaEatCwt};

// RFC 9711 EAT in CWT form. The device-identity chain is the COSE_Sign1
// x5chain header. With m_verify_evidence_signature false, a bare claims-set
// (no COSE_Sign1 or chain) can be parsed for diagnostics.
class EatEvidenceHandler : public IEvidenceHandler {
  public:
    bool accepts_media_type(const std::string &media_type) const override {
        return std::any_of(
            std::begin(kEatMediaTypes), std::end(kEatMediaTypes),
            [&](const char *known) { return media_type == known; });
    }

    Error extract_cert_chain(const CmwEvidenceItem &item,
                             const EvidenceHandlerSettings &settings,
                             std::vector<uint8_t> &out_pem) const override;

    Error verify_and_extract_ects(const CmwEvidenceItem &item,
                                  X509CertChain &validated_chain,
                                  const EvidenceHandlerSettings &settings,
                                  EvidenceVerification &out_verification) const override;
};

Error EatEvidenceHandler::extract_cert_chain(
    const CmwEvidenceItem &item, const EvidenceHandlerSettings &settings,
    std::vector<uint8_t> &out_pem) const {
    std::vector<uint8_t> cose_sign1_tagged;
    CoseSign1Components components;
    std::string pem;
    Error err = peel_eat_cwt_envelope(item.evidence.value, cose_sign1_tagged);
    if (err == Error::Ok) {
        err = decode_cose_sign1(cose_sign1_tagged, components);
    }
    if (err == Error::Ok) {
        err = validate_cose_sign1_x5chain(components);
    }
    if (err == Error::Ok) {
        err = x5chain_to_pem(components.x5chain, pem);
    }
    if (err == Error::Ok) {
        out_pem.assign(pem.begin(), pem.end());
        return Error::Ok;
    }
    if (!settings.m_verify_evidence_signature) {
        LOG_INFO("EAT chain extraction failed (" << to_string(err)
                 << "); continuing without a chain because verification is "
                    "disabled");
        out_pem.clear();
        return Error::Ok;
    }
    LOG_ERROR("EAT cert chain extraction failed: " << to_string(err));
    return err;
}

Error EatEvidenceHandler::verify_and_extract_ects(
    const CmwEvidenceItem &item, X509CertChain &validated_chain,
    const EvidenceHandlerSettings &settings, EvidenceVerification &out_verification) const {
    out_verification = EvidenceVerification{};
    Eat eat;

    std::vector<uint8_t> cose_sign1_tagged;
    Error peel_err =
        peel_eat_cwt_envelope(item.evidence.value, cose_sign1_tagged);
    if (peel_err != Error::Ok) {
        LOG_ERROR("EAT tag-envelope peel failed");
        return peel_err;
    }

    CoseSign1Components components;
    Error decode_err = decode_cose_sign1(cose_sign1_tagged, components);
    if (decode_err == Error::Ok) {
        out_verification.signature_checked = true;
        Error sig_err = verify_cose_sign1_signature(components, validated_chain);
        if (sig_err != Error::Ok) {
            LOG_ERROR("EAT COSE_Sign1 signature verification failed");
            if (settings.m_verify_evidence_signature) {
                return Error::Ok;
            }
        } else {
            out_verification.signature_valid = true;
        }
        Error claims_err = parse_eat_claims(components.payload, eat);
        if (claims_err != Error::Ok) {
            LOG_ERROR("EAT claims parse failed");
            return claims_err;
        }
    } else {
        if (settings.m_verify_evidence_signature) {
            LOG_ERROR("EAT COSE_Sign1 decode failed");
            return decode_err;
        }
        Error claims_err = parse_eat_claims(item.evidence.value, eat);
        if (claims_err != Error::Ok) {
            LOG_ERROR("EAT claims parse failed");
            return claims_err;
        }
    }

    out_verification.parsed = true;
    LOG_TRACE("EAT: " << nlohmann::json(eat).dump(
                              -1, ' ', false,
                              nlohmann::json::error_handler_t::replace));

    // Freshness: the nonce in the claims-set must equal the item nonce.
    out_verification.eat_nonce = eat.getNonce();
    if (!item.nonce.empty()) {
        const auto &nonce = eat.getNonce();
        if (nonce.size() != item.nonce.size() ||
            !std::equal(nonce.begin(), nonce.end(), item.nonce.begin())) {
            LOG_ERROR("EAT nonce does not match the evidence item nonce");
            return Error::Ok;
        }
        out_verification.nonce_matches = true;
    }

    std::vector<CorimLocatorMap> locator_maps;
    Error map_err = eat_to_ects(eat, out_verification.ects, locator_maps);
    if (map_err != Error::Ok) {
        LOG_ERROR("EAT -> ECT mapping failed");
        return map_err;
    }
    for (const auto &locator : locator_maps) {
        for (const std::string &uri : locator.getUris()) {
            out_verification.rim_locator_urls.push_back(uri);
        }
    }

    return Error::Ok;
}

} // namespace

const IEvidenceHandler *find_evidence_handler(const std::string &media_type) {
    // Add new evidence types here (stateless singletons).
    static const SpdmEvidenceHandler spdm_handler;
    static const EatEvidenceHandler eat_handler;
    static const IEvidenceHandler *const kHandlers[] = {&spdm_handler,
                                                         &eat_handler};
    for (const IEvidenceHandler *handler : kHandlers) {
        if (handler->accepts_media_type(media_type)) {
            return handler;
        }
    }
    return nullptr;
}

bool is_evidence_media_type_supported(const std::string &media_type) {
    return find_evidence_handler(media_type) != nullptr;
}

} // namespace nvattestation
