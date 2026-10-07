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

#include "nv_attestation/cmw.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"

namespace nvattestation {

namespace {

constexpr const char *kFieldCmwc = "__cmwc_t";
constexpr const char *kFieldNonce = "nonce";
constexpr const char *kFieldAppraisalSettings = "appraisal-settings";
constexpr const char *kFieldEvidence = "evidence";
constexpr const char *kFieldCertificate = "certificate";
constexpr const char *kFieldHints = "hints";

constexpr const char *kCertificateMediaTypes[] = {
    kCmwMediaPemCertChain,
    // TODO(v2): application/pem-certificate-chain (RFC 8555) or a DER variant.
};

bool is_supported_certificate_media_type(const std::string &media_type) {
    return std::any_of(std::begin(kCertificateMediaTypes),
                       std::end(kCertificateMediaTypes),
                       [&](const char *known) { return media_type == known; });
}

// [media-type, base64url-data]. The 3-element form (with an ind bitmap) is
// rejected; this profile doesn't use it.
Error read_record(const nlohmann::json &node, const std::string &field_name,
                  CmwRecord &out) {
    if (!node.is_array() || node.size() != 2) {
        LOG_ERROR("CMW field '" << field_name
                                << "' must be a 2-element array");
        return Error::EvidenceMalformed;
    }
    if (!node[0].is_string() || !node[1].is_string()) {
        LOG_ERROR("CMW field '" << field_name
                                << "' must contain string entries");
        return Error::EvidenceMalformed;
    }
    out.media_type = node[0].get<std::string>();
    if (decode_base64url(node[1].get<std::string>(), out.value) != Error::Ok) {
        LOG_ERROR("CMW field '" << field_name << "' has invalid base64url");
        return Error::EvidenceMalformed;
    }
    return Error::Ok;
}

Error record_to_json(const CmwRecord &record, nlohmann::json &out) {
    std::string encoded;
    Error err = encode_base64url(record.value, encoded);
    if (err != Error::Ok) {
        return err;
    }
    out = nlohmann::json::array();
    out.push_back(record.media_type);
    out.push_back(std::move(encoded));
    return Error::Ok;
}

Error read_nonce(const nlohmann::json &node, const std::string &field_name,
                 std::vector<uint8_t> &out_nonce) {
    CmwRecord record;
    Error err = read_record(node, field_name, record);
    if (err != Error::Ok) {
        return err;
    }
    if (record.media_type != kCmwMediaOctetStream) {
        LOG_ERROR("CMW " << field_name
                         << " media type must be application/octet-stream");
        return Error::EvidenceMalformed;
    }
    if (record.value.size() < MIN_VALID_NONCE_LEN) {
        LOG_ERROR("CMW " << field_name << " is too short: "
                         << record.value.size() << " bytes");
        return Error::EvidenceMalformed;
    }
    out_nonce = std::move(record.value);
    return Error::Ok;
}

Error parse_evidence_item(const nlohmann::json &node,
                          const std::string &label, CmwEvidenceItem &out) {
    if (!node.is_object()) {
        LOG_ERROR("CMW evidence item '" << label
                                        << "' must be a JSON object");
        return Error::EvidenceMalformed;
    }
    auto cmwc = node.find(kFieldCmwc);
    if (cmwc == node.end() || !cmwc->is_string() ||
        cmwc->get<std::string>() != kCmwEvidenceItemProfile) {
        LOG_ERROR("CMW evidence item '" << label << "' has wrong "
                                        << kFieldCmwc);
        return Error::EvidenceMalformed;
    }

    auto evidence = node.find(kFieldEvidence);
    if (evidence == node.end()) {
        LOG_ERROR("CMW evidence item '" << label << "' missing evidence");
        return Error::EvidenceMalformed;
    }
    Error err = read_record(*evidence, "evidence", out.evidence);
    if (err != Error::Ok) {
        return err;
    }
    // Evidence media type is validated at appraisal (per-item), not here.

    // Optional; read_nonce still length-validates a present nonce.
    auto nonce = node.find(kFieldNonce);
    if (nonce != node.end()) {
        err = read_nonce(*nonce, "evidence-item nonce", out.nonce);
        if (err != Error::Ok) {
            return err;
        }
    }

    // Optional: some evidence types embed the chain in the payload instead.
    auto certificate = node.find(kFieldCertificate);
    if (certificate != node.end()) {
        auto record = std::unique_ptr<CmwRecord>(new CmwRecord());
        err = read_record(*certificate, "certificate", *record);
        if (err != Error::Ok) {
            return err;
        }
        if (!is_supported_certificate_media_type(record->media_type)) {
            LOG_ERROR("CMW evidence item '"
                      << label << "' has unsupported certificate media type: "
                      << record->media_type);
            return Error::EvidenceMalformed;
        }
        out.certificate = std::move(record);
    }

    // Optional; the hint values themselves are an untrusted key-value bundle
    // interpreted (and validated) by the caller, not here.
    auto hints = node.find(kFieldHints);
    if (hints != node.end()) {
        auto record = std::unique_ptr<CmwRecord>(new CmwRecord());
        err = read_record(*hints, "hints", *record);
        if (err != Error::Ok) {
            return err;
        }
        if (record->media_type != kCmwMediaJson) {
            LOG_ERROR("CMW evidence item '"
                      << label << "' has unsupported hints media type: "
                      << record->media_type);
            return Error::EvidenceMalformed;
        }
        out.hints = std::move(record);
    }

    return Error::Ok;
}

Error parse_json(const uint8_t *data, std::size_t length,
                 CmwCollection &out_collection) {
    nlohmann::json root = nlohmann::json::parse(data, data + length, nullptr,
                                                /*allow_exceptions=*/false);
    if (root.is_discarded()) {
        LOG_ERROR("CMW JSON parse failed");
        return Error::EvidenceMalformed;
    }

    if (!root.is_object()) {
        LOG_ERROR("CMW root must be a JSON object");
        return Error::EvidenceMalformed;
    }

    auto cmwc = root.find(kFieldCmwc);
    if (cmwc == root.end() || !cmwc->is_string() ||
        cmwc->get<std::string>() != kCmwInputProfile) {
        LOG_ERROR("CMW root has wrong " << kFieldCmwc);
        return Error::EvidenceMalformed;
    }

    auto nonce_it = root.find(kFieldNonce);
    if (nonce_it != root.end()) {
        std::vector<uint8_t> nonce;
        Error err = read_nonce(*nonce_it, "nonce", nonce);
        if (err != Error::Ok) {
            return err;
        }
        out_collection.set_nonce(std::move(nonce));
    }

    auto settings_it = root.find(kFieldAppraisalSettings);
    if (settings_it != root.end()) {
        CmwRecord settings;
        Error err = read_record(*settings_it, kFieldAppraisalSettings, settings);
        if (err != Error::Ok) {
            return err;
        }
        if (settings.media_type != kCmwMediaJson) {
            LOG_ERROR("CMW appraisal-settings media type must be "
                      << kCmwMediaJson);
            return Error::EvidenceMalformed;
        }
        out_collection.set_appraisal_settings(std::move(settings.value));
    }

    bool any_evidence_item = false;
    for (auto it = root.begin(); it != root.end(); ++it) {
        const std::string &label = it.key();
        if (label == kFieldCmwc || label == kFieldNonce ||
            label == kFieldAppraisalSettings) {
            continue;
        }
        CmwEvidenceItem item;
        Error item_err = parse_evidence_item(it.value(), label, item);
        if (item_err != Error::Ok) {
            return item_err;
        }
        out_collection.add_evidence_item(label, std::move(item));
        any_evidence_item = true;
    }
    if (!any_evidence_item) {
        LOG_ERROR("CMW collection has no evidence items");
        return Error::EvidenceMalformed;
    }
    return Error::Ok;
}

Error serialize_json(const CmwCollection &cmw,
                     std::vector<uint8_t> &out_serialized) {
    nlohmann::json root = nlohmann::json::object();
    root[kFieldCmwc] = kCmwInputProfile;

    Error err = Error::Ok;
    if (!cmw.nonce().empty()) {
        CmwRecord nonce_record(kCmwMediaOctetStream, cmw.nonce());
        err = record_to_json(nonce_record, root[kFieldNonce]);
        if (err != Error::Ok) {
            return err;
        }
    }
    if (!cmw.appraisal_settings().empty()) {
        CmwRecord settings_record(kCmwMediaJson, cmw.appraisal_settings());
        err = record_to_json(settings_record, root[kFieldAppraisalSettings]);
        if (err != Error::Ok) {
            return err;
        }
    }

    for (const auto &labelled : cmw.evidence_items()) {
        nlohmann::json item = nlohmann::json::object();
        item[kFieldCmwc] = kCmwEvidenceItemProfile;
        err = record_to_json(labelled.second.evidence, item[kFieldEvidence]);
        if (err != Error::Ok) {
            return err;
        }
        if (!labelled.second.nonce.empty()) {
            CmwRecord item_nonce(kCmwMediaOctetStream, labelled.second.nonce);
            err = record_to_json(item_nonce, item[kFieldNonce]);
            if (err != Error::Ok) {
                return err;
            }
        }
        if (labelled.second.certificate) {
            err = record_to_json(*labelled.second.certificate,
                                  item[kFieldCertificate]);
            if (err != Error::Ok) {
                return err;
            }
        }
        if (labelled.second.hints) {
            err = record_to_json(*labelled.second.hints, item[kFieldHints]);
            if (err != Error::Ok) {
                return err;
            }
        }
        root[labelled.first] = std::move(item);
    }
    std::string dumped = root.dump();
    out_serialized.assign(dumped.begin(), dumped.end());
    return Error::Ok;
}

} // namespace

Error CmwCollection::serialize(CmwFormat format,
                               std::vector<uint8_t> &out_serialized) const {
    switch (format) {
    case CmwFormat::kJson:
        return serialize_json(*this, out_serialized);
    case CmwFormat::kCbor:
        // TODO(v2): CBOR encoding via zcbor.
        return Error::FeatureNotEnabled;
    }
    return Error::BadArgument;
}

Error CmwCollection::parse(const uint8_t *data, std::size_t length,
                           CmwFormat format, CmwCollection &out_collection) {
    if (data == nullptr) {
        LOG_ERROR("CMW parse called with null data");
        return Error::BadArgument;
    }
    // Commit to the caller's object only on full success.
    CmwCollection parsed;
    Error err = Error::BadArgument;
    switch (format) {
    case CmwFormat::kJson:
        err = parse_json(data, length, parsed);
        break;
    case CmwFormat::kCbor:
        // TODO(v2): CBOR decoding via zcbor.
        return Error::FeatureNotEnabled;
    }
    if (err != Error::Ok) {
        return err;
    }
    out_collection = std::move(parsed);
    return Error::Ok;
}

} // namespace nvattestation
