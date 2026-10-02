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

#include <algorithm>
#include <regex>

#include "nv_attestation/gpu/blackwell_fsp.h"
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"

namespace nvattestation {

static constexpr const char *kVbiosRimBaseUrl =
    "https://rim.attestation.nvidia.com/v1/rim/";

// ASCII "APSKU"; the 2 bytes immediately after it in the device identifier
// measurement (block 52) are the little-endian apSKU keyword.
static constexpr uint8_t kApskuTagBytes[5] = {0x41, 0x50, 0x53, 0x4B, 0x55};

static bool is_valid_blackwell_hw_model(const std::string &hw_model) {
    static const std::regex kBlackwellHwModel(R"(^GB\d{3}$)");
    return std::regex_match(hw_model, kBlackwellHwModel);
}

static Error extract_apsku_keyword(
    const std::vector<uint8_t> &device_identifier_measurement,
    std::string &out_apsku_hex,
    std::string &out_reason) {
    auto tag = std::search(device_identifier_measurement.begin(),
                           device_identifier_measurement.end(),
                           std::begin(kApskuTagBytes), std::end(kApskuTagBytes));
    if (tag == device_identifier_measurement.end()) {
        out_reason = "APSKU tag not found in device identifier measurement";
        LOG_ERROR("cannot build RIM locator, " << out_reason);
        return Error::EvidenceMalformed;
    }
    auto apsku_bytes = tag + sizeof(kApskuTagBytes);
    if (std::distance(apsku_bytes, device_identifier_measurement.end()) < 2) {
        out_reason = "device identifier measurement truncated after APSKU tag";
        LOG_ERROR("cannot build RIM locator, " << out_reason);
        return Error::EvidenceMalformed;
    }
    uint8_t low = *apsku_bytes;
    uint8_t high = *(apsku_bytes + 1);
    out_apsku_hex = to_hex_string(std::vector<uint8_t>{high, low}, /*uppercase=*/true);
    return Error::Ok;
}

Error validate_firmware_version_hint(const std::string &fw) {
    static const std::regex kFwVersionFormat(
        R"(^[0-9A-Fa-f]{2}(\.[0-9A-Fa-f]{2}){4}$)");
    if (!std::regex_match(fw, kFwVersionFormat)) {
        LOG_ERROR("firmware-version hint does not match expected format "
                  "(got length " << fw.size() << ")");
        return Error::EvidenceMalformed;
    }
    return Error::Ok;
}

bool is_blackwell_fsp_responder(const X509CertChain &validated_chain,
                                 const std::string &hw_model) {
    if (!is_valid_blackwell_hw_model(hw_model)) {
        return false;
    }
    std::string cn;
    if (validated_chain.get_subject_cn(0, cn) != Error::Ok) {
        return false;
    }
    return cn.find("FSP") != std::string::npos;
}

Error build_vbios_rim_locator(const std::string &hw_model,
                               const std::vector<uint8_t> &device_identifier_measurement,
                               const std::string &fw_version,
                               std::string &out_locator,
                               std::string &out_reason) {
    out_locator.clear();
    out_reason.clear();
    if (!is_valid_blackwell_hw_model(hw_model)) {
        out_reason = "hardware model has unexpected format: '" + hw_model + "'";
        LOG_ERROR("cannot build RIM locator, " << out_reason);
        return Error::EvidenceMalformed;
    }
    if (device_identifier_measurement.empty()) {
        out_reason = "device identifier measurement empty";
        LOG_ERROR("cannot build RIM locator, " << out_reason);
        return Error::EvidenceMalformed;
    }
    std::string apsku_hex;
    Error apsku_err = extract_apsku_keyword(
        device_identifier_measurement, apsku_hex, out_reason);
    if (apsku_err != Error::Ok) {
        return apsku_err;
    }
    Error fw_err = validate_firmware_version_hint(fw_version);
    if (fw_err != Error::Ok) {
        out_reason = "firmware-version hint does not match expected format";
        return fw_err;
    }
    // The RIM id has no separators between the firmware-version bytes.
    std::string fw_version_no_dots = fw_version;
    fw_version_no_dots.erase(
        std::remove(fw_version_no_dots.begin(), fw_version_no_dots.end(), '.'),
        fw_version_no_dots.end());
    out_locator = std::string(kVbiosRimBaseUrl) + "NV_GPU_VBIOS_" + hw_model +
                  "_" + apsku_hex + "_" + fw_version_no_dots;
    return Error::Ok;
}

}  // namespace nvattestation
