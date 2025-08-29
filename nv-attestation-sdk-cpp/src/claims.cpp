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

#include <cstddef>
#include <memory>
#include <string>

#include "nv_attestation/claims.h"
#include "nv_attestation/error.h"
#include "nv_attestation/utils.h"

namespace nvattestation {
    bool operator==(const SerializableCertChainClaims& lhs, const SerializableCertChainClaims& rhs) {
        return lhs.m_cert_expiration_date == rhs.m_cert_expiration_date &&
               lhs.m_cert_status == rhs.m_cert_status &&
               lhs.m_cert_ocsp_status == rhs.m_cert_ocsp_status &&
               compare_shared_ptr(lhs.m_cert_revocation_reason, rhs.m_cert_revocation_reason);
    }

    Error ClaimsCollection::serialize_json(std::string& out_json) const {
        try {
            nlohmann::json json_array = nlohmann::json::array();
            for (const auto& claim : m_claims) {
                json_array.push_back(claim->to_json_object());
            }
            out_json = json_array.dump();
            return Error::Ok;
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to serialize to JSON: " << e.what());
            return Error::InternalError;
        }    
    }

    void ClaimsCollection::extend(ClaimsCollection other) {
        m_claims.insert(m_claims.end(), other.m_claims.begin(), other.m_claims.end());
    }

    void ClaimsCollection::append(const std::shared_ptr<Claims>& claims) {
        m_claims.push_back(claims);
    }

    bool ClaimsCollection::empty() const {
        return m_claims.empty();
    }

    size_t ClaimsCollection::size() const {
        return m_claims.size();
    }

    std::shared_ptr<Claims> ClaimsCollection::operator[](size_t index) {
        return m_claims[index];
    }
} // namespace nvattestation
