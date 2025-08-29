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

#include <memory>
#include "nvat.h"

namespace nvattest {

    template<class T> struct DeleterOf;

    template<> struct DeleterOf<nvat_attestation_ctx_t> {
        void operator()(nvat_attestation_ctx_t* ptr) const {
            if (ptr) {
                nvat_attestation_ctx_free(ptr);
            }
        }
    };

    template<> struct DeleterOf<nvat_relying_party_policy_t> {
        void operator()(nvat_relying_party_policy_t* ptr) const {
            if (ptr) {
                nvat_relying_party_policy_free(ptr);
            }
        }
    };

    template<> struct DeleterOf<nvat_sdk_opts_t> {
        void operator()(nvat_sdk_opts_t* ptr) const {
            if (ptr) {
                nvat_sdk_opts_free(ptr);
            }
        }
    };

    template<> struct DeleterOf<nvat_claims_collection_t> {
        void operator()(nvat_claims_collection_t* ptr) const {
            if (ptr) {
                nvat_claims_collection_free(ptr);
            }
        }
    };

    template<> struct DeleterOf<nvat_rim_store_t> {
        void operator()(nvat_rim_store_t* ptr) const {
            if (ptr) {
                nvat_rim_store_free(ptr);
            }
        }
    };

    template<> struct DeleterOf<nvat_ocsp_client_t> {
        void operator()(nvat_ocsp_client_t* ptr) const {
            if (ptr) {
                nvat_ocsp_client_free(ptr);
            }
        }
    };

    template<class T> using nv_unique_ptr = std::unique_ptr<T, DeleterOf<T>>;
}