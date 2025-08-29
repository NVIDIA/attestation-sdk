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

# pragma once

#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <string>
#include <sstream> // Include for std::ostringstream if needed elsewhere, or consider simplifying string creation

#include "nv_attestation/nv_types.h"

namespace nvattestation {

// Helper function to get Subject and Issuer of an X509 certificate as a string
inline std::string get_cert_subject_issuer_str(X509 *cert) {
    if (!cert) {
        return "Subject: <null>, Issuer: <null>";
    }

    nv_unique_ptr<BIO> bio_out(BIO_new(BIO_s_mem()));
    if (!bio_out) {
        return "Subject: <BIO allocation failed>, Issuer: <BIO allocation failed>";
    }

    std::string result = "Subject: ";
    if (!X509_NAME_print_ex(bio_out.get(), X509_get_subject_name(cert), 0, XN_FLAG_ONELINE)) {
        return "Subject: <error printing subject>";
    }
    BUF_MEM *bio_buf = nullptr;
    BIO_get_mem_ptr(bio_out.get(), &bio_buf);
    if (bio_buf && bio_buf->data && bio_buf->length > 0) {
        result.append(bio_buf->data, bio_buf->length);
    } else {
        result.append("<error reading subject>");
    }
    BIO_reset(bio_out.get()); // Reset BIO for next use

    result += ", Issuer: ";
    if (!X509_NAME_print_ex(bio_out.get(), X509_get_issuer_name(cert), 0, XN_FLAG_ONELINE)) {
        return "Issuer: <error printing issuer>";
    }
    BIO_get_mem_ptr(bio_out.get(), &bio_buf); // Re-get buffer pointer after write
    if (bio_buf && bio_buf->data && bio_buf->length > 0) {
        result.append(bio_buf->data, bio_buf->length);
    } else {
        result.append("<error reading issuer>");
    }

    return result;
}

} // namespace nvattestation

