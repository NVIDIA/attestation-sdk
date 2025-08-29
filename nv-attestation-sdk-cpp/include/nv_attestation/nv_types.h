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

#include <libxml/parser.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlsec.h>
#include <openssl/x509.h>
#include <openssl/stack.h>
#include <openssl/ocsp.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <libxml/xmlschemas.h>
#include <curl/curl.h>
#ifdef ENABLE_NSCQ
#include "nv_attestation/switch/nscq_attestation.h"
#endif // ENABLE_NSCQ

namespace nvattestation {

//ref: https://quuxplusone.github.io/blog/2020/01/24/openssl-part-1/
//ref:https://stackoverflow.com/questions/37610494/passing-const-shared-ptrt-versus-just-shared-ptrt-as-parameter#comment62704490_37610494
template<class T> struct DeleterOf;


template<> struct DeleterOf<xmlDoc> {
    void operator()(xmlDoc* ptr) const {
        xmlFreeDoc(ptr);
    }
};

template<> struct DeleterOf<xmlSecDSigCtx> {
    void operator()(xmlSecDSigCtx* ptr) const {
        xmlSecDSigCtxDestroy(ptr);
    }
};

template<> struct DeleterOf<xmlSecKeysMngr> {
    void operator()(xmlSecKeysMngr* ptr) const {
        xmlSecKeysMngrDestroy(ptr);
    }
};
template<> struct DeleterOf<xmlXPathContext> {
    void operator()(xmlXPathContext* ptr) const {
        xmlXPathFreeContext(ptr);
    }
};

template<> struct DeleterOf<xmlXPathObject> { void operator()(xmlXPathObject* ptr) const { xmlXPathFreeObject(ptr);}};
template<> struct DeleterOf<xmlChar> { void operator()(xmlChar* ptr) const { xmlFree(ptr);}};
template<> struct DeleterOf<X509> { void operator()(X509* ptr) const { X509_free(ptr);}};
template<> struct DeleterOf<BIO> { void operator()(BIO* ptr) const { BIO_free(ptr);}};
template<> struct DeleterOf<X509_STORE> { void operator()(X509_STORE* ptr) const { X509_STORE_free(ptr);}};
template<> struct DeleterOf<X509_STORE_CTX> { void operator()(X509_STORE_CTX* ptr) const { X509_STORE_CTX_free(ptr);}};
template<> struct DeleterOf<STACK_OF(X509)> { void operator()(STACK_OF(X509)* ptr) const { sk_X509_free(ptr);}};
template<> struct DeleterOf<OCSP_REQUEST> { void operator()(OCSP_REQUEST* ptr) const { OCSP_REQUEST_free(ptr);}};
template<> struct DeleterOf<OCSP_CERTID> { void operator()(OCSP_CERTID* ptr) const { OCSP_CERTID_free(ptr);}};
template<> struct DeleterOf<OCSP_RESPONSE> { void operator()(OCSP_RESPONSE* ptr) const { OCSP_RESPONSE_free(ptr);}};
template<> struct DeleterOf<OCSP_BASICRESP> { void operator()(OCSP_BASICRESP* ptr) const { OCSP_BASICRESP_free(ptr);}};
template<> struct DeleterOf<STACK_OF(CONF_VALUE)> {void operator()(STACK_OF(CONF_VALUE)* ptr) const { {sk_CONF_VALUE_pop_free(ptr, X509V3_conf_free);}}};
template<> struct DeleterOf<EVP_PKEY> { void operator()(EVP_PKEY* ptr) const { EVP_PKEY_free(ptr);}};
template<> struct DeleterOf<EVP_PKEY_CTX> { void operator()(EVP_PKEY_CTX* ptr) const { EVP_PKEY_CTX_free(ptr);}};
template<> struct DeleterOf<EVP_MD_CTX> { void operator()(EVP_MD_CTX* ptr) const { EVP_MD_CTX_free(ptr);}};
template<> struct DeleterOf<BIGNUM> { void operator()(BIGNUM* ptr) const { BN_free(ptr);}};
template<> struct DeleterOf<ECDSA_SIG> { void operator()(ECDSA_SIG* ptr) const { ECDSA_SIG_free(ptr);}};
template<> struct DeleterOf<ASN1_OCTET_STRING> { void operator()(ASN1_OCTET_STRING* ptr) const { ASN1_OCTET_STRING_free(ptr);}};
template<> struct DeleterOf<ASN1_TYPE> { void operator()(ASN1_TYPE* ptr) const { ASN1_TYPE_free(ptr);}};
template<> struct DeleterOf<X509_EXTENSION> { void operator()(X509_EXTENSION* ptr) const { X509_EXTENSION_free(ptr);}};
template<> struct DeleterOf<ASN1_OBJECT> { void operator()(ASN1_OBJECT* ptr) const { ASN1_OBJECT_free(ptr);}};
template<> struct DeleterOf<ASN1_SEQUENCE_ANY> { void operator()(ASN1_SEQUENCE_ANY* ptr) const { sk_ASN1_TYPE_pop_free(ptr, ASN1_TYPE_free);}};
template<> struct DeleterOf<xmlSchema> { void operator()(xmlSchema* ptr) const { xmlSchemaFree(ptr);}};
template<> struct DeleterOf<xmlSchemaParserCtxt> { void operator()(xmlSchemaParserCtxt* ptr) const { xmlSchemaFreeParserCtxt(ptr);}};
template<> struct DeleterOf<xmlSchemaValidCtxt> { void operator()(xmlSchemaValidCtxt* ptr) const { xmlSchemaFreeValidCtxt(ptr);}};
template<> struct DeleterOf<curl_slist> { void operator()(curl_slist* ptr) const { curl_slist_free_all(ptr);}};
template<> struct DeleterOf<CURL> { void operator()(CURL* ptr) const { curl_easy_cleanup(ptr);}};

#ifdef ENABLE_NSCQ
template<> struct DeleterOf<nscq_session_st> {void operator()(nscq_session_st* ptr) const {if (ptr) {nscq_session_destroy(ptr);}}};
#endif // ENABLE_NSCQ

template<class T>
using nv_unique_ptr = std::unique_ptr<T, DeleterOf<T>>;

template<class T>
using nv_shared_ptr = std::shared_ptr<T>;

} // namespace nvattestation