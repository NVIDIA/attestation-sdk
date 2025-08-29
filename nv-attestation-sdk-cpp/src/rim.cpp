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

//todo: clean up the includes everwhere
// use <> for standard library headers and dependencies
// use "" for headers belonging to this sdk
#include <cstring>
#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>
#include <set>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlschemas.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/crypto.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmltree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <curl/curl.h>

#include "nv_attestation/rim.h"
#include "nv_attestation/error.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"
#include <nlohmann/json.hpp>
#include "nv_attestation/nv_http.h"
#include "internal/certs.h"

namespace nvattestation {

    
// ref: https://github.com/nlohmann/json?tab=readme-ov-file#simplify-your-life-with-macros
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(RimResponse, id, rim, request_id, sha256);

// RimDocumentImpl functions

Error RimDocument::create_from_rim_data(const std::string &rim_data, RimDocument& out_rim_document) {
    // TODO(p1): this is only TCG/SWID. We need to:
    // 1. have an understanding of the format
    // 2. fail for unparseable formats (e.g. CORIM, GENERIC)
    // 3. ensure the contract of RimDocument is compatible with CoRIM OR split out these methods to clearly separate 
    //    TCG from CORIM
    auto doc = nv_unique_ptr<xmlDoc>(xmlReadDoc(reinterpret_cast<const xmlChar *>(rim_data.c_str()), NULL, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET));
    if (!doc) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to parse RIM data when creating RimDocumentImpl");
        return Error::InternalError;
    }
    out_rim_document.m_rim_data = rim_data;
    out_rim_document.m_doc = std::move(doc);

    return Error::Ok;
}

Error RimDocument::create_from_file (const std::string &rim_path, RimDocument& out_rim_document) {
    std::ifstream file(rim_path);
    std::string rim_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return create_from_rim_data(rim_data, out_rim_document);
}

RimDocument::RimDocument(nv_unique_ptr<xmlDoc> doc, const std::string& rim_data) {
    m_doc = std::move(doc);
    m_rim_data = rim_data;
}

Error RimDocument::get_cert_chain(X509CertChain& out_cert_chain) const {

    auto x_path_ctx = nv_unique_ptr<xmlXPathContext>(xmlXPathNewContext(m_doc.get()));
    if (!x_path_ctx) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to create XPath context");
        return Error::InternalError;
    }

    if(xmlXPathRegisterNs(x_path_ctx.get(), BAD_CAST "ds", BAD_CAST RimDocument::XML_DSIG_NAMESPACE_URI) != 0) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to register namespace");
        return Error::InternalError;
    }

    auto x_path_obj = nv_unique_ptr<xmlXPathObject>(xmlXPathEvalExpression(BAD_CAST "//ds:X509Certificate", x_path_ctx.get()));
    if (!x_path_obj) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to get X509Certificate XPath object");
        return Error::InternalError;
    }

    xmlNodeSetPtr nodes = x_path_obj->nodesetval;
    if (nodes == nullptr) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to get nodesetval from XPath object");
        return Error::InternalError;
    }

    if (nodes->nodeNr == 0) {
        LOG_PUSH_ERROR(Error::InternalError, "No X509Certificate found in RIM data");
        return Error::InternalError;
    }

    // Create the root CA certificate from the predefined string
    nv_unique_ptr<X509> root_ca_cert = x509_from_cert_string(RIM_ROOT_CERT);
    if (root_ca_cert == nullptr) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to create X509 from RIM_ROOT_CERT string in get_cert_chain.");
        return Error::InternalError;
    }

    // todo: figure out a way to handle different types of RIMs
    // Create the X509CertChain using the static factory method
    Error error = X509CertChain::create(CertificateChainType::GPU_DRIVER_RIM, RIM_ROOT_CERT, out_cert_chain);
    if (error != Error::Ok) {
        // Error is logged within X509CertChain::create or x509_from_cert_string
        LOG_PUSH_ERROR(Error::InternalError, "Failed to create X509CertChain in get_cert_chain.");
        return error;
    }

    for(int i = 0; i < nodes->nodeNr; i++) {
        xmlNodePtr cur = nodes->nodeTab[i];
        auto content = nv_unique_ptr<xmlChar>(xmlNodeGetContent(cur));
        if(content) {
            //todo: can instead base64 decode this and use that to directly create the X509 object
            std::string full_cert = "-----BEGIN CERTIFICATE-----\n" 
                                    + std::string(reinterpret_cast<const char*>(content.get())) +
                                    "-----END CERTIFICATE-----";
            error = out_cert_chain.push_back(full_cert);
            if(error != Error::Ok) {
                return error;
            }
        }
    }
    return Error::Ok;
}

Error RimDocument::get_version(std::string& out_version) const {
    auto x_path_ctx = nv_unique_ptr<xmlXPathContext>(xmlXPathNewContext(m_doc.get()));
    if (!x_path_ctx) {
        LOG_ERROR("Failed to create XPath context");
        return Error::InternalError;
    }

    // Register the ns0 namespace for SoftwareIdentity schema
    if(xmlXPathRegisterNs(x_path_ctx.get(), BAD_CAST "ns0", BAD_CAST RimDocument::ISO_19770_SCHEMA_NAMESPACE_URI) != 0) {
        LOG_ERROR("Failed to register ns0 namespace");
        return Error::InternalError;
    }

    // Find the Meta element with colloquialVersion attribute
    auto x_path_obj = nv_unique_ptr<xmlXPathObject>(xmlXPathEvalExpression(BAD_CAST "//ns0:Meta[@colloquialVersion]", x_path_ctx.get()));
    if (!x_path_obj) {
        LOG_ERROR("Failed to get Meta XPath object");
        return Error::RimInvalidSchema;
    }

    xmlNodeSetPtr nodes = x_path_obj->nodesetval;
    if (nodes == nullptr) {
        LOG_ERROR("Failed to get nodesetval from XPath object");
        return Error::RimInvalidSchema;
    }

    if (nodes->nodeNr == 0) {
        LOG_ERROR("No Meta element with colloquialVersion attribute found in RIM data");
        return Error::RimInvalidSchema;
    }

    // Extract the colloquialVersion attribute from the first Meta node
    xmlNodePtr meta_node = nodes->nodeTab[0];
    auto version_attr = nv_unique_ptr<xmlChar>(xmlGetProp(meta_node, BAD_CAST "colloquialVersion"));
    if (!version_attr) {
        LOG_ERROR("Failed to extract colloquialVersion attribute from Meta element");
        return Error::RimInvalidSchema;
    }

    out_version = std::string(reinterpret_cast<const char*>(version_attr.get()));
    return Error::Ok;
}

Error RimDocument::verify_signature() const {
    nv_unique_ptr<xmlSecKeysMngr> keys_mngr(xmlSecKeysMngrCreate());
    if (keys_mngr == nullptr) {
        LOG_ERROR("Failed to create keys manager");
        return Error::InternalError;
    }

    if (xmlSecCryptoAppDefaultKeysMngrInit(keys_mngr.get()) < 0) {
        LOG_ERROR("Failed to initialize keys manager");
        return Error::InternalError;
    }

    xmlNodePtr root = xmlDocGetRootElement(m_doc.get());
    if (root == nullptr) {
        LOG_ERROR("Failed to get root element from RIM file: ");
        return Error::InternalError;
    }

    xmlNodePtr node = xmlSecFindNode(root, xmlSecNodeSignature, xmlSecDSigNs);
    if (node == nullptr) {
        LOG_ERROR("Failed to find signature node in RIM file");
        return Error::RimInvalidSchema;
    }

    nv_unique_ptr<xmlSecDSigCtx> d_sig_ctx(xmlSecDSigCtxCreate(keys_mngr.get()));

    if (d_sig_ctx == nullptr) {
        LOG_ERROR("Failed to create DSIG context");
        return Error::InternalError;
    }

    // we verify cert chain in a different method, so set the appropriate flag here to disable that.
    d_sig_ctx->keyInfoReadCtx.flags |= XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS;

    if (xmlSecDSigCtxVerify(d_sig_ctx.get(), node) < 0) {
        LOG_ERROR("Failed to verify signature");
        return Error::InternalError;
    }

    if (d_sig_ctx->status != xmlSecDSigStatusSucceeded) {
        // RIM signature is not valid
        LOG_ERROR("RIM signature is not valid");
        return Error::RimInvalidSignature;
    }

    return Error::Ok;
}

Error RimDocument::generate_rim_claims(const EvidencePolicy& evidence_policy, IOcspHttpClient& ocsp_client, RimClaims& out_rim_claims) const {
    // Get certificate chain
    X509CertChain cert_chain;
    Error error = get_cert_chain(cert_chain);
    if (error != Error::Ok) {
        return error;
    }
    
    // Generate certificate chain claims
    error = cert_chain.generate_cert_chain_claims(evidence_policy.ocsp_options, ocsp_client, out_rim_claims.m_cert_chain_claims);
    if (error != Error::Ok) {
        return error;
    }
    
    // Verify signature
    if (evidence_policy.verify_rim_signature) {
        LOG_DEBUG("Verifying RIM signature");
        error = verify_signature();
        if (error != Error::Ok) {
            return error;
        }
        out_rim_claims.m_signature_verified = true;
    } else {
        LOG_WARN("RIM signature verification is disabled in evidence policy");
        out_rim_claims.m_signature_verified = false;
    }
    
    return Error::Ok;
}

Error RimDocument::get_measurements(Measurements& out_measurements) const {
    
    if (!m_doc) {
        LOG_ERROR("RIM document is null");
        return Error::InternalError;
    }

    // Create XPath context
    auto x_path_ctx = nv_unique_ptr<xmlXPathContext>(xmlXPathNewContext(m_doc.get()));
    if (!x_path_ctx) {
        LOG_ERROR("Failed to create XPath context for measurements");
        return Error::LibXml2Error;
    }

    // Register namespaces
    if (xmlXPathRegisterNs(x_path_ctx.get(), BAD_CAST "ns0", BAD_CAST RimDocument::ISO_19770_SCHEMA_NAMESPACE_URI) != 0) {
        LOG_ERROR("Failed to register ns0 namespace for measurements");
        return Error::LibXml2Error;
    }
    
    if (xmlXPathRegisterNs(x_path_ctx.get(), BAD_CAST "ns2", BAD_CAST RimDocument::XML_ENC_SHA384_NAMESPACE_URI) != 0) {
        LOG_ERROR("Failed to register ns2 namespace for measurements");
        return Error::LibXml2Error;
    }

    // Query for measurement elements
    auto x_path_obj = nv_unique_ptr<xmlXPathObject>(xmlXPathEvalExpression(BAD_CAST "//ns0:Resource[@type='Measurement']", x_path_ctx.get()));
    if (!x_path_obj) {
        LOG_ERROR("Failed to evaluate XPath expression for measurements");
        return Error::LibXml2Error;
    }

    xmlNodeSetPtr nodes = x_path_obj->nodesetval;
    if (nodes == nullptr) {
        LOG_ERROR("No measurement nodes found in RIM document");
        return Error::RimInvalidSchema;
    }

    // Process each measurement node
    for (int i = 0; i < nodes->nodeNr; i++) {
        xmlNodePtr node = nodes->nodeTab[i];
        
        // Parse attributes
        auto active_attr = nv_unique_ptr<xmlChar>(xmlGetProp(node, BAD_CAST "active"));
        auto index_attr = nv_unique_ptr<xmlChar>(xmlGetProp(node, BAD_CAST "index"));
        auto alternatives_attr = nv_unique_ptr<xmlChar>(xmlGetProp(node, BAD_CAST "alternatives"));
        auto name_attr = nv_unique_ptr<xmlChar>(xmlGetProp(node, BAD_CAST "name"));
        auto size_attr = nv_unique_ptr<xmlChar>(xmlGetProp(node, BAD_CAST "size"));

        if (!active_attr || !index_attr || !alternatives_attr || !name_attr || !size_attr) {
            LOG_ERROR("Missing required attributes in measurement node");
            LOG_DEBUG("RIM data: **************\n" << get_raw_rim_data()<<"\n**************");
            return Error::RimInvalidSchema;
        }

        // Parse attribute values
        bool active = (std::string(reinterpret_cast<const char*>(active_attr.get())) == "True");
        int index = std::stoi(reinterpret_cast<const char*>(index_attr.get()));
        int alternatives = std::stoi(reinterpret_cast<const char*>(alternatives_attr.get()));
        std::string name = reinterpret_cast<const char*>(name_attr.get());
        int size = std::stoi(reinterpret_cast<const char*>(size_attr.get()));

        // Filter to only include active measurements
        if (!active) {
            LOG_TRACE("Skipping inactive measurement at index " << index);
            continue;
        }

        // Extract hash values
        std::vector<std::vector<uint8_t>> hash_values;
        for (int alt = 0; alt < alternatives; alt++) {
            std::string local_name = "Hash" + std::to_string(alt);
            auto hash_attr = nv_unique_ptr<xmlChar>(xmlGetNsProp(node, BAD_CAST local_name.c_str(), BAD_CAST RimDocument::XML_ENC_SHA384_NAMESPACE_URI));
            
            if (!hash_attr) {
                LOG_ERROR("Missing hash attribute ns2:" << local_name << " for measurement at index " << index);
                LOG_DEBUG("RIM data: **************\n" << get_raw_rim_data()<<"\n**************");
                return Error::RimInvalidSchema;
            }

            std::string hex_string = reinterpret_cast<const char*>(hash_attr.get());
            
            // Convert hex string to binary
            std::vector<uint8_t> hash_value = hex_string_to_bytes(hex_string);

            hash_values.push_back(hash_value);
        }

        // Validate that we got the expected number of hash alternatives
        if (hash_values.size() != static_cast<size_t>(alternatives)) {
            LOG_ERROR("Expected " << alternatives << " hash alternatives but got " << hash_values.size() << " for measurement at index " << index);
            LOG_DEBUG("RIM data: **************\n" << get_raw_rim_data()<<"\n**************");
            return Error::RimInvalidSchema;
        }

        // Create and add the measurement to the container
        Measurement measurement(active, index, size, alternatives, hash_values, name);
        Error add_error = out_measurements.add_measurement(measurement);
        if (add_error != Error::Ok) {
            LOG_ERROR("Failed to add measurement at index " << index);
            return add_error;
        }
        
        LOG_TRACE("Extracted measurement at index " << index << " with " << alternatives << " alternatives, name: " << name);
    }

    LOG_DEBUG("Extracted " << out_measurements.size() << " total measurements");
    return Error::Ok;
}

Error RimDocument::get_manufacturer_id(std::string& out_manufacturer_id) const {
    // tested in rim_test.cpp
    auto x_path_ctx = nv_unique_ptr<xmlXPathContext>(xmlXPathNewContext(m_doc.get()));
    if (!x_path_ctx) {
        LOG_ERROR("Failed to create XPath context");
        return Error::InternalError;
    }

    // Register the ns0 namespace for SoftwareIdentity schema
    if(xmlXPathRegisterNs(x_path_ctx.get(), BAD_CAST "ns0", BAD_CAST RimDocument::ISO_19770_SCHEMA_NAMESPACE_URI) != 0) {
        LOG_ERROR("Failed to register ns0 namespace");
        return Error::InternalError;
    }

    // Register the ns1 namespace for TCG RIM schema
    if(xmlXPathRegisterNs(x_path_ctx.get(), BAD_CAST "ns1", BAD_CAST RimDocument::TCG_RIM_NAMESPACE_URI) != 0) {
        LOG_ERROR("Failed to register ns1 namespace");
        return Error::InternalError;
    }

    // Find the Meta element with ns1:FirmwareManufacturerId attribute
    auto x_path_obj = nv_unique_ptr<xmlXPathObject>(xmlXPathEvalExpression(BAD_CAST "//ns0:Meta[@ns1:FirmwareManufacturerId]", x_path_ctx.get()));
    if (!x_path_obj) {
        LOG_ERROR("Failed to get Meta XPath object");
        return Error::RimInvalidSchema;
    }

    xmlNodeSetPtr nodes = x_path_obj->nodesetval;
    if (nodes == nullptr) {
        LOG_ERROR("Failed to get nodesetval from XPath object");
        return Error::RimInvalidSchema;
    }

    if (nodes->nodeNr != 1) {
        LOG_ERROR("Expected exactly 1 Meta element with ns1:FirmwareManufacturerId attribute, found " << nodes->nodeNr);
        return Error::RimInvalidSchema;
    }

    // Extract the ns1:FirmwareManufacturerId attribute from the Meta node
    xmlNodePtr meta_node = nodes->nodeTab[0];
    auto manufacturer_id_attr = nv_unique_ptr<xmlChar>(xmlGetNsProp(meta_node, BAD_CAST "FirmwareManufacturerId", BAD_CAST RimDocument::TCG_RIM_NAMESPACE_URI));
    if (!manufacturer_id_attr) {
        LOG_ERROR("Failed to extract ns1:FirmwareManufacturerId attribute from Meta element");
        return Error::RimInvalidSchema;
    }

    out_manufacturer_id = std::string(reinterpret_cast<const char*>(manufacturer_id_attr.get()));
    return Error::Ok;
}

// RimClient functions
NvRemoteRimStoreImpl::NvRemoteRimStoreImpl(const std::string &server_host) {
    m_base_url = server_host;
}

Error NvRemoteRimStoreImpl::init_from_env(NvRemoteRimStoreImpl& out_rim_store, const char* base_url, HttpOptions http_options) {
    if (base_url == nullptr || *base_url == '\0') {
        out_rim_store.m_base_url = get_env_or_default("NVAT_RIM_SERVICE_BASE_URL", DEFAULT_BASE_URL);
    } else {
        out_rim_store.m_base_url = std::string(base_url);
    }
    Error error = NvHttpClient::create(out_rim_store.m_http_client, http_options);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to create NvHttpClient");
        return error;
    }
    return Error::Ok;
}

// Helper callback function to write received data into a std::string
static size_t curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    auto totalSize = size * nmemb;
    auto* str = static_cast<std::string*>(userp);
    str->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

Error NvRemoteRimStoreImpl::get_rim(const std::string &rim_id, RimDocument& out_rim_document) {
    
   std::string url = m_base_url + "/v1/rim/" + rim_id;

    NvRequest request(url, NvHttpMethod::HTTP_METHOD_GET);
    long http_code = 0;
    std::string response;
    Error error = m_http_client.do_request_as_string(request, http_code, response);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to get RIM from RIM server");
        return error;
    }

    if (http_code != NvHttpStatus::HTTP_STATUS_OK) {
        LOG_ERROR("Non-200 response from RIM server. http_code: " << http_code << " http_response: " << response);
        if (http_code == NvHttpStatus::HTTP_STATUS_NOT_FOUND) {
            return Error::RimNotFound;
        }
        if (http_code == NvHttpStatus::HTTP_STATUS_FORBIDDEN || http_code == NvHttpStatus::HTTP_STATUS_UNAUTHORIZED) {
            return Error::RimForbidden;
        }
        return Error::RimInternalError;
    }

    // Parse the response body as JSON
    LOG_TRACE("RIM response: " << response);
    RimResponse rim_response;
    error = deserialize_from_json<RimResponse>(response, rim_response);
    if (error != Error::Ok) {
        LOG_ERROR("Failed to deserialize RIM response");
        return error;
    }

    LOG_DEBUG("RIM response: " << rim_response.id << " " << rim_response.request_id << " " << rim_response.sha256 << " " << rim_response.rim_format);
    if (rim_id != rim_response.id) {
        LOG_ERROR("RIM ID from RIM server does not match requested ID. Expected: " << rim_id << " Actual: " << rim_response.id); 
        return Error::InternalError;
    }

    return extract_rim_document(rim_response.rim, out_rim_document);
}

Error NvRemoteRimStoreImpl::extract_rim_document(const std::string &rim_response_data, RimDocument& out_rim_document) {
    std::string decoded_rim_data;
    Error error = decode_base64(rim_response_data, decoded_rim_data);
    if (error != Error::Ok) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to decode RIM data");
        return Error::InternalError;
    }
    RimDocument rim_document;
    error = RimDocument::create_from_rim_data(decoded_rim_data, rim_document);
    if (error != Error::Ok) {
        LOG_PUSH_ERROR(Error::InternalError, "Failed to create RimDocument from RIM data");
        return Error::InternalError;
    }
    out_rim_document = std::move(rim_document);
    return Error::Ok;
}

// Measurements class implementations

Error Measurements::get_measurement_at_index(int index, Measurement& out_measurement) const {
    auto it = m_measurements.find(index);
    if (it == m_measurements.end()) {
        return Error::RimMeasurementNotFound;
    }
    out_measurement = it->second;
    return Error::Ok;
}

bool Measurements::has_measurement_at_index(int index) const {
    return m_measurements.find(index) != m_measurements.end();
}

std::vector<int> Measurements::get_all_indices() const {
    std::vector<int> indices;
    for (const auto& pair : m_measurements) {
        indices.push_back(pair.first);
    }
    return indices;
}

size_t Measurements::size() const {
    return m_measurements.size();
}

Error Measurements::add_measurement(const Measurement& measurement) {
    int index = measurement.get_index();
    if (m_measurements.find(index) != m_measurements.end()) {
        LOG_ERROR("Measurement already exists at index " << index);
        return Error::RimInvalidSchema;
    }
    m_measurements[index] = measurement;
    return Error::Ok;
}



}