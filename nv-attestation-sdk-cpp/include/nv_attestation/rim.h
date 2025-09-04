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

#include <string>
#include <vector>
#include <memory>
#include <map>
#include "error.h"
#include "nv_attestation/nv_http.h"
#include "nv_x509.h"
#include "nv_types.h"

namespace nvattestation {
struct RimResponse {
    std::string id;
    std::string rim;
    std::string request_id;
    std::string sha256;
    std::string rim_format;
};

/**
 * @brief Represents a measurement entry from RIM document
 * 
 * This class encapsulates measurement data including index, size, count,
 * hash values, and metadata. Used for comparing RIM measurements against
 * attestation report measurements.
 */
class Measurement { // TODO(p1): this works for DMTF, does it also work for CORIM?
private:
    bool m_active;
    int m_index;
    // represents size of measurement in hex string, not bytes because that is what is present in the RIM file
    int m_size;
    int m_count;
    
    std::vector<std::vector<uint8_t>> m_values;
    std::string m_name;

public:
    // Default constructor
    Measurement() : m_active(false), m_index(0), m_size(0), m_count(0) {}
    
    // Constructor with parameters
    Measurement(bool active, int index, int size, int count, 
                const std::vector<std::vector<uint8_t>>& values, 
                const std::string& name)
        : m_active(active), m_index(index), m_size(size), m_count(count), 
          m_values(values), m_name(name) {}
    
    // Getter methods
    bool get_active() const { return m_active; }
    int get_index() const { return m_index; }
    int get_size() const { return m_size; }
    int get_count() const { return m_count; }
    const std::vector<std::vector<uint8_t>>& get_values() const { return m_values; }
    const std::string& get_name() const { return m_name; }
    
    // Setter methods for construction and modification
    void set_active(bool active) { m_active = active; }
    void set_index(int index) { m_index = index; }
    void set_size(int size) { m_size = size; }
    void set_count(int count) { m_count = count; }
    void set_values(const std::vector<std::vector<uint8_t>>& values) { m_values = values; }
    void set_name(const std::string& name) { m_name = name; }
};

/**
 * @brief Container class for managing measurement collections
 * 
 * This class provides a container for Measurement objects with efficient
 * index-based access and merging capabilities. Used for managing measurements
 * from RIM documents and enabling conflict detection during merging operations.
 */
class Measurements {
private:
    std::map<int, Measurement> m_measurements;

public:
    // Default constructor
    Measurements() = default;
    
    /**
     * @brief Retrieve a measurement at the specified index
     * @param index The measurement index to retrieve
     * @param out_measurement Output parameter for the measurement
     * @return Error::Ok on success, Error::RimMeasurementNotFound if not found
     */
    Error get_measurement_at_index(int index, Measurement& out_measurement) const;
    
    /**
     * @brief Check if a measurement exists at the specified index
     * @param index The measurement index to check
     * @return true if measurement exists, false otherwise
     */
    bool has_measurement_at_index(int index) const;
    
    /**
     * @brief Get all measurement indices
     * @return Vector of all measurement indices
     */
    std::vector<int> get_all_indices() const;
    
    /**
     * @brief Get the number of measurements
     * @return Number of measurements in the container
     */
    size_t size() const;
    
    /**
     * @brief Add a measurement to the container
     * @param measurement The measurement to add
     * @return Error::Ok on success
     */
    Error add_measurement(const Measurement& measurement);
    

};

/**
 * @brief Represents RIM claims for attestation
 */
struct RimClaims {
    CertChainClaims m_cert_chain_claims;
    bool m_signature_verified;
    
    RimClaims() : m_signature_verified(false) {}
};

class RimDocument{
    public:
        // URI constants for XML namespaces
        static constexpr const char* XML_DSIG_NAMESPACE_URI = "http://www.w3.org/2000/09/xmldsig#";
        static constexpr const char* ISO_19770_SCHEMA_NAMESPACE_URI = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd";
        static constexpr const char* XML_ENC_SHA384_NAMESPACE_URI = "http://www.w3.org/2001/04/xmlenc#sha384";
        static constexpr const char* TCG_RIM_NAMESPACE_URI = "https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/";

        // 1 indexed vector of measurements
        Error get_measurements(Measurements& out_measurements) const;
        Error verify_signature() const;
        Error get_cert_chain(X509CertChain& out_cert_chain) const;
        Error get_version(std::string& out_version) const;
        Error generate_rim_claims(const EvidencePolicy& evidence_policy, IOcspHttpClient& ocsp_client, RimClaims& out_rim_claims) const;
        Error get_manufacturer_id(std::string& out_manufacturer_id) const;
        RimDocument(nv_unique_ptr<xmlDoc> doc, const std::string& rim_data);
        RimDocument() = default;
        static Error create_from_rim_data(const std::string &rim_data, RimDocument& out_rim_document); // TODO(p2): create_from_string
        static Error create_from_file(const std::string &rim_path, RimDocument& out_rim_document);
        const std::string& get_raw_rim_data() const { return m_rim_data; }
    private:
        nv_unique_ptr<xmlDoc> m_doc;
        std::string m_rim_data;
};

/**
 * @brief Store of RIM files, where each RIM is accessible by a unique ID
 */
class IRimStore {
    public: 
    virtual ~IRimStore() = default;
    virtual Error get_rim(const std::string &rim_id, RimDocument& out_rim_document) = 0;
};

/**
 * @brief RIM store that fetches RIMs from the [NVIDIA RIM service](https://docs.nvidia.com/attestation/api-docs-rim/latest/rim_api.html)
 *        or a service with a compatible HTTP interface.
 */
class NvRemoteRimStoreImpl : public IRimStore {
    public:
        static constexpr const char* DEFAULT_BASE_URL = "https://rim.attestation.nvidia.com";

        // todo(p2): support SAK
        NvRemoteRimStoreImpl(const std::string &server_host);
        NvRemoteRimStoreImpl() : NvRemoteRimStoreImpl(DEFAULT_BASE_URL) {}
        static Error init_from_env(NvRemoteRimStoreImpl& out_rim_store, const char* base_url, HttpOptions http_options);

        Error get_rim(const std::string &rim_id, RimDocument& out_rim_document) override;
    private: 
        static Error extract_rim_document(const std::string &rim_response_data, RimDocument& out_rim_document);
        std::string m_base_url;
        NvHttpClient m_http_client;
};

/**
 * @brief RIM store backed by the local filesystem.
 */
// TODO(p1): implement, taking care to use a reasonable filesystem layout and file format.
//       it may not be sufficient to store the raw RIM files because we normally have the rim_format 
//       to inform our parser. do we just store entire RIM service responses on disk?
class FilesystemRimStoreImpl : public IRimStore {
    public:
        FilesystemRimStoreImpl(const std::string &path); // TODO: is there a better data structure?
        Error get_rim(const std::string &rim_id, RimDocument& out_rim_document) override;
    private: 
        std::string path;
};

/**
 * @brief Enriches a wrapped IRimStore with in-memory caching behavior.
 */
// TODO(p0): implement and add additional settings for TTL
class InMemoryCachingRimStoreImpl : public IRimStore {
    public:
        InMemoryCachingRimStoreImpl (std::unique_ptr<IRimStore> inner_client);
        Error get_rim(const std::string &rim_id, RimDocument& out_rim_document) override;
    private: 
        std::unique_ptr<IRimStore> inner_client;
};

}
