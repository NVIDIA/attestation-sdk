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

#include <string>
#include <cstring>
#include <vector>
#include <memory>
#include <mutex>
#include <dlfcn.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "nv_attestation/log.h"
#include "nv_attestation/error.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/gpu/corelib_client.h"
#include "nv_attestation/gpu/evidence.h"
#include "nv_attestation/spdm/utils.h"

namespace nvattestation {

// Error codes (from corelib.h)
using corelib_error_t = int;
constexpr corelib_error_t CORELIB_SUCCESS = 0;
constexpr corelib_error_t CORELIB_ERROR_FAILED = 1;
constexpr corelib_error_t CORELIB_ERROR_INVALID_ARG = 2;
constexpr corelib_error_t CORELIB_ERROR_BUFFER_TOO_SMALL = 3;
constexpr corelib_error_t CORELIB_ERROR_NOT_FOUND = 4;
constexpr corelib_error_t CORELIB_ERROR_NOT_SUPPORTED = 5;
constexpr corelib_error_t CORELIB_ERROR_OUT_OF_MEMORY = 6;

// Opaque handles (forward declarations)
struct corelib_device_manager_t;
struct corelib_device_t;
struct corelib_spdm_client_t;

struct corelib_spdm_digest_t {
    uint8_t index = 0;
    uint8_t data[SPDM_CERT_DIGEST_SIZE] = {};
};

// === Function pointer types ===

// Device Manager functions
using corelib_device_manager_create_t = corelib_error_t (*)(corelib_device_manager_t** manager);
using corelib_device_manager_destroy_t = void (*)(corelib_device_manager_t* manager);
using corelib_device_manager_discover_inband_gpus_t = corelib_error_t (*)(
    corelib_device_manager_t* manager,
    corelib_device_t** devices,
    size_t* count);

// Device functions
using corelib_device_destroy_t = void (*)(corelib_device_t* device);
using corelib_device_get_description_t = corelib_error_t (*)(
    corelib_device_t* device,
    char* buffer,
    size_t* len);

// SPDM Client functions
using corelib_spdm_client_create_t = corelib_error_t (*)(
    corelib_device_t* device,
    corelib_spdm_client_t** client);
using corelib_spdm_client_destroy_t = void (*)(corelib_spdm_client_t* client);
using corelib_spdm_reset_session_t = corelib_error_t (*)(corelib_spdm_client_t* client);
using corelib_spdm_get_digests_t = corelib_error_t (*)(
    corelib_spdm_client_t* client,
    corelib_spdm_digest_t* digests,
    size_t* count);
using corelib_spdm_get_certificate_t = corelib_error_t (*)(
    corelib_spdm_client_t* client,
    uint8_t slot,
    uint8_t* buffer,
    size_t* len);
using corelib_spdm_get_measurement_transcript_t = corelib_error_t (*)(
    corelib_spdm_client_t* client,
    uint8_t index,
    const uint8_t* nonce,
    size_t nonce_len,
    uint8_t* buffer,
    size_t* len);

// === Function pointers struct ===
struct CorelibFunctions {
    void* library_handle = nullptr;

    corelib_device_manager_create_t device_manager_create = nullptr;
    corelib_device_manager_destroy_t device_manager_destroy = nullptr;
    corelib_device_manager_discover_inband_gpus_t device_manager_discover_inband_gpus = nullptr;

    corelib_device_destroy_t device_destroy = nullptr;
    corelib_device_get_description_t device_get_description = nullptr;

    corelib_spdm_client_create_t spdm_client_create = nullptr;
    corelib_spdm_client_destroy_t spdm_client_destroy = nullptr;
    corelib_spdm_reset_session_t spdm_reset_session = nullptr;
    corelib_spdm_get_digests_t spdm_get_digests = nullptr;
    corelib_spdm_get_certificate_t spdm_get_certificate = nullptr;
    corelib_spdm_get_measurement_transcript_t spdm_get_measurement_transcript = nullptr;

    CorelibFunctions() = default;
};

// Global instance
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static CorelibFunctions g_corelib_funcs;

// Custom deleters for corelib types
template<> struct DeleterOf<corelib_device_manager_t> {
    void operator()(corelib_device_manager_t* ptr) const {
        if (ptr != nullptr && g_corelib_funcs.device_manager_destroy != nullptr) {
            g_corelib_funcs.device_manager_destroy(ptr);
        }
    }
};

template<> struct DeleterOf<corelib_device_t> {
    void operator()(corelib_device_t* ptr) const {
        if (ptr != nullptr && g_corelib_funcs.device_destroy != nullptr) {
            g_corelib_funcs.device_destroy(ptr);
        }
    }
};

template<> struct DeleterOf<corelib_spdm_client_t> {
    void operator()(corelib_spdm_client_t* ptr) const {
        if (ptr != nullptr && g_corelib_funcs.spdm_client_destroy != nullptr) {
            g_corelib_funcs.spdm_client_destroy(ptr);
        }
    }
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
bool g_corelib_initialized = false;

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static std::once_flag g_corelib_initialized_flag;

static const char* get_error_string(corelib_error_t error) {
    switch (error) {
        case CORELIB_SUCCESS: return "Success";
        case CORELIB_ERROR_FAILED: return "Failed";
        case CORELIB_ERROR_INVALID_ARG: return "Invalid argument";
        case CORELIB_ERROR_BUFFER_TOO_SMALL: return "Buffer too small";
        case CORELIB_ERROR_NOT_FOUND: return "Not found";
        case CORELIB_ERROR_NOT_SUPPORTED: return "Not supported";
        case CORELIB_ERROR_OUT_OF_MEMORY: return "Out of memory";
        default: return "Unknown error";
    }
}

static bool load_all_symbols(void* handle) {
    bool success = true;

    success = load_symbol(handle, "corelib_device_manager_create", g_corelib_funcs.device_manager_create) && success;
    success = load_symbol(handle, "corelib_device_manager_destroy", g_corelib_funcs.device_manager_destroy) && success;
    success = load_symbol(handle, "corelib_device_manager_discover_inband_gpus", g_corelib_funcs.device_manager_discover_inband_gpus) && success;

    success = load_symbol(handle, "corelib_device_destroy", g_corelib_funcs.device_destroy) && success;
    success = load_symbol(handle, "corelib_device_get_description", g_corelib_funcs.device_get_description) && success;

    success = load_symbol(handle, "corelib_spdm_client_create", g_corelib_funcs.spdm_client_create) && success;
    success = load_symbol(handle, "corelib_spdm_client_destroy", g_corelib_funcs.spdm_client_destroy) && success;
    success = load_symbol(handle, "corelib_spdm_reset_session", g_corelib_funcs.spdm_reset_session) && success;
    success = load_symbol(handle, "corelib_spdm_get_digests", g_corelib_funcs.spdm_get_digests) && success;
    success = load_symbol(handle, "corelib_spdm_get_certificate", g_corelib_funcs.spdm_get_certificate) && success;
    success = load_symbol(handle, "corelib_spdm_get_measurement_transcript", g_corelib_funcs.spdm_get_measurement_transcript) && success;

    return success;
}

Error init_corelib()
{
    // If already initialized, return Ok
    if (g_corelib_initialized) {
        return Error::Ok;
    }

    Error init_result = Error::CorelibInitFailed;

    std::call_once(g_corelib_initialized_flag, [&init_result]() {
        LOG_DEBUG("Initializing Corelib with dlopen");

        const std::string corelib_so = "libcorelib.so.1";
        g_corelib_funcs.library_handle = dlopen(corelib_so.c_str(), RTLD_LAZY | RTLD_LOCAL);
        if (g_corelib_funcs.library_handle == nullptr) {
            const char* error = dlerror();
            LOG_TRACE("Failed to load Corelib library: " << corelib_so << ": " << (error ? error : "unknown error"));
            init_result = Error::CorelibInitFailed;
            return;
        }
        LOG_TRACE("Successfully loaded Corelib library: " << corelib_so);

        if (!load_all_symbols(g_corelib_funcs.library_handle)) {
            LOG_ERROR("Failed to load required Corelib symbols");
            dlclose(g_corelib_funcs.library_handle);
            g_corelib_funcs.library_handle = nullptr;
            init_result = Error::CorelibInitFailed;
            return;
        }
        LOG_TRACE("Successfully loaded all Corelib symbols");

        LOG_DEBUG("Successfully initialized Corelib");
        g_corelib_initialized = true;
        init_result = Error::Ok;
    });

    return init_result;
}

void shutdown_corelib()
{
    if (!g_corelib_initialized || g_corelib_funcs.library_handle == nullptr) {
        return;
    }

    LOG_DEBUG("Shutting down Corelib");

    if (dlclose(g_corelib_funcs.library_handle) != 0) {
        const char* error = dlerror();
        LOG_ERROR("Failed to close Corelib library: " << (error != nullptr ? error : "unknown error"));
    }
    g_corelib_funcs = CorelibFunctions();
    g_corelib_initialized = false;
    LOG_DEBUG("Successfully shut down Corelib");
}

/**
 * @brief Converts a DER-encoded certificate chain to PEM format
 *
 * Corelib returns certificate chains as raw DER bytes.
 * This function parses each certificate and converts it to PEM format with
 * headers, footers, and base64 encoding.
 *
 * @param der_chain The DER-encoded certificate chain bytes
 * @param out_pem_chain The output PEM-formatted certificate chain string
 * @return Error::Ok on success, Error::InternalError on failure
 */
static Error convert_der_cert_chain_to_pem(
    const std::vector<uint8_t>& der_chain,
    std::string& out_pem_chain)
{
    if (der_chain.empty()) {
        LOG_ERROR("DER certificate chain is empty");
        return Error::InternalError;
    }

    out_pem_chain.clear();

    const unsigned char* data_ptr = der_chain.data();
    const unsigned char* data_end = data_ptr + der_chain.size();

    std::vector<std::string> pem_certs;

    // Parse each certificate in the DER chain
    while (data_ptr < data_end) {
        size_t remaining = data_end - data_ptr;
        const unsigned char* original_ptr = data_ptr;

        // Parse DER certificate
        X509* raw_cert = d2i_X509(nullptr, &data_ptr, static_cast<long>(remaining));
        if (raw_cert == nullptr) {
            LOG_ERROR("Failed to parse DER certificate at offset "
                     << (original_ptr - der_chain.data())
                     << ": " << get_openssl_error());
            return Error::InternalError;
        }
        nv_unique_ptr<X509> cert(raw_cert);

        // Convert X509 to PEM format
        nv_unique_ptr<BIO> bio(BIO_new(BIO_s_mem()));
        if (!bio) {
            LOG_ERROR("Failed to create BIO: " << get_openssl_error());
            return Error::InternalError;
        }

        if (PEM_write_bio_X509(bio.get(), cert.get()) != 1) {
            LOG_ERROR("Failed to write certificate to PEM format: " << get_openssl_error());
            return Error::InternalError;
        }

        // Extract PEM string from BIO
        char* pem_data = nullptr;
        long pem_len = BIO_get_mem_data(bio.get(), &pem_data);
        if (pem_data == nullptr || pem_len <= 0) {
            LOG_ERROR("Failed to get PEM data from BIO");
            return Error::InternalError;
        }

        pem_certs.push_back(std::string(pem_data, pem_len));
    }

    if (pem_certs.empty()) {
        LOG_ERROR("No certificates found in DER chain");
        return Error::InternalError;
    }

    // Reverse the order: last cert becomes first, first cert becomes last
    std::reverse(pem_certs.begin(), pem_certs.end());

    // Build the final PEM chain
    for (const auto& pem_cert : pem_certs) {
        out_pem_chain.append(pem_cert);
    }

    LOG_DEBUG("Successfully converted " << pem_certs.size() << " DER certificates to PEM format (reversed order)");
    return Error::Ok;
}

Error collect_evidence_corelib(
    const std::vector<uint8_t>& nonce_input,
    GpuArchitecture architecture,
    std::vector<std::shared_ptr<GpuEvidence>>& out_evidence)
{
    // Validate nonce (must be 32 bytes for SPDM)
    if (nonce_input.size() != SPDM_NONCE_SIZE) {
        LOG_ERROR("Corelib requires nonce to be exactly " << SPDM_NONCE_SIZE << " bytes, got " << nonce_input.size());
        return Error::BadArgument;
    }

    // Create device manager
    corelib_device_manager_t* raw_manager = nullptr;
    corelib_error_t result = g_corelib_funcs.device_manager_create(&raw_manager);
    if (result != CORELIB_SUCCESS) {
        LOG_ERROR("Failed to create corelib device manager: " << get_error_string(result));
        return Error::CorelibError;
    }
    nv_unique_ptr<corelib_device_manager_t> manager(raw_manager);

    // Discover GPUs - first get count
    size_t device_count = 0;
    result = g_corelib_funcs.device_manager_discover_inband_gpus(manager.get(), nullptr, &device_count);
    if (result != CORELIB_SUCCESS) {
        LOG_ERROR("Failed to get GPU device count: " << get_error_string(result));
        return Error::CorelibError;
    }

    if (device_count == 0) {
        LOG_ERROR("No inband GPU devices found");
        return Error::CorelibError;
    }

    LOG_DEBUG("Found " << device_count << " inband GPU device(s)");

    // Allocate device array
    std::vector<corelib_device_t*> raw_devices(device_count);
    result = g_corelib_funcs.device_manager_discover_inband_gpus(manager.get(), raw_devices.data(), &device_count);
    if (result != CORELIB_SUCCESS) {
        LOG_ERROR("Failed to discover GPU devices: " << get_error_string(result));
        return Error::CorelibError;
    }

    // Wrap devices in unique_ptrs for automatic cleanup
    std::vector<nv_unique_ptr<corelib_device_t>> devices;
    devices.reserve(device_count);
    for (auto* raw_device : raw_devices) {
        devices.emplace_back(raw_device);
    }

    // Collect evidence from each GPU
    for (size_t i = 0; i < device_count; ++i) {
        corelib_device_t* device = devices[i].get();

        // Get device description (optional, for logging)
        constexpr size_t desc_buffer_size = 256;
        char desc_buffer[desc_buffer_size];
        size_t desc_len = sizeof(desc_buffer);
        std::string device_desc = "Unknown";
        if (g_corelib_funcs.device_get_description(device, desc_buffer, &desc_len) == CORELIB_SUCCESS) {
            device_desc = std::string(desc_buffer, desc_len);
        }
        LOG_DEBUG("Collecting evidence from device " << i << ": " << device_desc);

        // Create SPDM client
        corelib_spdm_client_t* raw_client = nullptr;
        result = g_corelib_funcs.spdm_client_create(device, &raw_client);
        if (result != CORELIB_SUCCESS) {
            LOG_ERROR("Failed to create SPDM client for device " << i << ": " << get_error_string(result));
            return Error::CorelibError;
        }
        nv_unique_ptr<corelib_spdm_client_t> client(raw_client);

        // Get certificate digests to find cert slot
        size_t digest_count = 0;
        result = g_corelib_funcs.spdm_get_digests(client.get(), nullptr, &digest_count);
        if (result != CORELIB_SUCCESS || digest_count == 0) {
            LOG_ERROR("Failed to get certificate digests for device " << i << ": " << get_error_string(result));
            return Error::CorelibError;
        }

        std::vector<corelib_spdm_digest_t> digests(digest_count);
        result = g_corelib_funcs.spdm_get_digests(client.get(), digests.data(), &digest_count);
        if (result != CORELIB_SUCCESS) {
            LOG_ERROR("Failed to retrieve certificate digests for device " << i << ": " << get_error_string(result));
            return Error::CorelibError;
        }

        uint8_t cert_slot = digests[0].index;
        LOG_DEBUG("Using certificate slot " << static_cast<int>(cert_slot));

        // Reset SPDM session before getting certificate
        result = g_corelib_funcs.spdm_reset_session(client.get());
        if (result != CORELIB_SUCCESS) {
            LOG_ERROR("Failed to reset SPDM session before getting certificate for device " << i << ": " << get_error_string(result));
            return Error::CorelibError;
        }

        // Get certificate chain - first get size
        size_t cert_size = 0;
        result = g_corelib_funcs.spdm_get_certificate(client.get(), cert_slot, nullptr, &cert_size);
        if (result != CORELIB_SUCCESS || cert_size == 0) {
            LOG_ERROR("Failed to get certificate size for device " << i << ": " << get_error_string(result));
            return Error::CorelibError;
        }

        std::vector<uint8_t> cert_data(cert_size);
        result = g_corelib_funcs.spdm_get_certificate(client.get(), cert_slot, cert_data.data(), &cert_size);
        if (result != CORELIB_SUCCESS) {
            LOG_ERROR("Failed to retrieve certificate for device " << i << ": " << get_error_string(result));
            return Error::CorelibError;
        }
        cert_data.resize(cert_size);

        // Strip the cert digest to get the actual cert chain
        if (cert_size <= SPDM_CERT_DIGEST_SIZE) {
            LOG_ERROR("Certificate response too small (expected > " << SPDM_CERT_DIGEST_SIZE << " bytes, got " << cert_size << ") for device " << i);
            return Error::CorelibError;
        }
        std::vector<uint8_t> cert_chain(cert_data.begin() + SPDM_CERT_DIGEST_SIZE, cert_data.end());
        LOG_DEBUG("Stripped " << SPDM_CERT_DIGEST_SIZE << " byte digest header, cert chain size: " << cert_chain.size() << " bytes");

        // Reset SPDM session before getting measurements
        result = g_corelib_funcs.spdm_reset_session(client.get());
        if (result != CORELIB_SUCCESS) {
            LOG_ERROR("Failed to reset SPDM session before getting measurements for device " << i << ": " << get_error_string(result));
            return Error::CorelibError;
        }

        // Get measurement transcript with nonce (index 0xff = all measurements)
        constexpr uint8_t ALL_MEASUREMENTS_INDEX = 0xff;
        size_t transcript_size = 0;
        result = g_corelib_funcs.spdm_get_measurement_transcript(
            client.get(),
            ALL_MEASUREMENTS_INDEX,
            nonce_input.data(),
            nonce_input.size(),
            nullptr,
            &transcript_size);
        if (result != CORELIB_SUCCESS || transcript_size == 0) {
            LOG_ERROR("Failed to get measurement transcript size for device " << i << ": " << get_error_string(result));
            return Error::CorelibError;
        }

        std::vector<uint8_t> transcript_data(transcript_size);
        result = g_corelib_funcs.spdm_get_measurement_transcript(
            client.get(),
            ALL_MEASUREMENTS_INDEX,
            nonce_input.data(),
            nonce_input.size(),
            transcript_data.data(),
            &transcript_size);
        if (result != CORELIB_SUCCESS) {
            LOG_ERROR("Failed to retrieve measurement transcript for device " << i << ": " << get_error_string(result));
            return Error::CorelibError;
        }
        transcript_data.resize(transcript_size);

        // Convert DER certificate chain to PEM format
        std::string pem_cert_chain;
        Error convert_error = convert_der_cert_chain_to_pem(cert_chain, pem_cert_chain);
        if (convert_error != Error::Ok) {
            LOG_ERROR("Failed to convert DER certificate chain to PEM for device " << i);
            return Error::CorelibError;
        }

        // Create GpuEvidence object
        auto evidence = std::make_shared<GpuEvidence>(
            architecture,                                      // gpu_architecture
            0,                                                 // board_id (not available)
            device_desc,                                       // uuid (use device description)
            transcript_data,                                   // attestation_report
            pem_cert_chain,                                    // attestation_cert_chain
            nonce_input                                        // nonce
        );

        out_evidence.push_back(evidence);
        LOG_DEBUG("Successfully collected evidence from device " << i);
    }

    LOG_DEBUG("Successfully collected evidence from " << out_evidence.size() << " device(s)");
    return Error::Ok;
}

} // namespace nvattestation
