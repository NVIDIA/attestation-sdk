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

#include <functional>
#include <vector>
#include <memory>

#include "spdlog/spdlog.h"
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <openssl/ssl.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>

#include "nv_attestation/error.h"
#include "nv_attestation/init.h"
#include "nv_attestation/log.h"
#include "nv_attestation/gpu/nvml_client.h"
#include "nv_attestation/switch/nscq_client.h"

namespace nvattestation {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static std::shared_ptr<SdkOptions> g_sdkOptions = nullptr;

Error handle_init_logger(const std::shared_ptr<SdkOptions>& options) {
    if (options->logger != nullptr) {
        set_logger(options->logger);
    } else {
        // create a default console log sink
        // TODO: configure based on env vars?
        set_logger(std::make_shared<SpdLogLogger>(LogLevel::DEBUG));
    }
    return Error::Ok;
}

Error handle_init_xmlsec() {
    xmlInitParser();
    LIBXML_TEST_VERSION

    // throw errors because init failing is not recoverable
    // if we instead return an error here, we will need to keep
    // track of what has already been initialized and what not, 
    // (because some init cannot be done multiple times)
    // which does not seem worth the effort.

    // todo: create a single exception class for all errors and throw that
    // this will make it easier to clients to catch any exception thrown by this library
    // in envs where exceptions are not enabled, this should call abort()
    // if this is an issue for automobile, this can be changed.
    if (xmlSecInit() < 0) {
        LOG_ERROR("Failed to initialize XML security library");
        return Error::XmlInitFailed;
    }

    if(xmlSecCheckVersion() != 1) {
        LOG_ERROR("xmlsec library ABI version mismatch with application ABI version");
        return Error::XmlInitFailed;
    }

    if(xmlSecCryptoAppInit(NULL) < 0) {
        LOG_ERROR("Failed to initialize openssl crypto library for xmlsec");
        return Error::XmlInitFailed;
    }

    if(xmlSecCryptoInit() < 0) {
        LOG_ERROR("xmlsec-crypto initialization failed");
        return Error::XmlInitFailed;
    }
    return Error::Ok;
}

void handle_shutdown_xmlsec(){
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    xmlCleanupParser();
}

void handle_shutdown_nvml() {
    if (!g_nvml_initialized) {
        return;
    }
    shutdown_nvml();
    g_nvml_initialized = false;
}

void handle_shutdown_nscq() {
    if (!g_nscq_initialized) {
        return;
    }
    shutdown_nscq();
    g_nscq_initialized = false;
}

void handle_shutdown_logger() {
    destroy_logger();
}

void handle_delete_sdk_options() {
    g_sdkOptions = nullptr;
}

Error init(const std::shared_ptr<SdkOptions>& sdk_options) {
    static Error initialized = [](const std::shared_ptr<SdkOptions>& options) {
        if (options == nullptr) {
            g_sdkOptions = std::make_shared<SdkOptions>();
        } else {
            g_sdkOptions = options;
        }
        Error err = handle_init_logger(g_sdkOptions);
        if (err != Error::Ok) {
            return err;
        }

        err = handle_init_xmlsec();
        if (err != Error::Ok) {
            return err;
        }

        return Error::Ok;
    }(sdk_options);
    return initialized;
}

void shutdown() {
    if (g_sdkOptions == nullptr) {
        return;
    }
    // TODO: threadsafe way to make sure only one shutdown is run
    handle_shutdown_xmlsec();
    handle_shutdown_nvml();
    handle_shutdown_nscq();
    handle_delete_sdk_options();
    handle_shutdown_logger();
}

}