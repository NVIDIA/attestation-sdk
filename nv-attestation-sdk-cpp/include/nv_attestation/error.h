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
#include <cstdint>
#include <ostream>
#include <vector>

#include "nvat.h"

namespace nvattestation {

// Define a mapping from C return codes to a fully type-safe
// C++ enum class.
#define ERROR_ENUM_LIST(MACRO) \
    MACRO(Ok, NVAT_RC_OK) \
    MACRO(Unknown, NVAT_RC_UNKNOWN) \
    MACRO(InternalError, NVAT_RC_INTERNAL_ERROR) \
    MACRO(NotInitialized, NVAT_RC_NOT_INITIALIZED) \
    MACRO(BadArgument, NVAT_RC_BAD_ARGUMENT) \
    MACRO(AllocFailed, NVAT_RC_ALLOC_FAILED) \
    MACRO(FeatureNotEnabled, NVAT_RC_FEATURE_NOT_ENABLED) \
    MACRO(XmlInitFailed, NVAT_RC_XML_INIT_FAILED) \
    MACRO(RelyingPartyPolicyMismatch, NVAT_RC_RP_POLICY_MISMATCH) \
    MACRO(OverallResultFalse, NVAT_RC_OVERALL_RESULT_FALSE) \
    MACRO(RimForbidden, NVAT_RC_RIM_FORBIDDEN) \
    MACRO(RimInternalError, NVAT_RC_RIM_INTERNAL_ERROR) \
    MACRO(RimConnectionError, NVAT_RC_RIM_CONNECTION_ERROR) \
    MACRO(RimNotFound, NVAT_RC_RIM_NOT_FOUND) \
    MACRO(RimInvalidSignature, NVAT_RC_RIM_INVALID_SIGNATURE) \
    MACRO(RimInvalidSchema, NVAT_RC_RIM_INVALID_SCHEMA) \
    MACRO(RimMeasurementNotFound, NVAT_RC_RIM_MEASUREMENT_NOT_FOUND) \
    MACRO(RimMeasurementConflict, NVAT_RC_RIM_MEASUREMENT_CONFLICT) \
    MACRO(NrasAttestationError, NVAT_RC_NRAS_ATTESTATION_ERROR) \
    MACRO(NrasTokenInvalid, NVAT_RC_NRAS_TOKEN_INVALID) \
    MACRO(OcspInvalidResponse, NVAT_RC_OCSP_INVALID_RESPONSE) \
    MACRO(OcspServerError, NVAT_RC_OCSP_SERVER_ERROR) \
    MACRO(OcspInvalidRequest, NVAT_RC_OCSP_INVALID_REQUEST) \
    MACRO(OcspStatusNotGood, NVAT_RC_OCSP_STATUS_NOT_GOOD) \
    MACRO(PolicyEvaluationError, NVAT_RC_POLICY_EVALUATION_ERROR) \
    MACRO(SpdmParseError, NVAT_RC_SPDM_PARSE_ERROR) \
    MACRO(SpdmOpaqueDataParseError, NVAT_RC_SPDM_OPAQUE_DATA_PARSE_ERROR) \
    MACRO(SpdmMeasurementRecordParseError, NVAT_RC_SPDM_MSR_PARSE_ERROR) \
    MACRO(SpdmRequestParseError, NVAT_RC_SPDM_REQUEST_PARSE_ERROR) \
    MACRO(SpdmFieldNotFound, NVAT_RC_SPDM_FIELD_NOT_FOUND) \
    MACRO(NvmlInitFailed, NVAT_RC_NVML_INIT_FAILED) \
    MACRO(NvmlError, NVAT_RC_NVML_ERROR) \
    MACRO(GpuArchitectureNotSupported, NVAT_RC_GPU_ARCHITECTURE_NOT_SUPPORTED) \
    MACRO(GpuEvidenceInvalid, NVAT_RC_GPU_EVIDENCE_INVALID) \
    MACRO(GpuEvidenceNonceMismatch, NVAT_RC_GPU_EVIDENCE_NONCE_MISMATCH) \
    MACRO(GpuEvidenceDriverRimVersionMismatch, NVAT_RC_GPU_EVIDENCE_DRIVER_RIM_VERSION_MISMATCH) \
    MACRO(GpuEvidenceVbiosRimVersionMismatch, NVAT_RC_GPU_EVIDENCE_VBIOS_RIM_VERSION_MISMATCH) \
    MACRO(GpuEvidenceFwidMismatch, NVAT_RC_GPU_EVIDENCE_FWID_MISMATCH) \
    MACRO(GpuEvidenceInvalidSignature, NVAT_RC_GPU_EVIDENCE_INVALID_SIGNATURE) \
    MACRO(CertFwidNotFound, NVAT_RC_CERT_FWID_NOT_FOUND) \
    MACRO(CertNotFound, NVAT_RC_CERT_NOT_FOUND) \
    MACRO(CertChainVerificationFailure, NVAT_RC_CERT_CHAIN_VERIFICATION_FAILURE) \
    MACRO(JsonSerializationError, NVAT_RC_JSON_SERIALIZATION_ERROR) \
    MACRO(LibXml2Error, NVAT_RC_LIBXML2_ERROR) \
    MACRO(NscqInitFailed, NVAT_RC_NSCQ_INIT_FAILED) \
    MACRO(NscqError, NVAT_RC_NSCQ_ERROR) \
    MACRO(NscqUuidError, NVAT_RC_NSCQ_UUID_ERROR) \
    MACRO(NscqCertChainError, NVAT_RC_NSCQ_CERT_CHAIN_ERROR) \
    MACRO(NscqAttestationReportError, NVAT_RC_NSCQ_ATTESTATION_REPORT_ERROR) \
    MACRO(NscqArchitectureError, NVAT_RC_NSCQ_ARCHITECTURE_ERROR) \
    MACRO(NscqTnvlError, NVAT_RC_NSCQ_TNVL_ERROR) \
    MACRO(SwitchEvidenceNonceMismatch, NVAT_RC_SWITCH_EVIDENCE_NONCE_MISMATCH) \
    MACRO(SwitchEvidenceVbiosRimVersionMismatch, NVAT_RC_SWITCH_EVIDENCE_VBIOS_RIM_VERSION_MISMATCH) \
    MACRO(SwitchEvidenceFwidMismatch, NVAT_RC_SWITCH_EVIDENCE_FWID_MISMATCH) \
    MACRO(SwitchEvidenceInvalidSignature, NVAT_RC_SWITCH_EVIDENCE_INVALID_SIGNATURE)

// Define both the Enum and an array of enum values
enum class Error {
    #define ERROR_ENUM_TO_ENUM(name, val) name = (val),
        ERROR_ENUM_LIST(ERROR_ENUM_TO_ENUM)
    #undef ERROR_ENUM_TO_ENUM
};

constexpr Error ErrorValues[] = {
    #define ERROR_ENUM_TO_ARRAY(name, val) Error::name,
        ERROR_ENUM_LIST(ERROR_ENUM_TO_ARRAY)
    #undef ERROR_ENUM_TO_ARRAY
};

inline const char* to_string(Error error) {
    switch (error) {
        case Error::Ok: return "Ok";
        case Error::Unknown: return "Unknown";
        case Error::InternalError: return "Internal Error";
        case Error::NotInitialized: return "Not initialized";
        case Error::BadArgument: return "Bad Argument";
        case Error::AllocFailed: return "Allocation Failed";
        case Error::FeatureNotEnabled: return "Feature is not enabled";
        case Error::XmlInitFailed: return "XML Initialization Failed";
        case Error::RelyingPartyPolicyMismatch: return "Relying Party Policy Mismatch";
        case Error::OverallResultFalse: return "Overall Attestation Result is False";

        // RIM errors
        case Error::RimForbidden: return "RIM Forbidden";
        case Error::RimInternalError: return "RIM Internal Error";
        case Error::RimConnectionError: return "RIM Connection Error";
        case Error::RimNotFound: return "RIM Not Found";
        case Error::RimInvalidSignature: return "RIM Invalid Signature";
        case Error::RimInvalidSchema: return "RIM Invalid Schema";
        case Error::RimMeasurementNotFound: return "RIM Measurement Not Found";
        case Error::RimMeasurementConflict: return "RIM Measurement Conflict";

        // OCSP errors
        case Error::OcspInvalidResponse: return "OCSP Invalid Response";
        case Error::OcspServerError: return "OCSP Server Error";
        case Error::OcspInvalidRequest: return "OCSP Invalid Request";
        case Error::OcspStatusNotGood: return "OCSP Status Not Good";

        // Policy errors
        case Error::PolicyEvaluationError: return "Policy Evaluation Error";

        // SPDM errors
        case Error::SpdmParseError: return "SPDM Parse Error";
        case Error::SpdmOpaqueDataParseError: return "SPDM Opaque Data Parse Error";
        case Error::SpdmMeasurementRecordParseError: return "SPDM Measurement Record Parse Error";
        case Error::SpdmRequestParseError: return "SPDM Request Parse Error";
        case Error::SpdmFieldNotFound: return "SPDM Field Not Found";

        // NVML / GPU errors
        case Error::NvmlInitFailed: return "NVML Initialization Failed";
        case Error::NvmlError: return "NVML Error";
        case Error::GpuArchitectureNotSupported: return "GPU Architecture Not Supported";
        case Error::GpuEvidenceInvalid: return "GPU Evidence Invalid";
        case Error::GpuEvidenceNonceMismatch: return "GPU Evidence Nonce Mismatch";
        case Error::GpuEvidenceDriverRimVersionMismatch: return "GPU Evidence Driver RIM Version Mismatch";
        case Error::GpuEvidenceVbiosRimVersionMismatch: return "GPU Evidence VBios RIM Version Mismatch";
        case Error::GpuEvidenceFwidMismatch: return "GPU Evidence FWID Mismatch";
        case Error::GpuEvidenceInvalidSignature: return "GPU Evidence Invalid Signature";

        // Certificate errors
        case Error::CertFwidNotFound: return "Certificate FWID Not Found";
        case Error::CertNotFound: return "Certificate Not Found";
        case Error::CertChainVerificationFailure: return "Certificate Chain Verification Failure";

        // NSCQ / Switch errors
        case Error::NscqInitFailed: return "NSCQ Initialization Failed";
        case Error::NscqError: return "NSCQ Error";
        case Error::NscqUuidError: return "NSCQ UUID Error";
        case Error::NscqCertChainError: return "NSCQ Certificate Chain Error";
        case Error::NscqAttestationReportError: return "NSCQ Attestation Report Error";
        case Error::NscqArchitectureError: return "NSCQ Architecture Error";
        case Error::NscqTnvlError: return "NSCQ TNVL Error";
        case Error::SwitchEvidenceNonceMismatch: return "SWITCH Evidence Nonce Mismatch";
        case Error::SwitchEvidenceVbiosRimVersionMismatch: return "SWITCH Evidence VBIOS RIM Version Mismatch";
        case Error::SwitchEvidenceFwidMismatch: return "SWITCH Evidence FWID Mismatch";
        case Error::SwitchEvidenceInvalidSignature: return "SWITCH Evidence Invalid Signature";

        // JSON serialization errors
        case Error::JsonSerializationError: return "JSON Serialization Error";


        // LibXml2 errors
        case Error::LibXml2Error: return "LibXml2 Error";

        // NRAS errors
        case Error::NrasAttestationError: return "NRAS Attestation Error";
        case Error::NrasTokenInvalid: return "NRAS Token Invalid";
    }
    return "Undefined";
}


inline std::ostream &operator<<(std::ostream& os, Error e) {
    os << "Error code " << static_cast<uint16_t>(e) << ": " << to_string(e);
    return os;
}

struct ErrorRecord {
    Error code;
    std::string message;
};

// todo(p3): remote ErrorStack and LOG_PUSH_ERROR from the code
/*
 A thread-local error stack that follows a LIFO pattern.
ref: https://github.com/openssl/openssl/blob/master/crypto/err/err.c#L820
ref: https://stackoverflow.com/questions/37980798/openssl-error-handling
ref: https://nvidia.slack.com/archives/C05S8LP717T/p1742248869340249

in the future, along with the log macros, we can add additional metadata 
to the error record like file, line, function name, etc.

since error record is not meant to be used by the client code
and is hidden from the client code,
we can change the implementation at any time.
*/
class ErrorStack {
public:
    // Push a new error onto the current thread's error stack
    static void push(Error code, const std::string& message);

    // Check if the current thread has any errors
    static bool has_errors();

    // Pop the most recent error. Returns {Error::Ok} if empty.
    static ErrorRecord pop();

    static ErrorRecord peek();

    // Clear all errors for the current thread
    static void clear();

private:
    // Thread-local vector of errors
    static thread_local std::vector<ErrorRecord> m_thread_errors;

    // Helper to access the thread-local error vector
    static std::vector<ErrorRecord>& get_thread_errors();
};
// Inline helper to get the current error code.
// the client code should only use this function to get the error code.
Error nv_get_error();

}
