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

/**
 * @file spdm_resp.hpp
 * @brief Defines the SpdmMeasurementResponseMessage11 class for parsing and representing
 *        SPDM GET_MEASUREMENTS response messages.
 */
#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <array>
#include <memory> 
#include <iostream>

#include "spdm_opaque_data_parser.hpp" 
#include "spdm_measurement_records.hpp" 
#include "nv_attestation/utils.h"

namespace nvattestation {

/**
 * @brief Represents an SPDM GET_MEASUREMENTS response message.
 *
 * This class provides functionality to parse a raw byte stream representing
 * an SPDM MEASUREMENTS response and provides access to its various fields.
 * It follows the SPDM 1.1 specification for the MEASUREMENTS response format.
 */
class SpdmMeasurementResponseMessage11 {
public:
    // Constants defining the size of various fields in the SPDM message
    static const size_t kSpdmVersionSize = 1;             ///< Size of SPDMVersion field in bytes.
    static const size_t kRequestResponseCodeSize = 1;     ///< Size of RequestResponseCode field in bytes.
    static const size_t kParam1Size = 1;                  ///< Size of Param1 field in bytes.
    static const size_t kParam2Size = 1;                  ///< Size of Param2 field in bytes.
    static const size_t kNumberOfBlocksSize = 1;          ///< Size of NumberOfBlocks field in bytes.
    static const size_t kMeasurementRecordLengthSize = 3; ///< Size of MeasurementRecordLength field in bytes.
    static const size_t kNonceSize = 32;                  ///< Size of Nonce field in bytes.
    static const size_t kOpaqueLengthSize = 2;            ///< Size of OpaqueLength field in bytes.

    /**
     * @brief Constructor.
     */
    SpdmMeasurementResponseMessage11();

    /**
     * @brief Factory method to create and parse an SPDM Measurement Response message.
     * @param response_data The raw byte vector containing the SPDM response message.
     * @param signature_length The expected length of the signature in the message.
     * @param out_message Reference to the SpdmMeasurementResponseMessage11 object to populate.
     * @return Error::Ok if parsing was successful, specific error code otherwise.
     */
    static Error create(const std::vector<uint8_t>& response_data, size_t signature_length, SpdmMeasurementResponseMessage11& out_message);

    /**
     * @brief Parses the raw response data to populate the message fields.
     * @param response_data The raw byte vector containing the SPDM response message.
     * @param signature_length The expected length of the signature in the message.
     * @return Error::Ok if parsing was successful, specific error code otherwise.
     */
    Error parse(const std::vector<uint8_t>& response_data, size_t signature_length);

    // Getter methods
    /** @brief Gets the SPDM version from the message. */
    uint8_t get_spdm_version() const { return m_spdm_version; }
    /** @brief Gets the request/response code from the message. */
    uint8_t get_request_response_code() const { return m_request_response_code; }
    /** @brief Gets Param1 from the message. */
    uint8_t get_param1() const { return m_param1; }
    /** @brief Gets Param2 from the message. */
    uint8_t get_param2() const { return m_param2; }
    /** @brief Gets the number of measurement blocks. */
    uint8_t get_number_of_blocks() const { return m_number_of_blocks; }
    /** @brief Gets the length of the measurement record. */
    uint32_t get_measurement_record_length() const { return m_measurement_record_length; }
    /** @brief Gets the measurement record data. Vector of bytes */
    const std::vector<uint8_t>& get_measurement_record_data() const { return m_measurement_record_data; }
    /** @brief Gets the parsed measurement records. */
    const SpdmMeasurementRecordParser& get_parsed_measurement_records() const { return *m_parsed_measurement_records; }
    /** @brief Gets the nonce. Vector of bytes*/
    const std::array<uint8_t, kNonceSize>& get_nonce() const { return m_nonce; }
    /** @brief Gets the length of the opaque data. */
    uint16_t get_opaque_data_length() const { return m_opaque_data_length; }
    /** @brief Gets the opaque data. Vector of bytes*/
    const std::vector<uint8_t>& get_opaque_data() const { return m_opaque_data; }
    /** @brief Gets the parsed opaque data fields. 
     *  @param out_parsed_opaque_data Reference to a pointer that will be set to point to the OpaqueDataParser if parsing was successful and opaque data was present.
     *  @return Error::Ok if successful, Error::SpdmFieldNotFound if opaque data was not parsed or not available.
     */
    const OpaqueDataParser& get_parsed_opaque_struct() const { return m_parsed_opaque_data; }
    Error get_parsed_opaque_data(const std::vector<ParsedOpaqueFieldData>*& out_parsed_opaque_data) const;
    /** @brief Gets the signature. Vector of bytes*/
    const std::vector<uint8_t>& get_signature() const { return m_signature; }

    /**
     * @brief Overloads the << operator to print the object's fields.
     *
     * This function is useful for debugging and inspecting the content of the
     * parsed SPDM message.
     * @param os The output stream.
     * @param msg The SpdmMeasurementResponseMessage11 object to print.
     * @return The output stream.
     */
    friend std::ostream& operator<<(std::ostream& os, const SpdmMeasurementResponseMessage11& msg);

private:
    // Member fields
    uint8_t m_spdm_version{};                   ///< SPDMVersion field.
    uint8_t m_request_response_code{};          ///< RequestResponseCode field.
    uint8_t m_param1{};                         ///< Param1 field.
    uint8_t m_param2{};                         ///< Param2 field.
    uint8_t m_number_of_blocks{};               ///< NumberOfBlocks field.
    uint32_t m_measurement_record_length{};     ///< MeasurementRecordLength field (read as 3 bytes).
    std::vector<uint8_t> m_measurement_record_data; ///< MeasurementRecord data.
    std::shared_ptr<SpdmMeasurementRecordParser> m_parsed_measurement_records; ///< Parsed MeasurementRecord field.
    std::array<uint8_t, kNonceSize> m_nonce{};  ///< Nonce field.
    uint16_t m_opaque_data_length{};            ///< OpaqueDataLength field (read as 2 bytes).
    std::vector<uint8_t> m_opaque_data;         ///< OpaqueData.
    OpaqueDataParser m_parsed_opaque_data;     ///< Parsed OpaqueData field.
    std::vector<uint8_t> m_signature;           ///< Signature data.


};

} // namespace nvattestation
