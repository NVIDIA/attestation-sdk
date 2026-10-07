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
 * @file spdm_resp_test.cpp
 * @brief Unit tests for the SpdmMeasurementResponseMessage11 class.
 */
#include <vector>
#include <string>
#include <iomanip> // For std::setw, std::setfill, std::hex
#include <sstream> // For std::stringstream
#include <algorithm> // For std::copy
#include <fstream>   // For file input
#include <string>    // For std::stoul
#include <memory>    // For std::unique_ptr, std::shared_ptr

#include "gtest/gtest.h"

#include "nv_attestation/spdm/spdm_resp.hpp"
#include "nv_attestation/spdm/spdm_req.hpp"
#include "nv_attestation/spdm/spdm_opaque_data_parser.hpp" // For OpaqueDataParser, ParsedOpaqueFieldData
#include "nv_attestation/gpu/spdm/gpu_opaque_data_parser.hpp" // For GpuOpaqueDataType, GpuParsedOpaqueFieldData, GpuOpaqueDataParser
#include "nv_attestation/spdm/spdm_measurement_records.hpp" // For SpdmMeasurementRecordParser
#include "nv_attestation/log.h" // For LOG_DEBUG
#include "nv_attestation/error.h" // For nvattestation::Error
#include "nlohmann/json.hpp" // For JSON parsing
#include "nv_attestation/utils.h"
#include "spdm_test_utils.h"

using namespace nvattestation;
using json = nlohmann::json;


/**
 * @brief Test fixture for SpdmMeasurementResponseMessage11 tests.
 *
 * Provides a common setup and teardown environment for tests related to
 * SPDM response message parsing and handling.
 */
class GpuSpdmRespTest : public ::testing::Test {
protected:
    /**
     * @brief Sets up the test environment before each test case.
     * 
     * Reads the SPDM report, parses the response, and loads expected values from JSON.
     */
    void SetUp() override {
        std::string full_report_hex;
        std::ifstream report_file("testdata/hopperAttestationReport.txt");

        if (!report_file.is_open()) {
            GTEST_FAIL() << "Failed to open unit-tests/testdata/hopperAttestationReport.txt";
        }
        
        std::getline(report_file, full_report_hex);
        report_file.close();

        if (full_report_hex.empty()) {
            GTEST_FAIL() << "Failed to read data from hopperAttestationReport.txt or file is empty.";
        }

        const size_t request_hex_length = SpdmMeasurementRequestMessage11::get_request_length()*2;
        if (full_report_hex.length() < request_hex_length) {
            GTEST_FAIL() << "Report data too short.";
        }

        std::string response_hex_data = full_report_hex.substr(request_hex_length);
        m_response_bytes = hex_string_to_bytes(response_hex_data);

        // Default signature length, adjust if necessary based on actual SPDM settings.
        m_signature_length = 96; 

        Error error = SpdmMeasurementResponseMessage11::create(m_response_bytes, m_signature_length, m_msg);
        if (error != Error::Ok) {
            GTEST_FAIL() << "Failed to create SpdmMeasurementResponseMessage11 in SetUp. Check logs for errors.";
        }

        std::ifstream json_file("testdata/spdm_parsed_output.json");
        if (!json_file.is_open()) {
            GTEST_FAIL() << "Failed to open unit-tests/testdata/spdm_parsed_output.json in SetUp";
        }
        json_file >> m_expected_values_json;
        json_file.close();
    }

    /**
     * @brief Cleans up the test environment after each test case.
     */
    void TearDown() override {
        // Common teardown for tests if needed
        // Other members are value types or standard containers that manage their own memory.
    }

    // Member variables to hold common test data
    std::vector<uint8_t> m_response_bytes;
    size_t m_signature_length;
    SpdmMeasurementResponseMessage11 m_msg;
    json m_expected_values_json;
};

/**
 * @brief Tests parsing of a valid SPDM GET_MEASUREMENTS response and verifies its fields.
 *
 * the expected values were hardcoded from `spdm_parsed_output.json` which is a dump of parsed
 * spdm response for the sample spdm response hopperAttestationReport.txt from
 * the old python sdk. essentially, we are making sure that the parsed spdm response 
 * gives the same values as that of the old python sdk.
 */
TEST_F(GpuSpdmRespTest, ParseAndVerifySpdmResponse) {
    parse_and_verify_spdm_response(m_msg, m_expected_values_json);
    EXPECT_EQ(m_msg.get_signature().size(), m_signature_length);
}

TEST_F(GpuSpdmRespTest, ParseAndVerifyOpaqueData) {
    ASSERT_FALSE(m_expected_values_json.is_null()) << "Expected values JSON is null. SetUp might have failed.";

    const OpaqueDataParser& opaque_parser = m_msg.get_parsed_opaque_struct();

    LOG_DEBUG(opaque_parser);

    // Get all fields from the base parser
    const std::vector<ParsedOpaqueFieldData>* base_fields_ptr = nullptr;
    Error error = opaque_parser.get_all_fields(base_fields_ptr);
    ASSERT_EQ(error, Error::Ok) << "Failed to get all fields from base parser";

    // Create GPU-specific parser
    GpuOpaqueDataParser gpu_parser;
    error = GpuOpaqueDataParser::create(*base_fields_ptr, opaque_parser.get_format_version(), gpu_parser);
    ASSERT_EQ(error, Error::Ok) << "Failed to create GPU opaque data parser";

    LOG_DEBUG(gpu_parser);

    const json& expected_opaque_fields = m_expected_values_json["OpaqueData"]["OpaqueDataField"];

    // Helper lambda to get and check a byte_vector field
    auto check_byte_vector_field = [&](GpuOpaqueDataType type, const std::string& json_key) {
        const GpuParsedOpaqueFieldData* actual_field_data = nullptr;
        Error error = gpu_parser.get_field(type, actual_field_data);
        ASSERT_EQ(error, Error::Ok) << "Failed to get field: " << json_key;
        ASSERT_EQ(actual_field_data->get_type(), GpuParsedFieldType::BYTE_VECTOR) << "Field " << json_key << " is not a byte vector.";
        
        const std::string expected_hex = expected_opaque_fields[json_key].get<std::string>();
        // Ensure "0x" prefix is handled if present, hex_string_to_bytes expects it to be absent
        std::vector<uint8_t> expected_bytes = hex_string_to_bytes(expected_hex.rfind("0x", 0) == 0 ? expected_hex.substr(2) : expected_hex);
        const std::vector<uint8_t>* actual_bytes = nullptr;
        ASSERT_EQ(actual_field_data->get_byte_vector(actual_bytes), Error::Ok) << "Failed to get byte vector for field: " << json_key;
        EXPECT_EQ(*actual_bytes, expected_bytes) << "Mismatch for opaque field: " << json_key;
    };

    // Assertions for Opaque Data Fields
    check_byte_vector_field(GpuOpaqueDataType::BOARD_ID, "OPAQUE_FIELD_ID_BOARD_ID");
    check_byte_vector_field(GpuOpaqueDataType::CHIP_SKU, "OPAQUE_FIELD_ID_CHIP_SKU");
    check_byte_vector_field(GpuOpaqueDataType::CHIP_SKU_MOD, "OPAQUE_FIELD_ID_CHIP_SKU_MOD");
    check_byte_vector_field(GpuOpaqueDataType::CPRINFO, "OPAQUE_FIELD_ID_CPRINFO");
    check_byte_vector_field(GpuOpaqueDataType::DRIVER_VERSION, "OPAQUE_FIELD_ID_DRIVER_VERSION");
    check_byte_vector_field(GpuOpaqueDataType::FWID, "OPAQUE_FIELD_ID_FWID");
    check_byte_vector_field(GpuOpaqueDataType::GPU_INFO, "OPAQUE_FIELD_ID_GPU_INFO");
    check_byte_vector_field(GpuOpaqueDataType::NVDEC0_STATUS, "OPAQUE_FIELD_ID_NVDEC0_STATUS");
    check_byte_vector_field(GpuOpaqueDataType::PROJECT, "OPAQUE_FIELD_ID_PROJECT");
    check_byte_vector_field(GpuOpaqueDataType::PROJECT_SKU, "OPAQUE_FIELD_ID_PROJECT_SKU");
    check_byte_vector_field(GpuOpaqueDataType::PROJECT_SKU_MOD, "OPAQUE_FIELD_ID_PROJECT_SKU_MOD");
    check_byte_vector_field(GpuOpaqueDataType::PROTECTED_PCIE_STATUS, "OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS");
    check_byte_vector_field(GpuOpaqueDataType::VBIOS_VERSION, "OPAQUE_FIELD_ID_VBIOS_VERSION");

    // Special handling for MSRSCNT (uint32_vector)
    const GpuParsedOpaqueFieldData* msrscnt_field_data = nullptr;
    error = gpu_parser.get_field(GpuOpaqueDataType::MSRSCNT, msrscnt_field_data);
    ASSERT_EQ(error, Error::Ok) << "Failed to get field: MSRSCNT";
    ASSERT_EQ(msrscnt_field_data->get_type(), GpuParsedFieldType::UINT32_VECTOR) << "Field MSRSCNT is not a uint32 vector.";
    std::vector<uint32_t> expected_msrscnt = expected_opaque_fields["OPAQUE_FIELD_ID_MSRSCNT"].get<std::vector<uint32_t>>();
    const std::vector<uint32_t>* actual_msrscnt = nullptr;
    ASSERT_EQ(msrscnt_field_data->get_uint32_vector(actual_msrscnt), Error::Ok) << "Failed to get uint32 vector for field: MSRSCNT";
    EXPECT_EQ(*actual_msrscnt, expected_msrscnt) << "Mismatch for opaque field: MSRSCNT";
}

TEST_F(GpuSpdmRespTest, ParseAndVerifyMeasurementRecords) {
    parse_and_verify_measurement_records(m_msg, m_expected_values_json);
}

// Offset of the Nth (0-indexed) TLV record's DataSize field within the opaque-data segment.
static size_t find_opaque_tlv_size_field_offset(const std::vector<uint8_t>& response_bytes,
                                                  const SpdmMeasurementResponseMessage11& msg,
                                                  size_t record_index) {
    size_t offset = SpdmMeasurementResponseMessage11::kSpdmVersionSize
        + SpdmMeasurementResponseMessage11::kRequestResponseCodeSize
        + SpdmMeasurementResponseMessage11::kParam1Size
        + SpdmMeasurementResponseMessage11::kParam2Size
        + SpdmMeasurementResponseMessage11::kNumberOfBlocksSize
        + SpdmMeasurementResponseMessage11::kMeasurementRecordLengthSize
        + msg.get_measurement_record_length()
        + SpdmMeasurementResponseMessage11::kNonceSize
        + SpdmMeasurementResponseMessage11::kOpaqueLengthSize;

    for (size_t i = 0; i < record_index; i++) {
        uint16_t data_size = static_cast<uint16_t>(response_bytes[offset + 2]) |
                              (static_cast<uint16_t>(response_bytes[offset + 3]) << 8);
        offset += 2 /*type*/ + 2 /*size*/ + data_size;
    }
    return offset + 2; // skip past this record's type field to its size field
}

// Default (legacy) behavior: malformed OpaqueData still fails the whole parse.
TEST_F(GpuSpdmRespTest, OpaqueDataParseFailureIsFatalByDefault) {
    std::vector<uint8_t> corrupted_response = m_response_bytes;
    size_t size_field_offset = find_opaque_tlv_size_field_offset(corrupted_response, m_msg, 0);
    corrupted_response[size_field_offset] = 0xFF;
    corrupted_response[size_field_offset + 1] = 0xFF;

    SpdmMeasurementResponseMessage11 corrupted_msg;
    Error error = SpdmMeasurementResponseMessage11::create(corrupted_response, m_signature_length, corrupted_msg);
    EXPECT_EQ(error, Error::SpdmOpaqueDataParseError);
}

// parse_opaque_data=false (CoRIM): malformed OpaqueData must not fail the parse.
TEST_F(GpuSpdmRespTest, OpaqueDataParseIsSkippedWhenNotRequested) {
    std::vector<uint8_t> corrupted_response = m_response_bytes;
    size_t size_field_offset = find_opaque_tlv_size_field_offset(corrupted_response, m_msg, 0);
    corrupted_response[size_field_offset] = 0xFF;
    corrupted_response[size_field_offset + 1] = 0xFF;

    SpdmMeasurementResponseMessage11 corrupted_msg;
    Error error = SpdmMeasurementResponseMessage11::create(
        corrupted_response, m_signature_length, corrupted_msg, /*parse_opaque_data=*/false);
    ASSERT_EQ(error, Error::Ok);

    // Measurement records and raw opaque bytes are still available; only decoding is skipped.
    EXPECT_EQ(corrupted_msg.get_opaque_data_length(), m_msg.get_opaque_data_length());
    EXPECT_EQ(corrupted_msg.get_signature().size(), m_signature_length);
    const std::vector<ParsedOpaqueFieldData>* fields = nullptr;
    ASSERT_EQ(corrupted_msg.get_parsed_opaque_struct().get_all_fields(fields), Error::Ok);
    EXPECT_TRUE(fields->empty());
}

// ---------------------------------------------------------------------------
// OpaqueDataParser header detection tests
// ---------------------------------------------------------------------------

static std::vector<uint8_t> make_nvdaod_header(uint8_t major, uint8_t minor) {
    return {
        'N','V','D','A','O','D',
        0x00, 0x00,               // profile = 0 (u16 LE)
        major, minor, 0x00, 0x00  // version + reserved
    };
}

static std::vector<uint8_t> make_typed_entry(uint16_t type, uint16_t value_type,
                                             const std::vector<uint8_t>& data) {
    uint16_t sz = static_cast<uint16_t>(data.size());
    std::vector<uint8_t> out = {
        static_cast<uint8_t>(type & 0xFFU),       static_cast<uint8_t>(type >> 8U),
        static_cast<uint8_t>(value_type & 0xFFU), static_cast<uint8_t>(value_type >> 8U),
        static_cast<uint8_t>(sz & 0xFFU),         static_cast<uint8_t>(sz >> 8U),
    };
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

TEST(OpaqueDataParserHeaderTest, NewFormatParsedSuccessfully) {
    auto hdr = make_nvdaod_header(0, 2);
    auto entry = make_typed_entry(1U, 0U, {0xAB, 0xCD});
    hdr.insert(hdr.end(), entry.begin(), entry.end());

    OpaqueDataParser parser;
    ASSERT_EQ(OpaqueDataParser::create(hdr, parser), Error::Ok);

    OpaqueDataFormatVersion ver = parser.get_format_version();
    EXPECT_EQ(ver.major, 0U);
    EXPECT_EQ(ver.minor, 2U);

    const std::vector<ParsedOpaqueFieldData>* fields = nullptr;
    ASSERT_EQ(parser.get_all_fields(fields), Error::Ok);
    ASSERT_EQ(fields->size(), 1U);
    EXPECT_EQ((*fields)[0].get_type(),       1U);
    EXPECT_EQ((*fields)[0].get_value_type(), 0U);
}

TEST(OpaqueDataParserHeaderTest, ReusedInstanceDoesNotRetainStaleState) {
    auto hdr = make_nvdaod_header(0, 2);
    auto entry = make_typed_entry(1U, 0U, {0xAB, 0xCD});
    hdr.insert(hdr.end(), entry.begin(), entry.end());

    OpaqueDataParser parser;
    ASSERT_EQ(OpaqueDataParser::create(hdr, parser), Error::Ok);
    ASSERT_TRUE(parser.get_format_version().has_header);

    // Re-parse the same instance with legacy (no-header) bytes; the prior
    // has_header=true and field list must not leak into this parse.
    std::vector<uint8_t> legacy_raw = {0x02, 0x00, 0x02, 0x00, 0xEF, 0x01};
    ASSERT_EQ(OpaqueDataParser::create(legacy_raw, parser), Error::Ok);

    OpaqueDataFormatVersion ver = parser.get_format_version();
    EXPECT_FALSE(ver.has_header);
    EXPECT_EQ(ver.major, 0U);
    EXPECT_EQ(ver.minor, 0U);

    const std::vector<ParsedOpaqueFieldData>* fields = nullptr;
    ASSERT_EQ(parser.get_all_fields(fields), Error::Ok);
    ASSERT_EQ(fields->size(), 1U);
    EXPECT_EQ((*fields)[0].get_type(), 2U);
}

TEST(OpaqueDataParserHeaderTest, LegacyFormatVersionAllZero) {
    // Legacy TLV (no header): [u16 type][u16 size][data]
    std::vector<uint8_t> raw = {0x01, 0x00, 0x02, 0x00, 0xAB, 0xCD};
    OpaqueDataParser parser;
    ASSERT_EQ(OpaqueDataParser::create(raw, parser), Error::Ok);

    OpaqueDataFormatVersion ver = parser.get_format_version();
    EXPECT_EQ(ver.major, 0U);
    EXPECT_EQ(ver.minor, 0U);

    const std::vector<ParsedOpaqueFieldData>* fields = nullptr;
    ASSERT_EQ(parser.get_all_fields(fields), Error::Ok);
    ASSERT_EQ(fields->size(), 1U);
    EXPECT_EQ((*fields)[0].get_value_type(), 0U);  // no value_type in legacy
}

// Documents V0.C behavior on new-format bytes: the legacy parse path reads
// type=0x564E, size=0x4144=16708, then fails to fill a 16708-byte buffer.
TEST(OpaqueDataParserHeaderTest, LegacyParsePath_RejectsNewHeaderBytes) {
    auto hdr = make_nvdaod_header(0, 2);
    hdr.insert(hdr.end(), {0x01, 0x00, 0x02, 0x00, 0xAA});

    Error err = OpaqueDataParser::parse_as_legacy_for_test(hdr);
    EXPECT_NE(err, Error::Ok);
}

// The SPDM layer records the header's major/minor but does not gate on them; the version bound
// check happens once, downstream in GpuOpaqueDataParser::create (converged with the legacy path).
TEST(OpaqueDataParserHeaderTest, HeaderMajorVersionIsRecordedNotGated) {
    auto hdr = make_nvdaod_header(1, 0);
    OpaqueDataParser parser;
    ASSERT_EQ(OpaqueDataParser::create(hdr, parser), Error::Ok);
    EXPECT_EQ(parser.get_format_version().major, 1U);
}

TEST(OpaqueDataParserHeaderTest, NonZeroProfileReturnsBadArgument) {
    std::vector<uint8_t> bad_hdr = {
        'N','V','D','A','O','D',
        0x01, 0x00,  // profile = 1 (invalid)
        0x00, 0x02, 0x00, 0x00
    };
    OpaqueDataParser parser;
    EXPECT_EQ(OpaqueDataParser::create(bad_hdr, parser), Error::BadArgument);
}

TEST(OpaqueDataParserHeaderTest, NewFormatMultipleEntriesPreservesValueTypes) {
    auto hdr = make_nvdaod_header(0, 2);
    auto e1 = make_typed_entry(3U,  0x86U, {0x01, 0x02, 0x03, 0x04});
    auto e2 = make_typed_entry(37U, 0x87U, {0x04, 0x00});
    hdr.insert(hdr.end(), e1.begin(), e1.end());
    hdr.insert(hdr.end(), e2.begin(), e2.end());

    OpaqueDataParser parser;
    ASSERT_EQ(OpaqueDataParser::create(hdr, parser), Error::Ok);

    const std::vector<ParsedOpaqueFieldData>* fields = nullptr;
    ASSERT_EQ(parser.get_all_fields(fields), Error::Ok);
    ASSERT_EQ(fields->size(), 2U);
    EXPECT_EQ((*fields)[0].get_type(),       3U);
    EXPECT_EQ((*fields)[0].get_value_type(), 0x86U);
    EXPECT_EQ((*fields)[1].get_type(),       37U);
    EXPECT_EQ((*fields)[1].get_value_type(), 0x87U);
}

// ---------------------------------------------------------------------------
// GpuOpaqueDataParser FSP_UCODE_SVN + forward-compatibility tests
// ---------------------------------------------------------------------------

static std::vector<ParsedOpaqueFieldData> make_fields_with_min_svn(uint16_t svn) {
    std::vector<uint8_t> svn_bytes = {
        static_cast<uint8_t>(svn & 0xFFU),
        static_cast<uint8_t>(svn >> 8U)
    };
    ParsedOpaqueFieldData field;
    ParsedOpaqueFieldData::create(svn_bytes, 37U, 0x87U, field);
    return {field};
}

TEST(GpuOpaqueMinSvnTest, ParsesFspUcodeSvnFieldStoredAsBytes) {
    auto fields = make_fields_with_min_svn(5U);
    OpaqueDataFormatVersion ver{0, 2, true};
    GpuOpaqueDataParser parser;
    ASSERT_EQ(GpuOpaqueDataParser::create(fields, ver, parser), Error::Ok);

    const GpuParsedOpaqueFieldData* svn_field = nullptr;
    ASSERT_EQ(parser.get_field(37U, svn_field), Error::Ok);
    const std::vector<uint8_t>* bytes = nullptr;
    ASSERT_EQ(svn_field->get_byte_vector(bytes), Error::Ok);
    ASSERT_EQ(bytes->size(), 2U);
    uint16_t val = static_cast<uint16_t>((*bytes)[0]) | (static_cast<uint16_t>((*bytes)[1]) << 8U);
    EXPECT_EQ(val, 5U);
    EXPECT_EQ(svn_field->get_value_type(), 0x87U);
}

TEST(GpuOpaqueMinSvnTest, MissingFspUcodeSvnFieldNotFound) {
    std::vector<uint8_t> data = {0x01};
    ParsedOpaqueFieldData field;
    ASSERT_EQ(ParsedOpaqueFieldData::create(data, 1U, 0U, field), Error::Ok);

    OpaqueDataFormatVersion ver{0, 2, true};
    GpuOpaqueDataParser parser;
    ASSERT_EQ(GpuOpaqueDataParser::create({field}, ver, parser), Error::Ok);
    const GpuParsedOpaqueFieldData* svn_field = nullptr;
    EXPECT_NE(parser.get_field(37U, svn_field), Error::Ok);
}

TEST(GpuOpaqueMinSvnTest, LegacyVersionCheckFromType34) {
    std::vector<uint8_t> ver_bytes = {0x01, 0x00};  // NvU16 LE = 1
    ParsedOpaqueFieldData ver_field;
    ParsedOpaqueFieldData::create(ver_bytes, 34U, 0U, ver_field);

    OpaqueDataFormatVersion legacy_ver;  // default: all zero
    GpuOpaqueDataParser parser;
    ASSERT_EQ(GpuOpaqueDataParser::create({ver_field}, legacy_ver, parser), Error::Ok);
    EXPECT_EQ(parser.get_opaque_data_version(), 1U);
}

TEST(GpuOpaqueMinSvnTest, NewFormatVersionComesFromHeaderMajor) {
    OpaqueDataFormatVersion ver{1, 0, true};
    GpuOpaqueDataParser parser;
    ASSERT_EQ(GpuOpaqueDataParser::create({}, ver, parser), Error::Ok);
    EXPECT_EQ(parser.get_opaque_data_version(), 1U);
}

TEST(GpuOpaqueMinSvnTest, NewFormatIgnoresStrayLegacyVersionEntry) {
    // A producer may still emit the legacy OPAQUE_DATA_VERSION entry alongside the NVDAOD
    // header; the new format's version comes from the header major, not this entry.
    std::vector<uint8_t> ver_bytes = {0x63, 0x00};  // NvU16 LE = 99, would fail the bound check
    ParsedOpaqueFieldData ver_field;
    ParsedOpaqueFieldData::create(ver_bytes, 34U, 0U, ver_field);

    OpaqueDataFormatVersion ver{1, 0, true};
    GpuOpaqueDataParser parser;
    ASSERT_EQ(GpuOpaqueDataParser::create({ver_field}, ver, parser), Error::Ok);
    EXPECT_EQ(parser.get_opaque_data_version(), 1U);
}

TEST(GpuOpaqueMinSvnTest, NewFormatVersionExceedingMaxIsRejected) {
    OpaqueDataFormatVersion ver{3, 0, true};
    GpuOpaqueDataParser parser;
    EXPECT_EQ(GpuOpaqueDataParser::create({}, ver, parser), Error::GpuFwNotSupported);
}

// Types with no entry in GpuOpaqueDataType/expected_type_map are still retained (keyed by their
// raw id) rather than dropped, so a new MIN_SVN-style field can be recognized by compare_opaque_data()
// via type_id + value_type without an SDK release, as long as the major version hasn't changed.
TEST(GpuOpaqueMinSvnTest, UnknownTypeIsRetainedByRawId) {
    std::vector<uint8_t> data = {0xDE, 0xAD};
    ParsedOpaqueFieldData field;
    ASSERT_EQ(ParsedOpaqueFieldData::create(data, 200U, 0U, field), Error::Ok);

    OpaqueDataFormatVersion ver;
    GpuOpaqueDataParser parser;
    ASSERT_EQ(GpuOpaqueDataParser::create({field}, ver, parser), Error::Ok);

    const GpuParsedOpaqueFieldData* out_field = nullptr;
    ASSERT_EQ(parser.get_field(200U, out_field), Error::Ok);
    const std::vector<uint8_t>* byte_data = nullptr;
    ASSERT_EQ(out_field->get_byte_vector(byte_data), Error::Ok);
    EXPECT_EQ(*byte_data, data);
    EXPECT_EQ(out_field->get_value_type(), 0U);
}

TEST(GpuOpaqueMinSvnTest, Type255InvalidIsRetainedByRawId) {
    std::vector<uint8_t> data = {0xFF};
    ParsedOpaqueFieldData field;
    ASSERT_EQ(ParsedOpaqueFieldData::create(data, 255U, 0xFFU, field), Error::Ok);

    OpaqueDataFormatVersion ver;
    GpuOpaqueDataParser parser;
    ASSERT_EQ(GpuOpaqueDataParser::create({field}, ver, parser), Error::Ok);

    const GpuParsedOpaqueFieldData* out_field = nullptr;
    ASSERT_EQ(parser.get_field(255U, out_field), Error::Ok);
    EXPECT_EQ(out_field->get_value_type(), 0xFFU);
}

TEST(GpuOpaqueMinSvnTest, NvleStatusTypeIsRetainedByRawId) {
    // type=38 has no GpuOpaqueDataType entry yet; must still be recognized by raw id.
    std::vector<uint8_t> data = {0xAA, 0x00};
    ParsedOpaqueFieldData field;
    ASSERT_EQ(ParsedOpaqueFieldData::create(data, 38U, 0x85U, field), Error::Ok);

    OpaqueDataFormatVersion ver{0, 2, true};
    GpuOpaqueDataParser parser;
    ASSERT_EQ(GpuOpaqueDataParser::create({field}, ver, parser), Error::Ok);

    const GpuParsedOpaqueFieldData* out_field = nullptr;
    ASSERT_EQ(parser.get_field(38U, out_field), Error::Ok);
    EXPECT_EQ(out_field->get_value_type(), 0x85U);
}

TEST(GpuOpaqueDataTypeToStringTest, UnnamedIdFallsBackToHexFormat) {
    // GpuOpaqueDataType has a fixed underlying type (uint16_t), so static_cast from any
    // uint16_t is well-defined -- never UB, never throws -- even for values with no named
    // enumerator. Confirm to_string()'s default branch handles that case correctly.
    std::string result;
    EXPECT_NO_THROW(result = to_string(static_cast<GpuOpaqueDataType>(40U)));
    EXPECT_EQ(result, "UNKNOWN_OPAQUE_TYPE(0x28)");
}

// ---------------------------------------------------------------------------
// Real captured SPDM transcript, NVDAOD (new) opaque data format
// ---------------------------------------------------------------------------

// Structural smoke test only: parses the SPDM response and opaque data,
// without going through GpuEvidence::AttestationReport (which also verifies
// the report's signature against a cert chain we don't have for this sample).
//
// This transcript declares NVDAOD header major=2. MAX_OPAQUE_DATA_VERSION covers up
// through major=2, so this now parses end to end through the single, converged version
// check in GpuOpaqueDataParser::create.
TEST(SpdmRespRealTranscriptTest, ParsesNewFormatOpaqueData) {
    std::ifstream report_file("testdata/sample_nvdaod_transcript.txt");
    ASSERT_TRUE(report_file.is_open()) << "Failed to open testdata/sample_nvdaod_transcript.txt";
    std::string full_report_hex;
    std::getline(report_file, full_report_hex);
    ASSERT_FALSE(full_report_hex.empty());

    const size_t request_hex_length = SpdmMeasurementRequestMessage11::get_request_length() * 2;
    ASSERT_GT(full_report_hex.length(), request_hex_length) << "Report data too short";
    std::vector<uint8_t> response_bytes =
        hex_string_to_bytes(full_report_hex.substr(request_hex_length));

    const size_t signature_length = 96;
    SpdmMeasurementResponseMessage11 msg;
    ASSERT_EQ(SpdmMeasurementResponseMessage11::create(response_bytes, signature_length, msg), Error::Ok);

    OpaqueDataFormatVersion format_version = msg.get_parsed_opaque_struct().get_format_version();
    ASSERT_TRUE(format_version.has_header) << "Expected this transcript to use the NVDAOD header format";
    EXPECT_EQ(format_version.major, 2U);

    const std::vector<ParsedOpaqueFieldData>* opaque_fields = nullptr;
    ASSERT_EQ(msg.get_parsed_opaque_data(opaque_fields), Error::Ok);
    ASSERT_NE(opaque_fields, nullptr);
    EXPECT_FALSE(opaque_fields->empty());

    GpuOpaqueDataParser gpu_opaque_parser;
    ASSERT_EQ(GpuOpaqueDataParser::create(*opaque_fields, format_version, gpu_opaque_parser), Error::Ok);
    LOG_DEBUG(gpu_opaque_parser);
}
