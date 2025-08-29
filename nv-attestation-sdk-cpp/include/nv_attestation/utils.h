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
#include <cstdlib>
#include <cstring>
#include <curl/urlapi.h>
#include <string>
#include <vector>
#include <fstream>
#include <iterator>
#include <iomanip> // For std::setw, std::setfill, std::hex
#include <algorithm> // For std::copy (if needed by moved functions, though not directly by these)
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <errno.h>
#include "error.h"
#include "log.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>

namespace nvattestation {

const size_t MIN_VALID_NONCE_LEN = 32;

/**
 * @brief Reads the entire content of a file into a string.
 * @param path The path to the file to read.
 * @param out_content The string to store the file content.
 * @return Error::Ok on success, Error::InternalError on failure.
 */
inline Error readFileIntoString(const std::string& path, std::string& out_content) {
    std::ifstream ifs(path);
    if (!ifs) {
        LOG_ERROR("Could not open file: " << path);
        return Error::InternalError;
    }
    out_content = std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    return Error::Ok;
}

inline std::string get_openssl_error() {
    unsigned long err = ERR_peek_error();
    if (err == 0) {
        return "[No OpenSSL error on stack]";
    }
    const size_t err_msg_len = 256;
    char buf[err_msg_len] = {0};
    ERR_error_string_n(err, buf, err_msg_len - 1);
    return std::string(buf);
}


inline Error decode_base64(const std::string &base64_data, std::vector<uint8_t>& out_decoded_data) {
    //ref: https://docs.openssl.org/3.0/man3/EVP_EncodeInit/
    int len = base64_data.length();

    std::vector<unsigned char> out(len);
    int outlen = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(base64_data.c_str()), len);
    if (outlen < 0) {
        LOG_ERROR("Failed to decode base64 data");
        return Error::InternalError;
    }
    
    // Handle base64 padding by adjusting outlen
    // EVP_DecodeBlock doesn't handle padding correctly, we need to remove padding bytes manually
    int padding = 0;
    if (base64_data.length() >= 2) {
        if (base64_data[base64_data.length() - 1] == '=') padding++;
        if (base64_data[base64_data.length() - 2] == '=') padding++;
    }
    outlen -= padding;
    
    out_decoded_data = std::vector<uint8_t>(out.data(), out.data() + outlen);
    return Error::Ok;
}

inline Error decode_base64(const std::string &base64_data, std::string& out_decoded_data) {
    std::vector<uint8_t> decoded_data;
    Error error = decode_base64(base64_data, decoded_data);
    if (error != Error::Ok) {
        return error;
    }
    out_decoded_data = std::string(decoded_data.begin(), decoded_data.end());
    return Error::Ok;
}

inline Error encode_base64(const std::vector<uint8_t>& data, std::string& out_encoded_data) {
    //ref: https://docs.openssl.org/3.0/man3/EVP_EncodeInit/
    int len = data.size();
    
    // Over-allocate - base64 is ~33% larger, so 2x input is definitely enough
    std::vector<unsigned char> out(len * 2);
    
    int outlen = EVP_EncodeBlock(out.data(), data.data(), len);
    if (outlen < 0) {
        LOG_ERROR("Failed to encode base64 data. OpenSSL error: " << get_openssl_error());
        return Error::InternalError;
    }
    
    out_encoded_data = std::string(reinterpret_cast<char*>(out.data()), outlen);
    return Error::Ok;
}

inline Error encode_base64(const std::string &data, std::string& out_encoded_data) {
    std::vector<uint8_t> data_bytes(data.begin(), data.end());
    return encode_base64(data_bytes, out_encoded_data);
}

/**
 * @brief Converts a hexadecimal string to a vector of bytes.
 * @param hex The hexadecimal string to convert.
 * @return A vector of bytes derived from the input hex string.
 */
static std::vector<uint8_t> hex_string_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}


/**
 * @brief Converts a vector of bytes to its hexadecimal string representation.
 * @param data The vector of bytes to convert.
 * @return A string containing the hexadecimal representation of the input data.
 */
static std::string to_hex_string(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        ss << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return ss.str();
}

/**
 * @brief Converts a single byte to its hexadecimal string representation.
 * @param byte The byte to convert.
 * @return A string containing the two-character hexadecimal representation of the input byte.
 */
static std::string to_hex_string(uint8_t byte) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned int>(byte);
    return ss.str();
}

/**
 * @brief Converts a 16-bit integer to its hexadecimal string representation.
 * @param value The 16-bit integer to convert.
 * @return A string containing the four-character hexadecimal representation of the input value.
 */
static std::string to_hex_string(uint16_t value) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(4) << value;
    return ss.str();
}

/**
 * @brief Converts an array of bytes to its hexadecimal string representation.
 * @tparam N The size of the array.
 * @param data The array of bytes to convert.
 * @return A string containing the hexadecimal representation of the input data.
 */
template<size_t N>
std::string to_hex_string(const std::array<uint8_t, N>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        ss << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return ss.str();
}

/**
 * @brief Converts a timestamp to human readable string
 * @param timestamp The timestamp to convert
 * @param out_formatted_time The output string containing the formatted time
 * @return Error::Ok on success, Error::InternalError on failure
 */
inline Error format_time(time_t timestamp, std::string& out_formatted_time) {
    if (timestamp <= 0) {
        LOG_ERROR("Invalid timestamp: " << timestamp);
        return Error::InternalError;
    }
    
    struct tm* tm_info = gmtime(&timestamp);
    if (tm_info == nullptr) {
        if (errno == EOVERFLOW) {
            LOG_ERROR("gmtime() failed: timestamp too large to represent: " << timestamp);
        } else {
            LOG_ERROR("gmtime() failed for timestamp: " << timestamp);
        }
        return Error::InternalError;
    }
    
    char buffer[80];
    size_t result = strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S UTC", tm_info);
    if (result == 0) {
        LOG_ERROR("strftime() failed to format timestamp: " << timestamp);
        return Error::InternalError;
    }
    
    out_formatted_time = std::string(buffer);
    return Error::Ok;
}

inline Error remove_null_terminators(std::string& str) {
    size_t null_pos = str.find('\0');
    if (null_pos != std::string::npos) {
        str = str.substr(0, null_pos);
    }
    return Error::Ok;
}

inline Error generate_nonce(std::vector<uint8_t>& out_nonce) {
    size_t num_bytes = out_nonce.size();
    if (num_bytes < MIN_VALID_NONCE_LEN) {
        LOG_ERROR("Requested nonce length " << num_bytes << " is too short. Minimum viable nonce length is " << MIN_VALID_NONCE_LEN << " bytes.");
        return Error::BadArgument;
    }
    unsigned char* buffer = out_nonce.data();
    int result = RAND_bytes(buffer, num_bytes);
    if (result != 1) {
        LOG_ERROR("Failed to generate a secure random nonce. OpenSSL error: " << get_openssl_error());
        return Error::InternalError;
    }
    return Error::Ok;
}

/**
 * @brief Reads a little-endian integer value from a byte buffer.
 * @tparam T The integer type to read (e.g., uint16_t, uint32_t).
 * @param buffer The byte buffer to read from.
 * @param offset The starting offset in the buffer.
 * @param num_bytes The number of bytes to read for the value (e.g., 2 for uint16_t, 3 for a 24-bit value).
 * @param[out] out_value Reference to store the read value.
 * @return True on success, false if the buffer is too small or other errors occur.
 */
template<typename T>
bool read_little_endian(const std::vector<uint8_t>& buffer, size_t offset, size_t num_bytes, T& out_value) {
    if (offset + num_bytes > buffer.size()) {
        // Error should be logged by the caller who has more context.
        return false;
    }
    // Ensure num_bytes is not larger than what T can hold to prevent overflow issues,
    // though standard integer types will typically handle this via truncation if T is smaller.
    // For safety, one might add: if (num_bytes > sizeof(T)) { return false; }
    // However, for specific cases like 3 bytes into uint32_t, this is fine.

    out_value = 0;
    for (size_t i = 0; i < num_bytes; ++i) {
        out_value |= static_cast<T>(buffer[offset + i]) << (i * 8);
    }
    return true;
}

/**
 * @brief Deserializes an optional JSON field to a shared_ptr<T>
 * @tparam T The type to deserialize to
 * @param j The JSON object to read from
 * @param field_name The name of the field to read
 * @return shared_ptr<T> containing the value if field exists and is not null, nullptr otherwise
 */
template<typename T>
std::shared_ptr<T> deserialize_optional_shared_ptr(const nlohmann::json& j, const std::string& field_name) {
    if (j.contains(field_name) && !j.at(field_name).is_null()) {
        return std::make_shared<T>(j.at(field_name).get<T>());
    }
    return nullptr;
}

/**
 * @brief Serializes a shared_ptr<T> to JSON
 * @tparam T The type contained in the shared_ptr
 * @param ptr The shared_ptr to serialize
 * @return nlohmann::json value (null if ptr is nullptr, otherwise the dereferenced value)
 */
template<typename T>
nlohmann::json serialize_optional_shared_ptr(const T* ptr) {
    if (ptr != nullptr) {
        return *ptr;
    }
    return nullptr;
}

template<typename T>
inline Error serialize_to_json(T& value, std::string& out_string) {
    try {
        nlohmann::json json = value; // automatic conversion
        out_string = json.dump();
        return Error::Ok;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to serialize to JSON: " << e.what());
        return Error::InternalError;
    } catch (...) {
        LOG_ERROR("Unknown error occurred during JSON serialization");
        return Error::InternalError;
    }

}

template<typename T>
inline Error deserialize_from_json(const std::string& json_string, T& out_value) {
    try {
        nlohmann::json json = nlohmann::json::parse(json_string);
        out_value = json.get<T>();
        return Error::Ok;
    } catch (const nlohmann::json::exception& e) {
        LOG_ERROR("Failed to deserialize from JSON: " << e.what());
        return Error::InternalError;
    }
}

inline Error copy_string_to_buffer(std::string str, char* buffer, size_t buffer_len) {
    auto size = str.size();
    auto size_null_term = size + 1;
    if (size_null_term > buffer_len) {
        LOG_ERROR("Provided buffer length " << buffer_len << " is not large enough to hold string of size " << size_null_term);
        return Error::BadArgument;
    }
    memcpy(buffer, str.c_str(), size);
    buffer[size] = '\0';
    return Error::Ok;
}

inline Error parse_uri(
    const std::string& url,
    std::string& out_scheme,
    std::string& out_host,
    std::string& out_port,
    std::string& out_path
    ) {
    CURLU *handle = curl_url();
    if (!handle) {
        LOG_ERROR("Failed to create curl URL handle");
        return Error::InternalError;
    }
    
    CURLUcode result = curl_url_set(handle, CURLUPART_URL, url.c_str(), 0);
    if (result != CURLUE_OK) {
        LOG_ERROR("Failed to parse URL: " << curl_url_strerror(result));
        curl_url_cleanup(handle);
        return Error::BadArgument;
    }
    
    char *scheme = nullptr;
    result = curl_url_get(handle, CURLUPART_SCHEME, &scheme, 0);
    if (result == CURLUE_OK) {
        out_scheme = scheme;
        curl_free(scheme);
    } else {
        LOG_ERROR("Failed to parse scheme from OCSP URL: " << curl_url_strerror(result));
        curl_url_cleanup(handle);
        return Error::BadArgument;
    }
    
    char *host = nullptr;
    result = curl_url_get(handle, CURLUPART_HOST, &host, 0);
    if (result == CURLUE_OK) {
        out_host = host;
        curl_free(host);
    } else {
        LOG_ERROR("Failed to parse host from OCSP URL: " << curl_url_strerror(result));
        curl_url_cleanup(handle);
        return Error::BadArgument;
    }
    
    char *port = nullptr;
    result = curl_url_get(handle, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT);
    if (result == CURLUE_OK) {
        out_port = port;
        curl_free(port);
    } else {
        LOG_ERROR("Failed to parse port from OCSP URL: " << curl_url_strerror(result));
        curl_url_cleanup(handle);
        return Error::BadArgument;
    }

    char *path = nullptr;
    result = curl_url_get(handle, CURLUPART_PATH, &path, CURLU_URLDECODE);
    if (result == CURLUE_OK) {
      out_path = path;
      curl_free(path);
    } else {
      LOG_ERROR("Failed to parse path from OCSP URL: " << curl_url_strerror(result));
      curl_url_cleanup(handle);
      return Error::BadArgument;
    }

    curl_url_cleanup(handle);
    return Error::Ok;
}

inline std::string get_env_or_default(const char* name, const char* default_value) {
    const char* env_val = std::getenv(name);
    if (env_val == nullptr || strlen(env_val) == 0) {
        return std::string(default_value);
    }
    return std::string(env_val);
}

template<typename T>
bool compare_shared_ptr(const std::shared_ptr<T>& lhs, const std::shared_ptr<T>& rhs) {
    if (lhs == nullptr && rhs == nullptr) return true;
    if (lhs == nullptr || rhs == nullptr) return false;
    return *lhs == *rhs;
}

inline long long time_since_epoch_ms() {
    auto now = std::chrono::system_clock::now();
    auto duration_since_epoch = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration_since_epoch).count();
}

/**
 * @brief Checks if a specified number of bytes can be read from a buffer at a given offset.
 *        Logs an error if reading is not possible.
 * @param buffer The byte buffer to check.
 * @param start_offset The starting offset in the buffer.
 * @param bytes_to_read The number of bytes to check for readability.
 * @param field_name The name of the field being parsed, for logging purposes.
 * @return True if the bytes can be read, false otherwise.
 */
static bool can_read_buffer(const std::vector<uint8_t>& buffer, size_t start_offset, size_t bytes_to_read, const char* field_name) {
    if (start_offset + bytes_to_read > buffer.size()) {
        std::stringstream error_msg;
        error_msg << "Insufficient data for parsing field '" << field_name << "'. "
                  << "Attempted to read " << bytes_to_read << " bytes from offset " << start_offset
                  << " but remaining buffer size is only " << (buffer.size() > start_offset ? buffer.size() - start_offset : 0) << ".";
        LOG_ERROR(error_msg.str());
        return false;
    }
    return true;
}

} // namespace nvattestation