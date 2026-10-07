cmake_minimum_required(VERSION 3.11)
project(nv-attestation-fuzz-tests)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "Fuzz tests require clang (libFuzzer is built into clang)")
endif()

find_package(CURL REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(xmlsec REQUIRED)

# spdlog/fmt headers are statically linked into nvat — we only need the headers for compilation.
FetchContent_GetProperties(fmt)
if(NOT fmt_POPULATED)
  FetchContent_Populate(fmt)
endif()
FetchContent_GetProperties(spdlog)
if(NOT spdlog_POPULATED)
  FetchContent_Populate(spdlog)
endif()

# nlohmann/json is needed to compile some SDK headers.
FetchContent_Declare(json GIT_REPOSITORY https://github.com/nlohmann/json.git GIT_TAG v3.12.0 GIT_SHALLOW TRUE EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(json)

option(SANITIZER "Select a sanitizer" OFF)

# Helper to define one fuzz executable.
#
# Each target gets:
#   - -fsanitize=fuzzer (required for LLVMFuzzerTestOneInput)
#   - Optional additional sanitizer from SANITIZER option (e.g. address, undefined)
#   - BUILD_RPATH pointing at libnvat.so so the binary runs without LD_LIBRARY_PATH
function(add_fuzz_target TARGET_NAME SOURCE_FILE)
  add_executable(${TARGET_NAME} ${SOURCE_FILE})

  target_include_directories(${TARGET_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${regorus_SOURCE_DIR}/bindings/ffi
  )
  target_include_directories(${TARGET_NAME} SYSTEM PRIVATE
    ${spdlog_SOURCE_DIR}/include
    ${fmt_SOURCE_DIR}/include
  )

  target_compile_options(${TARGET_NAME} PRIVATE
    -fsanitize=fuzzer
    -Wno-unused
    -Wno-c++17-attribute-extensions
    -Wno-c++17-extensions
  )
  target_link_options(${TARGET_NAME} PRIVATE -fsanitize=fuzzer)

  if(SANITIZER)
    target_compile_options(${TARGET_NAME} PRIVATE
      -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
    target_link_options(${TARGET_NAME} PRIVATE
      -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
  endif()

  target_link_libraries(${TARGET_NAME} PRIVATE
    nvat
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    LibXml2::LibXml2
    xmlsec::xmlsec
    xmlsec::xmlsec-openssl
    nlohmann_json::nlohmann_json
  )

  set_target_properties(${TARGET_NAME} PROPERTIES
    BUILD_RPATH "$<TARGET_FILE_DIR:nvat>"
  )
endfunction()

# ---------------------------------------------------------------------------
# Tier 1 — SPDM binary protocol parsers
# ---------------------------------------------------------------------------
add_fuzz_target(fuzz_spdm_resp         fuzz_spdm_resp.cpp)
add_fuzz_target(fuzz_spdm_req          fuzz_spdm_req.cpp)
add_fuzz_target(fuzz_opaque_data       fuzz_opaque_data.cpp)
add_fuzz_target(fuzz_gpu_opaque        fuzz_gpu_opaque.cpp)
add_fuzz_target(fuzz_switch_opaque     fuzz_switch_opaque.cpp)

# ---------------------------------------------------------------------------
# Tier 2 — Crypto / X.509
# ---------------------------------------------------------------------------
add_fuzz_target(fuzz_x509_pkcs11_sig   fuzz_x509_pkcs11_sig.cpp)
add_fuzz_target(fuzz_x509_from_cert    fuzz_x509_from_cert.cpp)
add_fuzz_target(fuzz_x509_cert_chain   fuzz_x509_cert_chain.cpp)

# ---------------------------------------------------------------------------
# Tier 3 — XML / utilities
# ---------------------------------------------------------------------------
add_fuzz_target(fuzz_rim_document      fuzz_rim_document.cpp)
add_fuzz_target(fuzz_hex_to_bytes      fuzz_hex_to_bytes.cpp)

# ---------------------------------------------------------------------------
# Tier 4 — CoRIM (CBOR + COSE)
# ---------------------------------------------------------------------------
add_fuzz_target(fuzz_corim_unsigned    fuzz_corim_unsigned.cpp)
add_fuzz_target(fuzz_corim_signed      fuzz_corim_signed.cpp)
add_fuzz_target(fuzz_corim_comid       fuzz_corim_comid.cpp)

# ---------------------------------------------------------------------------
# Tier 5 — EAT (CBOR claims-set + CWT/COSE tag stack)
# ---------------------------------------------------------------------------
add_fuzz_target(fuzz_eat               fuzz_eat.cpp)
add_fuzz_target(fuzz_eat_signed        fuzz_eat_signed.cpp)

# Copy dictionaries to the build directory. Seed corpora are populated
# separately by fuzz-tests/generate_corpus.py (invoked from the Makefile's
# generate-fuzz-corpus target).
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/dict
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
