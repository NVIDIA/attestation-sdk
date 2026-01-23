cmake_minimum_required(VERSION 3.11)
project(nv-attestation-unit-tests)

include(CTest)
include(FetchContent)

# Reuse SDK's in-repo Find-modules (not installed).
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../cmake")

find_package(GTest REQUIRED)
find_package(CURL REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(xmlsec REQUIRED)

option(SANITIZER "Select a sanitizer" OFF)

# Unit-tests need internal rego headers from regorus in both build modes.
# - Build-tree mode: SDK already fetched regorus; reuse it via inherited variables.
# - Standalone mode: populate regorus source so headers are available.
if(NOT DEFINED regorus_SOURCE_DIR)
    FetchContent_Declare(
        regorus
        GIT_REPOSITORY https://github.com/microsoft/regorus.git
        GIT_TAG regorus-v0.4.0
    )
    FetchContent_Populate(regorus)
endif()

add_executable(nv-attestation-unit-tests
    main.cpp
    rim_test.cpp
    rego_engine/regorus_rego_engine_test.cpp
    attestation_test.cpp
    claims_evaluator_test.cpp
    gpu/spdm/spdm_req_test.cpp
    gpu/spdm/spdm_resp_test.cpp
    nv_x509_test.cpp
    error_test.cpp
    gpu/evidence_test.cpp
    gpu/verifier_test.cpp
    test_utils.cpp
    utils_test.cpp
    spdm_test_utils.cpp
    switch/spdm/spdm_req_test.cpp
    switch/spdm/spdm_resp_test.cpp
    switch/evidence_test.cpp
    switch/verifier_test.cpp
    switch_test_utils.cpp
    nv_http_test.cpp
    claims_test.cpp
    nv_cache_test.cpp
) 

target_include_directories(nv-attestation-unit-tests PRIVATE 
    nv-attestation
    ${regorus_SOURCE_DIR}/bindings/ffi
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(nv-attestation-unit-tests PRIVATE -Wno-unused -Wno-c++17-attribute-extensions)
if (SANITIZER)
    target_compile_options(nv-attestation-unit-tests PRIVATE -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
    target_link_options(nv-attestation-unit-tests PRIVATE -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
endif()

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(json)

# Fetch spdlog and fmt for header access only (nvat has them statically linked)
FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG 10.2.1
)
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.14.1
)

# Just populate to get source directories for headers (don't add to build)
FetchContent_GetProperties(fmt)
if(NOT fmt_POPULATED)
    FetchContent_Populate(fmt)
endif()

FetchContent_GetProperties(spdlog)
if(NOT spdlog_POPULATED)
    FetchContent_Populate(spdlog)
endif()

find_package(jwt-cpp QUIET)

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # the unit tests can be built as part of the sdk (in which case it will 
    # link against the build tree) or it can be built standalone in which 
    # case it will link against the installed version by manually locating lib+header.
    # if running as standalone, we need to fetch jwt-cpp
    
    # ideally, in both the cases, we should be able to fetch content jwt-cpp
    # but in the sdk build jwt-cpp is handled differently from other dependencies
    # because of that,
    # we cannot fetch it again here if we build as part of the sdk.

    # therefore, we fetch it only if we build as standalone

    # Set JWT-CPP options before fetching
    set(JWT_DISABLE_PICOJSON ON CACHE BOOL "Disable picojson support in jwt-cpp")
    set(JWT_BUILD_EXAMPLES OFF CACHE BOOL "Disable building jwt-cpp examples")

    FetchContent_Declare(
    jwt-cpp
    GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
    GIT_TAG v0.7.1  # Use the latest stable version
    EXCLUDE_FROM_ALL
    )

    # the fetch content for jwt-cpp is being handled differently because 
    # it's headers were getting installed even when using EXCLUDE_FROM_ALL
    # presumably, its because jwt-cpp is not respecting all of CMAKE's rules
    # this way prevents the headers being installed when the sdk is installed 
    # the headers must not be installed because we want to just link to this 
    # statically. there is no need to add unnecessary libraries to target machines.
    FetchContent_Populate(jwt-cpp)
    add_library(own-jwt-cpp INTERFACE)
    target_include_directories(own-jwt-cpp
        INTERFACE ${jwt-cpp_SOURCE_DIR}/include)
    # jwt-cpp is advertized as a c++11 library. but it somehow uses c++17 features, 
    # but it should work with c++14 also. so disable this warning.
    target_compile_options(own-jwt-cpp INTERFACE -Wno-c++17-extensions)
endif()

target_link_libraries(nv-attestation-unit-tests PRIVATE
    GTest::gtest
    GTest::gmock
    nlohmann_json::nlohmann_json
    # Explicitly link deps needed to compile internal SDK headers (nvat deps are PRIVATE).
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    LibXml2::LibXml2
    xmlsec::xmlsec
    xmlsec::xmlsec-openssl
    # link regarless of whether we are building as part of the sdk or standalone
    # if built as part of the sdk, the cmake in sdk will have 
    # made this available.
    own-jwt-cpp
)

# spdlog/fmt headers needed for compilation (nvat has them statically linked, no need to link again)
target_include_directories(nv-attestation-unit-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${spdlog_SOURCE_DIR}/include
    ${fmt_SOURCE_DIR}/include
)

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # CMake file is being run on its own (standalone) - testing installed version of sdk
    include("${CMAKE_CURRENT_SOURCE_DIR}/../cmake/nvat_locate_installed.cmake")
    nvat_locate_installed()

    target_link_libraries(nv-attestation-unit-tests PRIVATE nvat::nvat)
else()
    # CMake file is being invoked as part of subdirectory from another CMake file
    target_link_libraries(nv-attestation-unit-tests PRIVATE nvat)
    # Make build-tree test execution reliable via ctest without LD_LIBRARY_PATH.
    set_target_properties(nv-attestation-unit-tests PROPERTIES
        BUILD_RPATH "$<TARGET_FILE_DIR:nvat>"
    )
endif()

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/testdata
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

include(GoogleTest)

gtest_discover_tests(nv-attestation-unit-tests PROPERTIES LABELS "unit"
    XML_OUTPUT_DIR ${CMAKE_BINARY_DIR}/test-results
)