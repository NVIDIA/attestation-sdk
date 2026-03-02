cmake_minimum_required(VERSION 3.11)
project(nv-attestation-cli-tests)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../nv-attestation-sdk-cpp/cmake")
include(nvat_fetch_gtest)

option(SANITIZER "Select a sanitizer" OFF)

add_executable(nv-attestation-cli-tests
    main.cpp
    attest_tests.cpp
    gpu_faulty_driver_rim_tests.cpp
    measurement_mismatch_tests.cpp
    trust_outpost_tests.cpp
    collect_evidence_tests.cpp
    test_utils.h
    environment.h
)

if (SANITIZER)
    target_compile_options(nv-attestation-cli-tests PRIVATE -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
    target_link_options(nv-attestation-cli-tests PRIVATE -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
endif()
target_compile_options(nv-attestation-cli-tests PRIVATE -Wno-unused -Wno-c++17-attribute-extensions)

include(FetchContent)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(json)

FetchContent_Declare(
    cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.4.2
)
FetchContent_MakeAvailable(cli11)

# Fetch spdlog/fmt for header access only (nvat has them statically linked)
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

target_link_libraries(nv-attestation-cli-tests PRIVATE
    GTest::gtest
    GTest::gmock
    nlohmann_json::nlohmann_json
    CLI11::CLI11
)

# spdlog/fmt headers needed for compilation (nvat has them statically linked, no need to link again)
target_include_directories(nv-attestation-cli-tests PRIVATE
    ${spdlog_SOURCE_DIR}/include
    ${fmt_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

# nvat.h is needed for result codes used by the tests, but the test executable must not link to libnvat.
if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # Standalone mode: CMake file is being run directly.
    # Use the cmake helper to locate the installed SDK headers.
    # nvat_locate_installed() sets NVAT_INCLUDE_DIR to the directory containing nvat.h
    include(CTest)
    enable_testing()
    include(nvat_locate_installed)
    nvat_locate_installed()

    target_include_directories(nv-attestation-cli-tests PRIVATE
        ${NVAT_INCLUDE_DIR}
    )
else()
    # Build-tree mode: invoked as subdirectory from nv-attestation-cli/CMakeLists.txt.
    # NVAT_SDK_INCLUDE_DIR is set by the parent CMakeLists.txt pointing to the SDK build tree headers.
    target_include_directories(nv-attestation-cli-tests PRIVATE
        ${NVAT_SDK_INCLUDE_DIR}
    )

    # nvattest target only exists when built as part of the parent.
    add_dependencies(nv-attestation-cli-tests nvattest)
endif()

include(GoogleTest)
gtest_discover_tests(nv-attestation-cli-tests PROPERTIES LABELS "cli"
    XML_OUTPUT_DIR ${CMAKE_BINARY_DIR}/test-results
)