cmake_minimum_required(VERSION 3.11)
project(nvattest VERSION 2.0.0)

option(BUILD_TESTING "Build tests" OFF)
option(USE_SYSTEM_NVAT "Compile and link to the system nvat library. If OFF, nvat will be built from source." OFF)
option(ENABLE_COVERAGE "Enable LLVM source-based code coverage instrumentation" OFF)
if(ENABLE_COVERAGE)
    add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
    add_link_options(-fprofile-instr-generate)
endif()

option(SANITIZER "Select a sanitizer [thread|address|undefined|leak|OFF]" OFF)

option(ENABLE_SCCACHE "Enable sccache" OFF)
if(ENABLE_SCCACHE)
    find_program(SCCACHE sccache REQUIRED)
    set(CMAKE_C_COMPILER_LAUNCHER ${SCCACHE})
    set(CMAKE_CXX_COMPILER_LAUNCHER ${SCCACHE})
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

include(CTest)
include(GNUInstallDirs)
include(FetchContent)

FetchContent_Declare(
    CLI11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.6.1
    GIT_SHALLOW TRUE
)

FetchContent_Declare(json GIT_REPOSITORY https://github.com/nlohmann/json.git GIT_TAG v3.12.0 GIT_SHALLOW TRUE EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(CLI11 json)

add_executable(nvattest
    src/main.cpp
    src/version.cpp
    src/attest.cpp
    src/attest_v2.cpp
    src/ear_status.cpp
    src/collect_evidence.cpp
    src/verify_token.cpp
    src/verify_token_output.cpp
    src/collect_evidence_v2.cpp
    src/utils.cpp
    src/logging.cpp
)

# Set full version with build timestamp if provided, otherwise use PROJECT_VERSION
if(DEFINED BUILD_TIMESTAMP AND NOT BUILD_TIMESTAMP STREQUAL "")
    set(NVATTEST_FULL_VERSION "${PROJECT_VERSION}+${BUILD_TIMESTAMP}")
else()
    set(NVATTEST_FULL_VERSION "${PROJECT_VERSION}")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version_config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/version_config.h)

# nvat dependency: either use an installed libnvat.so or build the SDK from source.
if(USE_SYSTEM_NVAT)
    # Use helper to locate installed libnvat + headers (no installed CMake package files).
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../nv-attestation-sdk-cpp/cmake")
    include(nvat_locate_installed)
    nvat_locate_installed()

    # CLI tests (when built as a subdirectory) use NVAT_SDK_INCLUDE_DIR for nvat.h.
    set(NVAT_SDK_INCLUDE_DIR "${NVAT_INCLUDE_DIR}")

    # Fetch spdlog/fmt for header access only (libnvat has them statically linked).
    FetchContent_Declare(
        fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        GIT_TAG 10.2.1
        GIT_SHALLOW TRUE
    )
    FetchContent_Declare(
        spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.14.1
        GIT_SHALLOW TRUE
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
else()
    set(NVAT_SDK_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/nv-attestation-sdk-build")
    set(NVAT_SDK_INCLUDE_DIR ${NVAT_SDK_BUILD_DIR}/include)

    add_subdirectory(
        "${CMAKE_CURRENT_SOURCE_DIR}/../nv-attestation-sdk-cpp"  # Source directory
        "${NVAT_SDK_BUILD_DIR}"                                  # Binary directory
    )
    if(NOT TARGET nvat::nvat)
        add_library(nvat::nvat ALIAS nvat)
    endif()

    # FetchContent variables are directory-scoped; fetch the populated source dirs for header access.
    # this is necessary because we need the fmt and spdlog headers
    # because they are statically linked in the SDK, we just need their
    # headers and not the binary. we get use these properties
    # to get the path to their headers
    FetchContent_GetProperties(fmt)
    FetchContent_GetProperties(spdlog)
    if(NOT fmt_POPULATED OR NOT spdlog_POPULATED)
        message(FATAL_ERROR "Expected fmt/spdlog to be populated by the SDK build, but they were not.")
    endif()
endif()

target_link_libraries(nvattest PRIVATE
    nvat::nvat
    nlohmann_json::nlohmann_json
    CLI11::CLI11
)

# spdlog/fmt headers needed for compilation (nvat has them statically linked, no need to link again)
target_include_directories(nvattest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_include_directories(nvattest SYSTEM PRIVATE
    ${spdlog_SOURCE_DIR}/include
    ${fmt_SOURCE_DIR}/include
)

# Instrument the nvattest binary itself. The CLI tests drive nvattest as a child
# process, so sanitizing only the test executable would never see a leak here.
if (SANITIZER)
    message("-- Building nvattest with sanitizer: ${SANITIZER}")
    target_compile_options(nvattest PRIVATE -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
    target_link_options(nvattest PRIVATE -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
endif()

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS nvattest DESTINATION ${CMAKE_INSTALL_BINDIR})

include(CPack)
