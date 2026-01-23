cmake_minimum_required(VERSION 3.11)
project(nvattest VERSION 1.0.0)

option(BUILD_TESTING "Build tests" OFF)
option(USE_SYSTEM_NVAT "Compile and link to the system nvat library. If OFF, nvat will be built from source." OFF)

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
)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(CLI11 json)

add_executable(nvattest
    src/main.cpp
    src/version.cpp
    src/attest.cpp
    src/collect_evidence.cpp
    src/utils.cpp
    src/logging.cpp
)

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
    ${spdlog_SOURCE_DIR}/include
    ${fmt_SOURCE_DIR}/include
)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS nvattest DESTINATION ${CMAKE_INSTALL_BINDIR})

include(CPack)
