cmake_minimum_required(VERSION 3.11)
project(nvattest VERSION 0.1.0)

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
    GIT_TAG v2.3.2
)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(CLI11 json)

add_executable(nvattest
    src/main.cpp
    src/version.cpp
    src/attest.cpp
    src/collect_evidence.cpp
    src/utils.cpp
)

find_package(spdlog REQUIRED)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.toml
               ${CMAKE_CURRENT_BINARY_DIR}/config.toml
               COPYONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version_config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/version_config.h)

if(USE_SYSTEM_NVAT)
    find_package(nvat REQUIRED)
else()
    add_subdirectory(
        "${CMAKE_CURRENT_SOURCE_DIR}/../nv-attestation-sdk-cpp"  # Source directory
        "${CMAKE_CURRENT_BINARY_DIR}/nv-attestation-sdk-build"   # Binary directory
    )
    add_library(nvat::nvat ALIAS nvat)
endif()

target_link_libraries(nvattest PRIVATE
    nvat::nvat
    nlohmann_json::nlohmann_json
    CLI11::CLI11
    spdlog::spdlog
)

target_include_directories(nvattest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS nvattest DESTINATION ${CMAKE_INSTALL_BINDIR})

include(CPack)
