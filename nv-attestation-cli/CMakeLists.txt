cmake_minimum_required(VERSION 3.11)
project(nvattest VERSION 0.0.0)

option(BUILD_TESTING "Build tests" OFF)

# set c++11
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

# Add debug flags when building in Debug mode
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

include(CTest)
include(GNUInstallDirs)
include(FetchContent)

# Declare external dependencies
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
)

find_package(spdlog REQUIRED)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.toml
               ${CMAKE_CURRENT_BINARY_DIR}/config.toml
               COPYONLY)

# Generate version header from template
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version_config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/version_config.h)

# TODO - Link against installed nv attestation sdk cpp instead of directly to the source code
add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/../nv-attestation-sdk-cpp"  # Source directory
    "${CMAKE_CURRENT_BINARY_DIR}/nv-attestation-sdk-build"   # Binary directory
)

# Create namespaced alias for the nvat target added by the SDK subdirectory
add_library(nvat::nvat ALIAS nvat)

target_link_libraries(nvattest PRIVATE
    nvat::nvat
    nlohmann_json::nlohmann_json
    CLI11::CLI11
    spdlog::spdlog
)

# Add the binary directory to the include path for the generated version header
target_include_directories(nvattest PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

# Only build tests if BUILD_TESTING is enabled
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS nvattest DESTINATION ${CMAKE_INSTALL_BINDIR})

include(CPack)