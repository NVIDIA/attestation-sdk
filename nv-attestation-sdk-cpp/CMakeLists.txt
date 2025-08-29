cmake_minimum_required(VERSION 3.11)
project(nv-attestation VERSION 0.0.0)

# set c++14
set(CMAKE_CXX_STANDARD 14 CACHE STRING 
  "The C++ standard whose features are requested to build this target."
)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON CACHE STRING
  "Specify whether to treat warnings on compile as errors."
)

option(BUILD_SHARED_LIBS "Default to shared libraries instead of static libraries" ON)
option(BUILD_EXAMPLES "Whether to build executables in examples folder" OFF)
option(BUILD_TESTING "Whether to build unit-tests and integration-tests" OFF)
option(ENABLE_NVML "Enable NVML support for GPU attestation" OFF)
option(ENABLE_NSCQ "Enable NSCQ support for SWITCH Attestation" OFF)
option(SANITIZER "Select a sanitizer [thread|address|undefined|leak|OFF]" OFF)

include(CTest)
include(GNUInstallDirs)
include(FetchContent)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    # Use a tag that has a fix for https://github.com/corrosion-rs/corrosion/issues/590
    GIT_TAG 6be991bb34c348dfb8344be22f3606288ea5c7fd
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(Corrosion)

FetchContent_Declare(
  regorus
  GIT_REPOSITORY https://github.com/microsoft/regorus.git
  GIT_TAG regorus-v0.4.0
)
FetchContent_MakeAvailable(regorus)

corrosion_import_crate(
  # Path to <regorus-source-folder>/bindings/ffi/Cargo.toml
  MANIFEST_PATH "${regorus_SOURCE_DIR}/bindings/ffi/Cargo.toml"
  # Always build regorus in Release mode.
  PROFILE "release"
  # Only build the "regorus-ffi" crate.
  CRATES regorus-ffi

  # Select specific features in regorus.
  FEATURES "regorus/semver"
  
  # Link statically
  CRATE_TYPES "staticlib"
)

# Set JWT-CPP options before fetching
set(JWT_DISABLE_PICOJSON ON CACHE BOOL "Disable picojson support in jwt-cpp")
set(JWT_BUILD_EXAMPLES OFF CACHE BOOL "Disable building jwt-cpp examples")

FetchContent_Declare(
  jwt-cpp
  GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
  GIT_TAG v0.7.1
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
# jwt-cpp is advertised as a c++11 library. but it somehow uses c++17 features, 
# but it should work with c++14 also. so disable this warning.
target_compile_options(own-jwt-cpp INTERFACE -Wno-c++17-extensions)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(json)


find_package(CURL REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(xmlsec REQUIRED)

if(ENABLE_NVML)
  message("-- Building with NVML support")
  find_package(Nvml REQUIRED)
  add_compile_definitions(ENABLE_NVML)
endif()

if(ENABLE_NSCQ)
  message("-- Building with NSCQ support")
  find_package(Nscq REQUIRED)
  add_compile_definitions(ENABLE_NSCQ)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -pedantic)
if (CMAKE_VERSION VERSION_LESS 3.24.0 AND CMAKE_COMPILE_WARNING_AS_ERROR)
  add_compile_options(-Werror)
endif()
# TODO: Remove this and handle problems before GA.
#       Unused params and variables natural during development.
add_compile_options(-Wno-unused -Wno-unused-parameter)

# Add debug flags if Debug build or any sanitizer is used
if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR (SANITIZER AND NOT SANITIZER STREQUAL "OFF"))
  add_compile_options(-g3 -O0 -fno-omit-frame-pointer)
endif()

# Make __FILE__ relative to source directory for logging
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-ffile-prefix-map=${CMAKE_SOURCE_DIR}/src/=)
endif()

configure_file("include/nvat.h.in" "include/nvat.h")

add_library(nvat
  src/nvat.cpp
  src/attestation.cpp
  src/claims.cpp
  src/claims_evaluator.cpp
  src/error.cpp
  src/gpu/evidence.cpp
  src/gpu/claims.cpp
  src/gpu/nvml_client.cpp
  src/gpu/verify.cpp
  src/spdm/spdm_measurement_records.cpp
  src/spdm/spdm_opaque_data_parser.cpp
  src/gpu/spdm/gpu_opaque_data_parser.cpp
  src/spdm/spdm_req.cpp
  src/spdm/spdm_resp.cpp
  src/init.cpp
  src/log.cpp 
  src/nv_x509.cpp
  src/rego_engine/regorus_rego_engine.cpp
  src/rim.cpp 
  src/switch/evidence.cpp
  src/switch/nscq_client.cpp
  src/switch/claims.cpp
  src/switch/verify.cpp
  src/verify.cpp
  src/switch/spdm/switch_opaque_data_parser.cpp
  src/nv_http.cpp
  src/nv_jwt.cpp
  src/utils.cpp
)

set(NV_ATTESTATION_SOVERSION 0)
set_target_properties(nvat PROPERTIES
  VERSION "${PROJECT_VERSION}"
  SOVERSION "${NV_ATTESTATION_SOVERSION}"
)

target_include_directories(nvat 
  PUBLIC
    $<$<BOOL:${ENABLE_NVML}>:${Nvml_INCLUDE_DIR}>
    $<$<BOOL:${ENABLE_NSCQ}>:${Nscq_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  PRIVATE
    src
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>  
    ${regorus_SOURCE_DIR}/bindings/ffi
)

if (SANITIZER)
  message("-- Building with sanitizer: ${SANITIZER}")
  target_compile_options(nvat PRIVATE -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
  target_link_options(nvat PRIVATE -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
endif()

if (BUILD_EXAMPLES)
  message("-- Building with examples")
  add_subdirectory(examples)
endif()

if (BUILD_TESTING)
  message("-- Building with tests")
  enable_testing()
  add_subdirectory(unit-tests)
  add_subdirectory(integration-tests)
endif()

#todo: how to handle cases where client links against the same 
#dependency, but a different version of it? what if that dependency
#has global state that causes conficts if the client modifies that 
#global state? we can maybe provide a check function that verifies 
#that all the loaded libraries are of correct version. maybe cmake
#has support for this.
# why public: https://stackoverflow.com/questions/26037954/cmake-target-link-libraries-interface-dependencies
#https://stackoverflow.com/questions/69783203/examples-of-when-public-private-interface-should-be-used-in-cmake
target_link_libraries(nvat
  PUBLIC
    $<$<BOOL:${ENABLE_NVML}>:${Nvml_LIBRARY}>
    $<$<BOOL:${ENABLE_NSCQ}>:${Nscq_LIBRARY}>
    spdlog::spdlog
    xmlsec::xmlsec
    xmlsec::xmlsec-openssl
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    LibXml2::LibXml2
  PRIVATE
    own-jwt-cpp
    nlohmann_json::nlohmann_json
    regorus_ffi
)

# Ensure regorus_ffi is built before nvat to generate header files
add_dependencies(nvat regorus_ffi)

install(TARGETS nvat
  EXPORT nvatTargets
  ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT Development
  LIBRARY
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT Runtime
    NAMELINK_COMPONENT Development
  RUNTIME
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT Runtime
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/include/nvat.h"
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT Development
)

install(EXPORT nvatTargets
  FILE nvatTargets.cmake
  NAMESPACE nvat::
  DESTINATION ${CMAKE_INSTALL_DATADIR}/cmake/nvat
  COMPONENT Development
)

install(FILES
    cmake/FindLibXml2.cmake
    cmake/FindNvml.cmake
    cmake/Findxmlsec.cmake
    DESTINATION ${CMAKE_INSTALL_DATADIR}/cmake/nvat/Modules
    COMPONENT Development
)

include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/Config.cmake.in nvatConfig.cmake
  INSTALL_DESTINATION "${CMAKE_INSTALL_DATADIR}/cmake/nvat"
  NO_SET_AND_CHECK_MACRO
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/nvatConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/nvatConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/nvatConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_DATADIR}/cmake/nvat
  COMPONENT Development
)

include(CPack)
