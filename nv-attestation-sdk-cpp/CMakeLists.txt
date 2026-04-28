cmake_minimum_required(VERSION 3.11)
project(nv-attestation VERSION 1.2.0)

set(CMAKE_CXX_STANDARD 14 CACHE STRING
  "The C++ standard whose features are requested to build this target."
)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON CACHE STRING
  "Specify whether to treat warnings on compile as errors."
)

option(BUILD_SHARED_LIBS "Default to shared libraries instead of static libraries" ON)
option(BUILD_EXAMPLES "Whether to build executables in examples folder" OFF)
option(BUILD_TESTING "Whether to build unit-tests" OFF)
option(SANITIZER "Select a sanitizer [thread|address|undefined|leak|OFF]" OFF)
option(ENABLE_SCCACHE "Enable sccache" OFF)

if (ENABLE_SCCACHE)
    find_program(SCCACHE sccache REQUIRED)

    set(CMAKE_C_COMPILER_LAUNCHER ${SCCACHE})
    set(CMAKE_CXX_COMPILER_LAUNCHER ${SCCACHE})

    if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.25")
        set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug,RelWithDebInfo>:Embedded>")
        cmake_policy(SET CMP0141 NEW)
    endif()
endif()

include(CTest)
include(GNUInstallDirs)
include(FetchContent)
include(ExternalProject)

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24")
    cmake_policy(SET CMP0135 NEW)
endif()

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
  MANIFEST_PATH "${regorus_SOURCE_DIR}/bindings/ffi/Cargo.toml"
  PROFILE "release"
  CRATES regorus-ffi
  FEATURES "regorus/semver"
  CRATE_TYPES "staticlib"
)

if (ENABLE_SCCACHE)
  corrosion_set_env_vars(regorus_ffi "RUSTC_WRAPPER=${SCCACHE}")
endif()

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

# Build fmt and spdlog as static libraries with PIC (needed for linking into shared libs)
# Save current settings
set(BUILD_SHARED_LIBS_SAVED ${BUILD_SHARED_LIBS})
set(CMAKE_POSITION_INDEPENDENT_CODE_SAVED ${CMAKE_POSITION_INDEPENDENT_CODE})

# Force static build with PIC for both fmt and spdlog
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Build fmt as static library (spdlog depends on it)
set(FMT_INSTALL OFF CACHE BOOL "Don't install fmt headers" FORCE)
FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 10.2.1
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(fmt)

# Build spdlog as static library using our fetched fmt
set(SPDLOG_INSTALL OFF CACHE BOOL "Don't install spdlog headers" FORCE)
set(SPDLOG_FMT_EXTERNAL ON CACHE BOOL "Use external fmt library" FORCE)
set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "Build spdlog as static library" FORCE)
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.14.1
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(spdlog)

# Restore original settings
set(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_SAVED})
set(CMAKE_POSITION_INDEPENDENT_CODE ${CMAKE_POSITION_INDEPENDENT_CODE_SAVED})

set(_EP_CC "${CMAKE_C_COMPILER}")
set(_EP_CFLAGS "${CMAKE_C_FLAGS} -fPIC")

# Build OpenSSL statically — RHEL8 ships 1.1.1 but the code needs 3.x APIs
set(OPENSSL_INSTALL_DIR "${CMAKE_BINARY_DIR}/openssl-install")

ExternalProject_Add(openssl_external
  URL https://github.com/openssl/openssl/releases/download/openssl-3.6.1/openssl-3.6.1.tar.gz
  URL_HASH SHA256=b1bfedcd5b289ff22aee87c9d600f515767ebf45f77168cb6d64f231f518a82e
  CONFIGURE_COMMAND <SOURCE_DIR>/Configure
    "CC=${_EP_CC}"
    "CFLAGS=${_EP_CFLAGS}"
    --prefix=${OPENSSL_INSTALL_DIR}
    --openssldir=${OPENSSL_INSTALL_DIR}
    --libdir=lib
    no-shared
  BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
  INSTALL_COMMAND make install_sw install_ssldirs
  BUILD_IN_SOURCE 1
)

set(OPENSSL_INCLUDE_DIR "${OPENSSL_INSTALL_DIR}/include")
file(MAKE_DIRECTORY "${OPENSSL_INCLUDE_DIR}")

add_library(OpenSSL::Crypto STATIC IMPORTED)
set_target_properties(OpenSSL::Crypto PROPERTIES
  IMPORTED_LOCATION "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a"
  INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
  INTERFACE_LINK_LIBRARIES "dl;pthread"
)

add_library(OpenSSL::SSL STATIC IMPORTED)
set_target_properties(OpenSSL::SSL PROPERTIES
  IMPORTED_LOCATION "${OPENSSL_INSTALL_DIR}/lib/libssl.a"
  INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
  INTERFACE_LINK_LIBRARIES "OpenSSL::Crypto"
)

# Build xmlsec 1.2.39 statically (depends on OpenSSL 3)
set(XMLSEC_INSTALL_DIR "${CMAKE_BINARY_DIR}/xmlsec-install")

ExternalProject_Add(xmlsec_external
  DEPENDS openssl_external
  URL https://github.com/lsh123/xmlsec/releases/download/xmlsec-1_2_39/xmlsec1-1.2.39.tar.gz
  URL_HASH SHA256=15f2f55ea5968e578fcd24b3b427e553876c86c147dc7f03923e98fc2768a1fa
  CONFIGURE_COMMAND <SOURCE_DIR>/configure
    --prefix=${XMLSEC_INSTALL_DIR}
    --disable-shared
    --enable-static
    --disable-crypto-dl
    --with-openssl=${OPENSSL_INSTALL_DIR}
    --without-gnutls
    --without-nss
    --without-gcrypt
    --with-libxslt=no
    --disable-docs
    --disable-apps
    "CC=${_EP_CC}"
    "CFLAGS=${_EP_CFLAGS}"
    "PKG_CONFIG_PATH=${OPENSSL_INSTALL_DIR}/lib/pkgconfig"
  BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
  INSTALL_COMMAND make install
  BUILD_IN_SOURCE 1
)

set(XMLSEC_ROOT "${XMLSEC_INSTALL_DIR}" CACHE PATH "xmlsec installation directory" FORCE)

# Build libcurl statically — RHEL8 ships 7.61 but the code needs the URL API (>= 7.62)
set(CURL_INSTALL_DIR "${CMAKE_BINARY_DIR}/curl-install")

ExternalProject_Add(curl_external
  DEPENDS openssl_external
  URL https://github.com/curl/curl/releases/download/curl-7_88_1/curl-7.88.1.tar.gz
  URL_HASH SHA256=cdb38b72e36bc5d33d5b8810f8018ece1baa29a8f215b4495e495ded82bbf3c7
  CONFIGURE_COMMAND <SOURCE_DIR>/configure
    --prefix=${CURL_INSTALL_DIR}
    --with-openssl=${OPENSSL_INSTALL_DIR}
    --without-libssh2
    --without-nghttp2
    --without-brotli
    --without-zstd
    --without-libidn2
    --without-librtmp
    --without-libpsl
    --disable-ldap
    --disable-shared
    --enable-static
    "CC=${_EP_CC}"
    "CFLAGS=${_EP_CFLAGS}"
    "PKG_CONFIG_PATH=${OPENSSL_INSTALL_DIR}/lib/pkgconfig"
  BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
  INSTALL_COMMAND make install
  BUILD_IN_SOURCE 1
)

set(CURL_INCLUDE_DIR "${CURL_INSTALL_DIR}/include")
file(MAKE_DIRECTORY "${CURL_INCLUDE_DIR}")

add_library(CURL::libcurl STATIC IMPORTED)
set_target_properties(CURL::libcurl PROPERTIES
  IMPORTED_LOCATION "${CURL_INSTALL_DIR}/lib/libcurl.a"
  INTERFACE_INCLUDE_DIRECTORIES "${CURL_INCLUDE_DIR}"
  INTERFACE_LINK_LIBRARIES "OpenSSL::SSL;OpenSSL::Crypto;z;pthread"
)

find_package(LibXml2 REQUIRED)
find_package(xmlsec REQUIRED)

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
  src/gpu/evidence.cpp
  src/gpu/claims.cpp
  src/gpu/nvml_client.cpp
  src/gpu/corelib_client.cpp
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
  src/nv_ocsp.cpp
  src/utils.cpp
  src/nv_cache.cpp
)

set(NV_ATTESTATION_SOVERSION ${PROJECT_VERSION_MAJOR})
set_target_properties(nvat PROPERTIES
  VERSION "${PROJECT_VERSION}"
  SOVERSION "${NV_ATTESTATION_SOVERSION}"
)

target_include_directories(nvat
  PUBLIC
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  PRIVATE
    src
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    ${regorus_SOURCE_DIR}/bindings/ffi
    # spdlog and fmt include dirs (linked statically via TARGET_FILE below)
    ${spdlog_SOURCE_DIR}/include
    ${fmt_SOURCE_DIR}/include
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
  PRIVATE
    # Keep all deps PRIVATE so consumers of libnvat.so do not need to link them.
    # (Runtime deps must still be present on the system.)
    xmlsec::xmlsec
    xmlsec::xmlsec-openssl
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    LibXml2::LibXml2
    # Use TARGET_FILE to link the static library directly without creating
    # a target dependency that CMake would try to export
    $<TARGET_FILE:spdlog>
    $<TARGET_FILE:fmt>
    own-jwt-cpp
    nlohmann_json::nlohmann_json
    regorus_ffi
)

# Ensure dependencies are built before nvat
add_dependencies(nvat regorus_ffi spdlog fmt curl_external xmlsec_external openssl_external)

# todo (p0): remove cmake configuration helpers
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

configure_file(cmake/nvat.pc.in nvat.pc @ONLY)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/nvat.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
  COMPONENT Development
)

include(CPack)
