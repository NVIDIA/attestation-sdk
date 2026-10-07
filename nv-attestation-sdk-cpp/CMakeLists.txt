cmake_minimum_required(VERSION 3.11)
project(nv-attestation VERSION 2.0.0)

set(CMAKE_CXX_STANDARD 14 CACHE STRING
  "The C++ standard whose features are requested to build this target."
)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON CACHE STRING
  "Specify whether to treat warnings on compile as errors."
)

option(BUILD_SHARED_LIBS "Default to shared libraries instead of static libraries" ON)
option(BUILD_EXAMPLES "Whether to build executables in examples folder" OFF)
option(BUILD_TESTING "Whether to build unit-tests" OFF)
option(BUILD_FUZZ_TESTS "Build fuzz tests (requires clang with libFuzzer)" OFF)
option(SANITIZER "Select a sanitizer [thread|address|undefined|leak|OFF]" OFF)
option(ENABLE_SCCACHE "Enable sccache" OFF)
option(ENABLE_COVERAGE "Enable LLVM source-based code coverage instrumentation" OFF)
if(ENABLE_COVERAGE)
    add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
    add_link_options(-fprofile-instr-generate)
endif()

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
    GIT_TAG v0.6.1
    GIT_SHALLOW TRUE
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(Corrosion)

FetchContent_Declare(
  regorus
  GIT_REPOSITORY https://github.com/microsoft/regorus.git
  GIT_TAG regorus-v0.4.0
  GIT_SHALLOW TRUE
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
  GIT_SHALLOW TRUE
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

FetchContent_Declare(json GIT_REPOSITORY https://github.com/nlohmann/json.git GIT_TAG v3.12.0 GIT_SHALLOW TRUE EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(json)

FetchContent_Declare(
  zcbor
  GIT_REPOSITORY https://github.com/NordicSemiconductor/zcbor.git
  GIT_TAG bd28ef9fc2abe154cb420c232910a1a9f8258114
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(zcbor)

add_library(zcbor_lib STATIC
  ${zcbor_SOURCE_DIR}/src/zcbor_decode.c
  ${zcbor_SOURCE_DIR}/src/zcbor_encode.c
  ${zcbor_SOURCE_DIR}/src/zcbor_common.c
  ${zcbor_SOURCE_DIR}/src/zcbor_print.c
)
target_include_directories(zcbor_lib PUBLIC ${zcbor_SOURCE_DIR}/include)
set_target_properties(zcbor_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ZCBOR_MAP_SMART_SEARCH changes the layout of zcbor_state_t, so the runtime and
# the generated decoders must agree. nvat links zcbor via TARGET_FILE, which does
# not propagate usage requirements, so both targets read this list.
# RFC 9052 §9 requires definite-length encoding for Sig_structure.
set(ZCBOR_ABI_DEFINITIONS ZCBOR_CANONICAL ZCBOR_MAP_SMART_SEARCH)
target_compile_definitions(zcbor_lib PUBLIC ${ZCBOR_ABI_DEFINITIONS})

# Override zcbor's logging to use our spdlog bridge
target_compile_definitions(zcbor_lib PRIVATE ZCBOR_PRINT_FUNC=nvat_zcbor_log)

target_compile_options(zcbor_lib PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/include/zcbor_logger.h)

# ZCBOR_VERBOSE only in Debug-without-sanitizer; trace macros do unchecked OOB reads.
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND (NOT SANITIZER OR SANITIZER STREQUAL "OFF"))
  target_compile_definitions(zcbor_lib PRIVATE ZCBOR_VERBOSE)
endif()

# Pre-generated zcbor decoder sources are committed under generated/ to remove the
# Python/zcbor-CLI build dependency.  Set REGENERATE_ZCBOR=ON to re-run codegen
# from the CDDL sources (requires the zcbor venv; see requirements-dev.txt).
option(REGENERATE_ZCBOR "Regenerate zcbor decoder sources from CDDL files (requires zcbor CLI)" OFF)

if(REGENERATE_ZCBOR)
    # Ensure the venv exists at configure time so find_program() below picks
    # up the pinned zcbor CLI rather than failing on a missing binary.
    execute_process(
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/setup-venv.sh
        RESULT_VARIABLE _setup_venv_rc
    )
    if(NOT _setup_venv_rc EQUAL 0)
        message(FATAL_ERROR "scripts/setup-venv.sh failed (exit ${_setup_venv_rc}); cannot enable REGENERATE_ZCBOR")
    endif()
    list(PREPEND CMAKE_PROGRAM_PATH "${CMAKE_CURRENT_SOURCE_DIR}/venv/bin")
endif()

set(CDDL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cddl)
set(GENERATED_DIR ${CMAKE_CURRENT_SOURCE_DIR}/generated)
set(LICENSE_HEADER ${CDDL_DIR}/license_header.txt)

if(REGENERATE_ZCBOR)
    find_program(ZCBOR_EXE zcbor REQUIRED HINTS ENV PATH)
    message(STATUS "REGENERATE_ZCBOR=ON: regenerating zcbor decoders via ${ZCBOR_EXE}")
    file(REMOVE_RECURSE ${GENERATED_DIR})
    file(MAKE_DIRECTORY ${GENERATED_DIR})
else()
    message(STATUS "REGENERATE_ZCBOR=OFF: using committed generated sources in generated/")
endif()

file(GLOB CDDL_FILES "${CDDL_DIR}/*.cddl")

foreach(cddl_file ${CDDL_FILES})
    get_filename_component(cddl_name ${cddl_file} NAME_WE)

    # coev.cddl and eat.cddl are co-generated with corim.cddl in a single
    # zcbor invocation (see the corim branch below) so all parsers share one
    # type pack and avoid ODR conflicts on the generated struct types. They do
    # not produce their own *_decode files.
    if(cddl_name STREQUAL "coev" OR cddl_name STREQUAL "eat")
        continue()
    endif()

    set(gen_c ${GENERATED_DIR}/${cddl_name}_decode.c)
    set(gen_h ${GENERATED_DIR}/${cddl_name}_decode.h)
    set(gen_types_h ${GENERATED_DIR}/${cddl_name}_decode_types.h)

    if(REGENERATE_ZCBOR)
        if(cddl_name STREQUAL "cose")
            set(entry_types "COSE_Sign1_Tagged")
            set(zcbor_cddl_args "-c" "${cddl_file}")
        elseif(cddl_name STREQUAL "corim")
            # Combined CoRIM + CoEV codegen. coev.cddl references CoRIM types
            # (environment-map, measurement-map, corim-locator-map, ...) and
            # vice versa (CoEV's spdm-indirect-map is declared in corim.cddl
            # so measurement-values-map can carry it). zcbor unions the two
            # vocabularies into one shared type pack.
            set(entry_types "corim" "tagged-unsigned-corim-map" "concise-mid-tag"
                            "tagged-spdm-toc" "concise-evidence" "eat-claims-map")
            set(zcbor_cddl_args "-c" "${cddl_file}" "-c" "${CDDL_DIR}/coev.cddl"
                                "-c" "${CDDL_DIR}/eat.cddl")
        else()
            set(entry_types "${cddl_name}")
            set(zcbor_cddl_args "-c" "${cddl_file}")
        endif()

        add_custom_command(
            OUTPUT ${gen_c} ${gen_h} ${gen_types_h}
            COMMAND ${ZCBOR_EXE} code
                --decode
                --default-max-qty 10
                --file-header ${LICENSE_HEADER}
                --unordered-maps
                ${zcbor_cddl_args}
                -t ${entry_types}
                --oc ${gen_c}
                --oh ${gen_h}
            DEPENDS ${cddl_file} ${LICENSE_HEADER} ${CDDL_DIR}/corim.cddl ${CDDL_DIR}/coev.cddl ${CDDL_DIR}/eat.cddl
            COMMENT "Generating ${cddl_name} decoder with zcbor (entry types: ${entry_types})"
        )
    endif()

    list(APPEND GENERATED_SOURCES ${gen_c})
    list(APPEND GENERATED_HEADERS ${gen_h} ${gen_types_h})
endforeach()


set_source_files_properties(${GENERATED_SOURCES} PROPERTIES
    COMPILE_OPTIONS "-include;${CMAKE_CURRENT_SOURCE_DIR}/include/zcbor_logger.h;-Wno-type-limits"
)

if(NOT REGENERATE_ZCBOR)
    # Generated sources are committed; track CDDL files so CMake recompiles if
    # they diverge.  Actual regeneration requires -DREGENERATE_ZCBOR=ON.
    set_source_files_properties(${GENERATED_SOURCES} PROPERTIES
        OBJECT_DEPENDS "${CDDL_FILES};${LICENSE_HEADER}"
    )
endif()

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
  GIT_SHALLOW TRUE
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(fmt)
set_target_properties(fmt PROPERTIES COMPILE_WARNING_AS_ERROR OFF)

# Build spdlog as static library using our fetched fmt
set(SPDLOG_INSTALL OFF CACHE BOOL "Don't install spdlog headers" FORCE)
set(SPDLOG_FMT_EXTERNAL ON CACHE BOOL "Use external fmt library" FORCE)
set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "Build spdlog as static library" FORCE)
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.14.1
  GIT_SHALLOW TRUE
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(spdlog)
set_target_properties(spdlog PROPERTIES COMPILE_WARNING_AS_ERROR OFF)

# Restore original settings
set(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_SAVED})
set(CMAKE_POSITION_INDEPENDENT_CODE ${CMAKE_POSITION_INDEPENDENT_CODE_SAVED})

find_package(ZLIB REQUIRED)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/nvat_parallelism.cmake)
nvat_resolve_build_jobs(NVAT_BUILD_JOBS)

option(USE_SYSTEM_DEPS "Use system-installed OpenSSL, curl, and xmlsec instead of building from source" OFF)

if(USE_SYSTEM_DEPS)
  # Use system-installed packages (requires libssl-dev, libcurl4-openssl-dev, libxmlsec1-dev)
  find_package(OpenSSL REQUIRED)
  find_package(CURL REQUIRED)
  find_package(LibXml2 REQUIRED)

  # Find system xmlsec via pkg-config (IMPORTED_TARGET creates PkgConfig::XMLSEC1)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(XMLSEC1 REQUIRED IMPORTED_TARGET xmlsec1-openssl)

  set(XMLSEC_COMPILE_DEFINITIONS
    __XMLSEC_FUNCTION__=__func__
    XMLSEC_NO_SIZE_T
    XMLSEC_NO_XSLT=1
    XMLSEC_NO_FTP=1
    XMLSEC_NO_MD5=1
    XMLSEC_NO_GOST=1
    XMLSEC_NO_GOST2012=1
    XMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1
    XMLSEC_CRYPTO_OPENSSL=1
  )

  if(NOT TARGET xmlsec::xmlsec)
    add_library(xmlsec::xmlsec INTERFACE IMPORTED)
    set_target_properties(xmlsec::xmlsec PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${XMLSEC1_INCLUDE_DIRS}"
      INTERFACE_COMPILE_DEFINITIONS "${XMLSEC_COMPILE_DEFINITIONS}"
      INTERFACE_LINK_LIBRARIES "LibXml2::LibXml2"
    )
  endif()

  if(NOT TARGET xmlsec::xmlsec-openssl)
    add_library(xmlsec::xmlsec-openssl INTERFACE IMPORTED)
    set_target_properties(xmlsec::xmlsec-openssl PROPERTIES
      INTERFACE_LINK_LIBRARIES "PkgConfig::XMLSEC1;xmlsec::xmlsec;OpenSSL::SSL;OpenSSL::Crypto"
    )
  endif()

  # No-op targets for add_dependencies compatibility
  add_custom_target(openssl_external)
  add_custom_target(xmlsec_external)
  add_custom_target(curl_external)

else()
  # Build dependencies from source (production builds, RHEL8 compat)

  # The ExternalProjects build via their own Configure/make, so they don't pick up
  # CMAKE_*_COMPILER_LAUNCHER; route them through sccache by prefixing CC instead.
  if(ENABLE_SCCACHE)
    set(_EP_CC "${SCCACHE} ${CMAKE_C_COMPILER}")
  else()
    set(_EP_CC "${CMAKE_C_COMPILER}")
  endif()
  set(_EP_CFLAGS "${CMAKE_C_FLAGS} -fPIC")

  # Build OpenSSL statically — RHEL8 ships 1.1.1 but the code needs 3.x APIs
  set(OPENSSL_INSTALL_DIR "${CMAKE_BINARY_DIR}/openssl-install")

  ExternalProject_Add(openssl_external
    URL https://github.com/openssl/openssl/releases/download/openssl-3.6.4/openssl-3.6.4.tar.gz
    URL_HASH SHA256=9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef
    CONFIGURE_COMMAND <SOURCE_DIR>/Configure
      "CC=${_EP_CC}"
      "CFLAGS=${_EP_CFLAGS}"
      --prefix=${OPENSSL_INSTALL_DIR}
      --openssldir=${OPENSSL_INSTALL_DIR}
      --libdir=lib
      no-shared
      no-tests      # Skip ~100+ test binaries — not needed, saves link-time memory
      no-apps       # Skip openssl CLI binary
      no-docs       # Skip man pages and HTML docs
      no-legacy     # Disable legacy provider (MD2, RC4, DES, etc.)
      no-engine     # Disable deprecated ENGINE API — unused with static linking
      no-dtls       # Disable DTLS — SDK uses TLS only, not UDP-based DTLS
    BUILD_COMMAND make -j${NVAT_BUILD_JOBS}
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

  # Build libxml2 statically — avoids DT_VERNEED/DT_VERDEF mismatch on Ubuntu 26.04+
  set(LIBXML2_INSTALL_DIR "${CMAKE_BINARY_DIR}/libxml2-install")

  ExternalProject_Add(libxml2_external
    URL https://download.gnome.org/sources/libxml2/2.15/libxml2-2.15.4.tar.xz
    URL_HASH SHA256=98087fd181d9070724f3fbc65c7377db03038eb92bd882374daff44940138821
    CONFIGURE_COMMAND <SOURCE_DIR>/configure
      --prefix=${LIBXML2_INSTALL_DIR}
      --disable-shared
      --enable-static
      --without-python
      --without-lzma
      --with-zlib
      "CC=${_EP_CC}"
      "CFLAGS=${_EP_CFLAGS}"
    BUILD_COMMAND make -j${NVAT_BUILD_JOBS}
    INSTALL_COMMAND make install
    BUILD_IN_SOURCE 1
  )

  set(LIBXML2_INCLUDE_DIR "${LIBXML2_INSTALL_DIR}/include/libxml2")
  file(MAKE_DIRECTORY "${LIBXML2_INCLUDE_DIR}")

  add_library(LibXml2::LibXml2 STATIC IMPORTED)
  set_target_properties(LibXml2::LibXml2 PROPERTIES
    IMPORTED_LOCATION "${LIBXML2_INSTALL_DIR}/lib/libxml2.a"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBXML2_INCLUDE_DIR}"
    INTERFACE_LINK_LIBRARIES "ZLIB::ZLIB"
  )
  add_dependencies(LibXml2::LibXml2 libxml2_external)

  # Build xmlsec 1.2.39 statically (depends on OpenSSL 3 and libxml2)
  set(XMLSEC_INSTALL_DIR "${CMAKE_BINARY_DIR}/xmlsec-install")

  ExternalProject_Add(xmlsec_external
    DEPENDS openssl_external libxml2_external
    URL https://github.com/lsh123/xmlsec/releases/download/xmlsec-1_2_39/xmlsec1-1.2.39.tar.gz
    URL_HASH SHA256=15f2f55ea5968e578fcd24b3b427e553876c86c147dc7f03923e98fc2768a1fa
    CONFIGURE_COMMAND <SOURCE_DIR>/configure
      --prefix=${XMLSEC_INSTALL_DIR}
      --disable-shared
      --enable-static
      --disable-crypto-dl
      --with-openssl=${OPENSSL_INSTALL_DIR}
      --with-libxml=${LIBXML2_INSTALL_DIR}
      --without-gnutls
      --without-nss
      --without-gcrypt
      --with-libxslt=no
      --disable-docs
      --disable-apps
      "CC=${_EP_CC}"
      "CFLAGS=${_EP_CFLAGS}"
      "PKG_CONFIG_PATH=${OPENSSL_INSTALL_DIR}/lib/pkgconfig:${LIBXML2_INSTALL_DIR}/lib/pkgconfig"
    BUILD_COMMAND make -j${NVAT_BUILD_JOBS}
    INSTALL_COMMAND make install
    BUILD_IN_SOURCE 1
  )

  set(XMLSEC_ROOT "${XMLSEC_INSTALL_DIR}" CACHE PATH "xmlsec installation directory" FORCE)

  # Build libcurl statically — RHEL8 ships 7.61 but the code needs the URL API (>= 7.62)
  set(CURL_INSTALL_DIR "${CMAKE_BINARY_DIR}/curl-install")

  ExternalProject_Add(curl_external
    DEPENDS openssl_external
    URL https://github.com/curl/curl/releases/download/curl-8_22_0/curl-8.22.0.tar.gz
    URL_HASH SHA256=d54dd598bf05927a726deb38df31c6a255ba83ff1de57c5d1464dac3ed8f44a1
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
    BUILD_COMMAND make -j${NVAT_BUILD_JOBS}
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

  find_package(xmlsec REQUIRED)

endif() # USE_SYSTEM_DEPS

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

# Make __FILE__ relative to source directory for cleaner log output.
# Uses -fmacro-prefix-map (not -ffile-prefix-map) so that only preprocessor
# macros (__FILE__, __builtin_FILE()) are remapped. Debug info and coverage
# mapping paths are left intact — required for llvm-cov / SonarQube.
# Ref: https://clang.llvm.org/docs/ClangCommandLineReference.html
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/src/=)
endif()

configure_file("include/nvat.h.in" "include/nvat.h")

add_library(nvat
  src/nvat.cpp
  src/attestation.cpp
  src/claims.cpp
  src/claims_evaluator.cpp
  src/cmw.cpp
  src/corim.cpp
  src/corim_evidence/coev.cpp
  src/corim_evidence/coev_to_ect.cpp
  src/corim_evidence/eat_to_ect.cpp
  src/corim_evidence/corim_store.cpp
  src/corim_evidence/eat.cpp
  src/corim_evidence/eat_cwt.cpp
  src/corim_evidence/evidence_handler.cpp
  src/corim_verify.cpp
  src/ear_mapper.cpp
  src/corim_evidence/dice_tcb_info_to_ect.cpp
  src/cose.cpp
  ${GENERATED_SOURCES}
  src/gpu/evidence.cpp
  src/gpu/blackwell_fsp.cpp
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
  src/dice_tcb_info.cpp
  src/zcbor_logger.cpp
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
    ${zcbor_SOURCE_DIR}/include
    ${GENERATED_DIR}
)

# spdlog and fmt include dirs (linked statically via TARGET_FILE below)
target_include_directories(nvat SYSTEM PRIVATE
  ${spdlog_SOURCE_DIR}/include
  ${fmt_SOURCE_DIR}/include
)

# Apply zcbor logger override to generated decoder sources
target_compile_definitions(nvat PRIVATE ZCBOR_PRINT_FUNC=nvat_zcbor_log ${ZCBOR_ABI_DEFINITIONS})

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND (NOT SANITIZER OR SANITIZER STREQUAL "OFF"))
  target_compile_definitions(nvat PRIVATE ZCBOR_VERBOSE)
endif()

# Suppress anonymous-struct warnings from generated zcbor headers.
set_source_files_properties(src/corim.cpp src/cose.cpp src/corim_evidence/coev.cpp src/corim_evidence/eat.cpp src/corim_evidence/eat_cwt.cpp src/corim_verify.cpp PROPERTIES COMPILE_OPTIONS
    "$<$<CXX_COMPILER_ID:GNU>:-Wno-pedantic>;$<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-gnu-anonymous-struct;-Wno-nested-anon-types>"
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

if (BUILD_FUZZ_TESTS)
  message("-- Building fuzz tests")
  add_subdirectory(fuzz-tests)
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
    ZLIB::ZLIB
    # Use TARGET_FILE to link the static library directly without creating
    # a target dependency that CMake would try to export
    $<TARGET_FILE:spdlog>
    $<TARGET_FILE:fmt>
    $<TARGET_FILE:zcbor_lib>
    own-jwt-cpp
    nlohmann_json::nlohmann_json
    regorus_ffi
)

# Ensure dependencies are built before nvat
add_dependencies(nvat regorus_ffi spdlog fmt curl_external xmlsec_external openssl_external zcbor_lib)

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

include(CPack)
