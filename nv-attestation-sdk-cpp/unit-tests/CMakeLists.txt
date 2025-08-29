cmake_minimum_required(VERSION 3.11)
project(nv-attestation-unit-tests)

find_package(GTest REQUIRED)

option(SANITIZER "Select a sanitizer" OFF)

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
    gpu/claims_test.cpp
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

include(FetchContent)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(json)

target_link_libraries(nv-attestation-unit-tests PRIVATE
    GTest::gtest
    GTest::gmock
    nlohmann_json::nlohmann_json
)

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # CMake file is being run on its own (standalone) - testing installed version of sdk
    find_package(nvat REQUIRED)
    target_link_libraries(nv-attestation-unit-tests PRIVATE nvat::nvat)
    target_include_directories(nv-attestation-unit-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)  
else()
    # CMake file is being invoked as part of subdirectory from another CMake file
    target_link_libraries(nv-attestation-unit-tests PRIVATE nvat)
    target_include_directories(nv-attestation-unit-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)  
endif()

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/testdata
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

include(GoogleTest)

gtest_discover_tests(nv-attestation-unit-tests PROPERTIES LABELS "unit")