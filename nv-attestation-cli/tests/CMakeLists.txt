cmake_minimum_required(VERSION 3.11)
project(nv-attestation-cli-tests)

find_package(GTest REQUIRED)

option(SANITIZER "Select a sanitizer" OFF)

add_executable(nv-attestation-cli-tests
    main.cpp
    attest_tests.cpp
    collect_evidence_tests.cpp
    test_utils.h
    environment.h
    ${nvattest_SOURCE_DIR}/src/attest.cpp
    ${nvattest_SOURCE_DIR}/src/collect_evidence.cpp
    ${nvattest_SOURCE_DIR}/src/utils.cpp
)

target_include_directories(nv-attestation-cli-tests PRIVATE 
    ${nvattest_SOURCE_DIR}/src
)

if (SANITIZER)
    target_compile_options(nv-attestation-cli-tests PRIVATE -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
    target_link_options(nv-attestation-cli-tests PRIVATE -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
endif()
target_compile_options(nv-attestation-cli-tests PRIVATE -Wno-unused -Wno-c++17-attribute-extensions)

find_package(spdlog REQUIRED)

target_link_libraries(nv-attestation-cli-tests PRIVATE
    GTest::gtest
    GTest::gmock
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    CLI11::CLI11
)

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # CMake file is being run on its own (standalone)
    find_package(nvat REQUIRED)
    target_link_libraries(nv-attestation-cli-tests PRIVATE nvat::nvat)
else()
    # CMake file is being invoked as part of subdirectory from another CMake file
    target_link_libraries(nv-attestation-cli-tests PRIVATE nvat)
endif()

include(GoogleTest)
gtest_discover_tests(nv-attestation-cli-tests PROPERTIES LABELS "cli")