cmake_minimum_required(VERSION 3.11)
project(nv-attestation-integration-tests)

# todo(p3): integration tests is currently not used. keeping the folder structure for now, in case we need to add any more in the future
# if after a few weeks of development this becomes unecessary, this entire folder can be removed
find_package(GTest REQUIRED)

option(SANITIZER "Select a sanitizer" OFF)

add_executable(nv-attestation-integration-tests
    main.cpp
    gpu_evidence_test.cpp
    switch_evidence_test.cpp
) 

target_include_directories(nv-attestation-integration-tests PRIVATE 
    nv-attestation
)

if (SANITIZER)
    target_compile_options(nv-attestation-integration-tests PRIVATE -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
    target_link_options(nv-attestation-integration-tests PRIVATE -fsanitize=${SANITIZER} -fno-sanitize-recover=all)
endif()
target_compile_options(nv-attestation-integration-tests PRIVATE -Wno-unused -Wno-c++17-attribute-extensions)

find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(xmlsec REQUIRED)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(json)


target_link_libraries(nv-attestation-integration-tests PRIVATE
    GTest::gtest
    nlohmann_json::nlohmann_json
)

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # CMake file is being run on its own (standalone)
    find_package(nvat REQUIRED)
    target_link_libraries(nv-attestation-integration-tests PRIVATE nvat::nvat)
    target_include_directories(nv-attestation-unit-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)  
else()
    # CMake file is being invoked as part of subdirectory from another CMake file
    target_link_libraries(nv-attestation-integration-tests PRIVATE nvat)
    target_include_directories(nv-attestation-integration-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)  
endif()

include(GoogleTest)
gtest_discover_tests(nv-attestation-integration-tests PROPERTIES LABELS "integration")