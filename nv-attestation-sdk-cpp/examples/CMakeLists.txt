# Check if we're being built as a subdirectory
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # Standalone build - find installed SDK
    cmake_minimum_required(VERSION 3.11)
    project(nv-attestation-examples)
    
    set(CMAKE_CXX_STANDARD 14)
    
    find_package(nvat REQUIRED)
    # Set output directory for all example executables
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()


add_subdirectory(attest-minimal)
add_subdirectory(attest)
add_subdirectory(collect-gpu-evidence)
add_subdirectory(custom-logger)
add_subdirectory(parallel-verification)
