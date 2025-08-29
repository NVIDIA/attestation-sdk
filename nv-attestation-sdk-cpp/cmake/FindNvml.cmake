include(FindPackageHandleStandardArgs)

file(GLOB CUDA_INCLUDE_SEARCH_PATHS "/usr/local/cuda-*/include")
file(GLOB CUDA_INCLUDE_TARGET_SEARCH_PATHS "/usr/local/cuda-*/targets/*/include/")
find_file(Nvml_HEADER nvml.h
  HINTS
    "${Nvml_ROOT}"
    "${NVML_ROOT}"
    ENV Nvml_ROOT
    ENV NVML_ROOT
    ENV CUDA_PATH
    ${CUDA_INCLUDE_SEARCH_PATHS}
    ${CUDA_INCLUDE_TARGET_SEARCH_PATHS}
  PATHS
    /usr/local/cuda
)

mark_as_advanced(Nvml_HEADER)
if (Nvml_HEADER)
  get_filename_component(Nvml_INCLUDE_DIR "${Nvml_HEADER}" DIRECTORY CACHE)
endif()

file(GLOB CUDA_LIB_SEARCH_PATHS "/usr/local/cuda-*/lib64")
file(GLOB CUDA_LIB_TARGET_SEARCH_PATHS "/usr/local/cuda-*/targets/*/lib/stubs")
find_library(Nvml_LIBRARY
  NAMES nvml nvidia-ml libnvidia-ml
  HINTS
    "${Nvml_ROOT}"
    "${NVML_ROOT}"
    ${CUDA_LIB_SEARCH_PATHS}
    ${CUDA_LIB_TARGET_SEARCH_PATHS}
    ENV Nvml_ROOT
    ENV NVML_ROOT
    ENV CUDA_PATH
  PATH_SUFFIXES nvidia/current
)

mark_as_advanced(Nvml_LIBRARY)

find_package_handle_standard_args(Nvml
  REQUIRED_VARS Nvml_INCLUDE_DIR Nvml_LIBRARY)

if (NOT TARGET CUDA::nvml AND Nvml_FOUND)
    add_library(CUDA::nvml UNKNOWN IMPORTED)

    set_target_properties(CUDA::nvml PROPERTIES
      IMPORTED_LOCATION "${Nvml_LIBRARY}"
      INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${Nvml_INCLUDE_DIR}"
    )
endif()
