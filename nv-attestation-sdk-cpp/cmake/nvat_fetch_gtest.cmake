# Fetch and configure Google Test for use with the NVAT build.
#
# - Fetches GTest v1.16.0 via FetchContent
# - Suppresses the [[maybe_unused]] C++17 attribute warning that fires
#   under -Werror when building with C++14

include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.16.0
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(googletest)

foreach(_gt_target gtest gtest_main gmock gmock_main)
  if(TARGET ${_gt_target})
    target_compile_options(${_gt_target} PRIVATE -Wno-error=c++17-attribute-extensions)
  endif()
endforeach()
