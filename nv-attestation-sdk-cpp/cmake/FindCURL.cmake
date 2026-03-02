# If CURL target already exists (e.g. created manually for ExternalProject),
# skip the file search.
if(TARGET CURL::libcurl)
  set(CURL_FOUND TRUE)
  return()
endif()

# Fall through to CMake's built-in FindCURL
list(REMOVE_ITEM CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
find_package(CURL ${ARGN})
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
