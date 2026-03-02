# If OpenSSL targets already exist (e.g. created manually for ExternalProject),
# skip the file search — the built-in FindOpenSSL always searches disk even when
# the targets are already defined.
if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
  set(OpenSSL_FOUND TRUE)
  set(OPENSSL_FOUND TRUE)
  return()
endif()

# Fall through to CMake's built-in FindOpenSSL
list(REMOVE_ITEM CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
find_package(OpenSSL ${ARGN})
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
