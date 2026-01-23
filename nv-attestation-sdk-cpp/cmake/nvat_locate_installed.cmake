include_guard(GLOBAL)

# Locate an installed NV Attestation SDK without relying on any installed CMake package files.
#
# Expected installed artifacts:
# - Header:  <prefix>/include/nvat.h
# - Library: <prefix>/(lib|lib64|lib/${CMAKE_LIBRARY_ARCHITECTURE})/libnvat.so
#
# Search order (first match wins):
# - Explicit overrides: NVAT_INCLUDE_DIR / NVAT_LIBRARY
# - Prefix: NVAT_ROOT
# - Prefix list: CMAKE_PREFIX_PATH
# - CMake default search (system paths, etc.)
#
# Consumer override knobs:
# - NVAT_ROOT: prefix to search (e.g. /usr, /usr/local, /opt/nvat)
# - NVAT_INCLUDE_DIR: directory containing nvat.h
# - NVAT_LIBRARY: full path to libnvat.so
#
# On success:
# - Creates IMPORTED SHARED target: nvat::nvat
# - Sets/updates variables: NVAT_INCLUDE_DIR, NVAT_LIBRARY

function(nvat_locate_installed)
  if(NOT DEFINED NVAT_ROOT)
    set(NVAT_ROOT "" CACHE PATH "Prefix path to search for an installed NV Attestation SDK (libnvat + nvat.h)")
  endif()

  # If a prior configure seeded these cache variables with empty/NOTFOUND values,
  # CMake's find_* commands won't reliably re-search. Clear them so our tiered
  # search can run without requiring a clean build directory.
  if(DEFINED CACHE{NVAT_INCLUDE_DIR})
    if(NVAT_INCLUDE_DIR STREQUAL "" OR NVAT_INCLUDE_DIR MATCHES "-NOTFOUND$")
      unset(NVAT_INCLUDE_DIR CACHE)
    endif()
  endif()
  if(DEFINED CACHE{NVAT_LIBRARY})
    if(NVAT_LIBRARY STREQUAL "" OR NVAT_LIBRARY MATCHES "-NOTFOUND$")
      unset(NVAT_LIBRARY CACHE)
    endif()
  endif()

  if(NOT NVAT_INCLUDE_DIR)
    if(NVAT_ROOT)
      find_path(
        NVAT_INCLUDE_DIR
        NAMES nvat.h
        HINTS "${NVAT_ROOT}"
        PATH_SUFFIXES include
        NO_DEFAULT_PATH
      )
    endif()

    if(NOT NVAT_INCLUDE_DIR AND CMAKE_PREFIX_PATH)
      find_path(
        NVAT_INCLUDE_DIR
        NAMES nvat.h
        HINTS ${CMAKE_PREFIX_PATH}
        PATH_SUFFIXES include
        NO_DEFAULT_PATH
      )
    endif()

    if(NOT NVAT_INCLUDE_DIR)
      find_path(
        NVAT_INCLUDE_DIR
        NAMES nvat.h
        PATH_SUFFIXES include
      )
    endif()
  endif()

  if(NOT NVAT_LIBRARY)
    if(NVAT_ROOT)
      find_library(
        NVAT_LIBRARY
        NAMES nvat
        HINTS "${NVAT_ROOT}"
        PATH_SUFFIXES
          lib
          lib64
          "lib/${CMAKE_LIBRARY_ARCHITECTURE}"
        NO_DEFAULT_PATH
      )
    endif()

    if(NOT NVAT_LIBRARY AND CMAKE_PREFIX_PATH)
      find_library(
        NVAT_LIBRARY
        NAMES nvat
        HINTS ${CMAKE_PREFIX_PATH}
        PATH_SUFFIXES
          lib
          lib64
          "lib/${CMAKE_LIBRARY_ARCHITECTURE}"
        NO_DEFAULT_PATH
      )
    endif()

    if(NOT NVAT_LIBRARY)
      find_library(
        NVAT_LIBRARY
        NAMES nvat
        PATH_SUFFIXES
          lib
          lib64
          "lib/${CMAKE_LIBRARY_ARCHITECTURE}"
      )
    endif()
  endif()

  if(NOT NVAT_INCLUDE_DIR OR NOT EXISTS "${NVAT_INCLUDE_DIR}/nvat.h")
    message(FATAL_ERROR
      "Failed to locate installed NV Attestation header 'nvat.h'.\n"
      "Set NVAT_INCLUDE_DIR=<dir-containing-nvat.h>, NVAT_ROOT=<prefix>, or CMAKE_PREFIX_PATH=<prefix>.\n"
      "Current values:\n"
      "  NVAT_ROOT='${NVAT_ROOT}'\n"
      "  NVAT_INCLUDE_DIR='${NVAT_INCLUDE_DIR}'\n"
      "  CMAKE_PREFIX_PATH='${CMAKE_PREFIX_PATH}'\n"
    )
  endif()

  if(NOT NVAT_LIBRARY OR NOT EXISTS "${NVAT_LIBRARY}")
    message(FATAL_ERROR
      "Failed to locate installed NV Attestation library 'libnvat'.\n"
      "Set NVAT_LIBRARY=<full-path-to-libnvat.so>, NVAT_ROOT=<prefix>, or CMAKE_PREFIX_PATH=<prefix>.\n"
      "Current values:\n"
      "  NVAT_ROOT='${NVAT_ROOT}'\n"
      "  NVAT_LIBRARY='${NVAT_LIBRARY}'\n"
      "  CMAKE_PREFIX_PATH='${CMAKE_PREFIX_PATH}'\n"
      "  CMAKE_LIBRARY_ARCHITECTURE='${CMAKE_LIBRARY_ARCHITECTURE}'\n"
    )
  endif()

  if(NOT TARGET nvat::nvat)
    add_library(nvat::nvat SHARED IMPORTED GLOBAL)
    set_target_properties(nvat::nvat PROPERTIES
      IMPORTED_LOCATION "${NVAT_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${NVAT_INCLUDE_DIR}"
    )
  endif()
endfunction()



