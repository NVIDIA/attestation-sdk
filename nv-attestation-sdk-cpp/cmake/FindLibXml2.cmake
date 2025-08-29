# Prevent infinite recursion
if(DEFINED _FIND_LIBXML2_GUARD)
    return()
endif()
set(_FIND_LIBXML2_GUARD ON)

list(REMOVE_ITEM CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
find_package(LibXml2)

if (NOT LibXml2_FOUND)
  find_package(PkgConfig)

  if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_LibXml2 QUIET libxml-2.0)
  endif()

  if(CMAKE_VERSION VERSION_LESS 3.12.0)
    list(APPEND LibXml2_ROOT "$ENV{LibXml2_ROOT}")
  endif()

  list(APPEND LibXml2_ROOT "${LibXml2_ROOT_DIR}" "$ENV{LibXml2_ROOT_DIR}")
  list(REMOVE_ITEM LibXml2_ROOT "")
  list(REMOVE_DUPLICATES LibXml2_ROOT)

  find_path(LibXml2_INCLUDE_DIR
    NAMES libxml/parser.h
    PATHS ${LibXml2_ROOT}
    HINTS ${PC_LibXml2_INCLUDE_DIRS}
  )

  find_library(LibXml2_LIBRARY
    NAMES xml2
    PATHS ${LibXml2_ROOT}
    HINTS ${PC_LibXml2_LIBRARY_DIRS}
  )

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(LibXml2
    REQUIRED_VARS LibXml2_LIBRARY LibXml2_INCLUDE_DIR
  )
endif()

if(LibXml2_FOUND AND NOT TARGET LibXml2::LibXml2)
  add_library(LibXml2::LibXml2 UNKNOWN IMPORTED)
  set_target_properties(LibXml2::LibXml2 PROPERTIES
    IMPORTED_LOCATION "${LibXml2_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${LibXml2_INCLUDE_DIR}"
  )
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")

# Clean up guard variable
unset(_FIND_LIBXML2_GUARD)
