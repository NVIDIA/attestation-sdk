find_package(PkgConfig)

if(PKG_CONFIG_FOUND)
  pkg_check_modules(Pc_xmlsec QUIET xmlsec1)
  pkg_check_modules(Pc_xmlsec_openssl QUIET xmlsec1-openssl)

  if (Pc_xmlsec_openssl_FOUND)
    list(APPEND xmlsec_COMPILE_DEFINITIONS ${Pc_xmlsec_openssl_CFLAGS_OTHER})
    list(APPEND xmlsec_INCLUDE_DIRS ${Pc_xmlsec_openssl_INCLUDE_DIRS})
    list(APPEND xmlsec_LIBRARY_DIRS ${Pc_xmlsec_openssl_LIBRARY_DIRS})
    list(APPEND xmlsec_LIBRARIES ${Pc_xmlsec_openssl_LIBRARIES})
  endif()

  if (NOT xmlsec_FIND_QUIETLY)
    if (Pc_xmlsec_FOUND)
      message(STATUS "Found xmlsec1 via pkg-config")
    else()
      message(STATUS "Not found xmlsec1 via pkg-config")
    endif()

    if (Pc_xmlsec_openssl_FOUND)
      message(STATUS "Found xmlsec1-openssl via pkg-config")
      message(STATUS "XMLSec CFLAGS: ${Pc_xmlsec_CFLAGS}")
      message(STATUS "XMLSec LDFLAGS: ${Pc_xmlsec_LDFLAGS}")
    else()
      message(STATUS "Not found xmlsec1-openssl via pkg-config")
    endif()
  endif()
endif()

if(CMAKE_VERSION VERSION_LESS 3.12.0)
  list(APPEND xmlsec_ROOT "$ENV{xmlsec_ROOT}")
endif()

list(APPEND xmlsec_ROOT "${xmlsec_ROOT_DIR}" "$ENV{xmlsec_ROOT_DIR}")
list(REMOVE_ITEM xmlsec_ROOT "")
list(REMOVE_DUPLICATES xmlsec_ROOT)

find_path(xmlsec_INCLUDE_DIR
  NAMES xmlsec/xmlsec.h
  PATH_SUFFIXES xmlsec1
  PATHS "${xmlsec_ROOT}"
  HINTS "${Pc_xmlsec_INCLUDE_DIRS}" "${Pc_xmlsec_openssl_INCLUDE_DIRS}"
)

find_library(xmlsec_LIBRARY
  NAMES xmlsec1
  PATHS "${xmlsec_ROOT}"
  HINTS ${Pc_xmlsec_LIBRARY_DIRS}
)

find_library(xmlsec_OPENSSL_LIBRARY
  NAMES xmlsec1-openssl
  PATHS "${xmlsec_ROOT}"
  HINTS ${Pc_xmlsec_openssl_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(xmlsec REQUIRED_VARS
  xmlsec_LIBRARY
  xmlsec_OPENSSL_LIBRARY
  xmlsec_INCLUDE_DIRS
)

if(xmlsec_FOUND)
  if (NOT TARGET xmlsec::xmlsec)
    add_library(xmlsec::xmlsec UNKNOWN IMPORTED)
    set_target_properties(xmlsec::xmlsec PROPERTIES
      IMPORTED_LOCATION "${xmlsec_LIBRARY}"
      INTERFACE_COMPILE_OPTIONS "${Pc_xmlsec_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${xmlsec_INCLUDE_DIRS}"
    )
  endif()

  if(NOT TARGET xmlsec::xmlsec-openssl)
    add_library(xmlsec::xmlsec-openssl UNKNOWN IMPORTED)
    set_target_properties(xmlsec::xmlsec-openssl PROPERTIES
      IMPORTED_LOCATION "${xmlsec_OPENSSL_LIBRARY}"
      INTERFACE_COMPILE_OPTIONS "${Pc_xmlsec_openssl_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${xmlsec_INCLUDE_DIR}"
      INTERFACE_LINK_LIBRARIES "${Pc_xmlsec_openssl_LIBRARIES}"
      INTERFACE_LINK_DIRECTORIES "${Pc_xmlsec_openssl_LIBRARY_DIRS}"
    )
  endif()
endif()
