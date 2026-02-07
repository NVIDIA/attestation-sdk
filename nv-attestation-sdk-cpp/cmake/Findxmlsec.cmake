# Static-only xmlsec linking
# Requires XMLSEC_ROOT to be set by CMakeLists.txt before find_package(xmlsec)

if(NOT XMLSEC_ROOT)
  message(FATAL_ERROR "XMLSEC_ROOT must be set to the xmlsec installation directory")
endif()

# Set expected paths - files won't exist at configure time (ExternalProject builds later)
set(xmlsec_INCLUDE_DIR "${XMLSEC_ROOT}/include/xmlsec1")
set(xmlsec_LIBRARY "${XMLSEC_ROOT}/lib/libxmlsec1.a")
set(xmlsec_OPENSSL_LIBRARY "${XMLSEC_ROOT}/lib/libxmlsec1-openssl.a")

file(MAKE_DIRECTORY "${xmlsec_INCLUDE_DIR}")

message(STATUS "xmlsec_INCLUDE_DIR: ${xmlsec_INCLUDE_DIR}")
message(STATUS "xmlsec_LIBRARY: ${xmlsec_LIBRARY}")
message(STATUS "xmlsec_OPENSSL_LIBRARY: ${xmlsec_OPENSSL_LIBRARY}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(xmlsec REQUIRED_VARS
  xmlsec_LIBRARY
  xmlsec_OPENSSL_LIBRARY
  xmlsec_INCLUDE_DIR
)

if(xmlsec_FOUND)
  find_package(LibXml2 REQUIRED)
  find_package(OpenSSL REQUIRED)

  # Compile definitions required by xmlsec headers (matches pkg-config output)
  set(XMLSEC_COMPILE_DEFINITIONS
    __XMLSEC_FUNCTION__=__func__
    XMLSEC_NO_SIZE_T
    XMLSEC_NO_XSLT=1
    XMLSEC_NO_FTP=1
    XMLSEC_NO_MD5=1
    XMLSEC_NO_GOST=1
    XMLSEC_NO_GOST2012=1
    XMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1
    XMLSEC_CRYPTO_OPENSSL=1
  )

  if(NOT TARGET xmlsec::xmlsec)
    add_library(xmlsec::xmlsec STATIC IMPORTED)
    set_target_properties(xmlsec::xmlsec PROPERTIES
      IMPORTED_LOCATION "${xmlsec_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${xmlsec_INCLUDE_DIR}"
      INTERFACE_COMPILE_DEFINITIONS "${XMLSEC_COMPILE_DEFINITIONS}"
      INTERFACE_LINK_LIBRARIES "LibXml2::LibXml2"
    )
  endif()

  if(NOT TARGET xmlsec::xmlsec-openssl)
    add_library(xmlsec::xmlsec-openssl STATIC IMPORTED)
    set_target_properties(xmlsec::xmlsec-openssl PROPERTIES
      IMPORTED_LOCATION "${xmlsec_OPENSSL_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${xmlsec_INCLUDE_DIR}"
      INTERFACE_COMPILE_DEFINITIONS "${XMLSEC_COMPILE_DEFINITIONS}"
      INTERFACE_LINK_LIBRARIES "xmlsec::xmlsec;OpenSSL::SSL;OpenSSL::Crypto"
    )
  endif()
endif()
