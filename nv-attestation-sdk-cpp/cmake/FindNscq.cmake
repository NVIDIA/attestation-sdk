include(FindPackageHandleStandardArgs)

find_library(Nscq_LIBRARY NAMES nvidia-nscq libnvidia-nscq
  HINTS
    "${Nscq_ROOT}"
    "${NSCQ_ROOT}"
    ENV Nscq_ROOT
    ENV NSCQ_ROOT
    /usr/lib/x86_64-linux-gnu
  REQUIRED
)

mark_as_advanced(Nscq_LIBRARY)

find_package_handle_standard_args(Nscq
  REQUIRED_VARS Nscq_LIBRARY)
