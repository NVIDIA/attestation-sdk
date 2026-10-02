# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
# All rights reserved. SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# CPU count usable by this process, for sizing `make -j` in the external
# projects.
#
# ProcessorCount() reports the CPU affinity mask, which reflects a cpuset
# (docker --cpuset-cpus) but NOT a bandwidth quota (docker --cpus=N, Kubernetes
# CPU limits). Under a quota a container still sees every host CPU, so affinity
# alone over-subscribes badly on a large shared machine. Take the smaller of the
# affinity count and ceil(quota / period), which is what Rust, Go and the JVM do.
#
# Only the leaf cgroup is read; a tighter limit on a parent is not detected.
function(nvat_available_cpus out_var)
  include(ProcessorCount)
  ProcessorCount(_cpus)
  if(_cpus EQUAL 0)
    set(_cpus 1)
  endif()

  # CPUs allowed by a bandwidth quota, or 0 when there is no quota. The quota
  # is microseconds of CPU time per period, so quota/period is the CPU count:
  # "200000 100000" means 200ms every 100ms, i.e. 2 CPUs.
  set(_quota 0)
  if(EXISTS "/sys/fs/cgroup/cpu.max")
    # cgroup v2: "<quota> <period>", or "max <period>" when unlimited.
    file(READ "/sys/fs/cgroup/cpu.max" _cpu_max)
    # Two numbers means a quota is set. "max" is not digits, so an unlimited
    # container falls through with _quota still 0.
    if("${_cpu_max}" MATCHES "([0-9]+)[ \t]+([0-9]+)")
      # MATCHES sets CMAKE_MATCH_1 = quota, CMAKE_MATCH_2 = period.
      # math() truncates, so (a + b - 1) / b rounds up instead of down.
      # Rounding matters for fractional limits: --cpus=0.5 would truncate to
      # 0, and `make -j0` is an error.
      math(EXPR _quota "(${CMAKE_MATCH_1} + ${CMAKE_MATCH_2} - 1) / ${CMAKE_MATCH_2}")
    endif()
  elseif(EXISTS "/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
    # cgroup v1: same two numbers in separate files; quota is -1 when
    # unlimited, which the GREATER 0 check below rejects.
    file(READ "/sys/fs/cgroup/cpu/cpu.cfs_quota_us" _q)
    file(READ "/sys/fs/cgroup/cpu/cpu.cfs_period_us" _p)
    string(STRIP "${_q}" _q)
    string(STRIP "${_p}" _p)
    if(_q GREATER 0 AND _p GREATER 0)
      math(EXPR _quota "(${_q} + ${_p} - 1) / ${_p}")
    endif()
  endif()

  # A quota can only lower the count; affinity already bounds it from above.
  if(_quota GREATER 0 AND _quota LESS _cpus)
    set(_cpus ${_quota})
  endif()
  set(${out_var} ${_cpus} PARENT_SCOPE)
endfunction()

# Resolves the job count for the external projects into NVAT_BUILD_JOBS:
# an explicit -DCMAKE_BUILD_PARALLEL_LEVEL wins, then the environment variable
# of the same name, then the detected CPU count.
#
# CMake does not import environment variables into ${...}, so the bare
# ${CMAKE_BUILD_PARALLEL_LEVEL} previously expanded to nothing and the external
# projects ran `make -j` with no limit.
function(nvat_resolve_build_jobs out_var)
  if(CMAKE_BUILD_PARALLEL_LEVEL)
    set(_jobs "${CMAKE_BUILD_PARALLEL_LEVEL}")
    set(_source "cmake variable")
  elseif(DEFINED ENV{CMAKE_BUILD_PARALLEL_LEVEL} AND NOT "$ENV{CMAKE_BUILD_PARALLEL_LEVEL}" STREQUAL "")
    set(_jobs "$ENV{CMAKE_BUILD_PARALLEL_LEVEL}")
    set(_source "environment")
  else()
    nvat_available_cpus(_jobs)
    set(_source "detected")
  endif()
  message(STATUS "External project build parallelism: ${_jobs} (${_source})")
  set(${out_var} ${_jobs} PARENT_SCOPE)
endfunction()
