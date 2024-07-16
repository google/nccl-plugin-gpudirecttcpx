/*
 Copyright 2024 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

cmake_minimum_required(VERSION 3.15)

project(net-tcpx VERSION 3.1.9)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STARDARD_REQUIRED True)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")

set(CMAKE_CUDA_ARCHITECTURES 90)
# set(CMAKE_CUDA_ARCHITECTURES 70)
set(CMAKE_CUDA_COMPILER /usr/local/cuda/bin/nvcc)
# set(ENV{CUDACXX} /usr/local/cuda/bin/nvcc)

enable_language(CUDA)
find_package(CUDAToolkit REQUIRED)
include_directories(${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES})

set(CUDA_TOOLKIT_ROOT_DIR /usr/local/cuda)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# set(CMAKE_BUILD_TYPE Debug)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3")
if (DEFINED VERBOSE)
else ()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter -Wno-stringop-truncation")
endif ()

set(CMAKE_CXX_FLAGS_DEBUG "-g")
# set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# foreach(flag IN LISTS CMAKE_CXX_FLAGS)
#     add_compile_options("$<$<COMPILE_LANGUAGE:CUDA>:--compiler-options=${flag}>")
# endforeach()

message("1 ${CMAKE_CXX_COMPILER}")
message("2 ${CMAKE_CXX_FLAGS}")

# building the NCCL plugin

function(DETECT_PATH name path)
if (NOT DEFINED ${path})
  message(FATAL_ERROR "${name} undefined, define ${path}")
elseif(NOT EXISTS ${${path}})
  message(FATAL_ERROR "${name} not found, ${path}=${${path}}")
else()
  message(STATUS "${name} found ${path}=${${path}}")
endif()
endfunction()

DETECT_PATH(nccl NCCL_PATH)
set(NCCL_SRC_INCLUDE_PATH ${NCCL_PATH}/src/include)
set(NCCL_BUILD_INCLUDE_PATH ${NCCL_PATH}/build/include)
if(NOT DEFINED NCCL_VERSION)
  set(NCCL_UNPACK_INCLUDE_PATH ${NCCL_PATH}/src/collectives/device/network/unpack)
elseif( ${NCCL_VERSION} VERSION_LESS "2.19")
  set(NCCL_UNPACK_INCLUDE_PATH ${NCCL_PATH}/src/collectives/device/network/unpack)
else()
  set(NCCL_UNPACK_INCLUDE_PATH ${NCCL_PATH}/src/device/network/unpack/)
endif()
if (NOT EXISTS ${NCCL_UNPACK_INCLUDE_PATH})
  message(FATAL_ERROR "${NCCL_UNPACK_INCLUDE_PATH} not found, consider setting NCCL_VERSION if above 2.19, e.g. NCCL_VERSION=2.19.3")
endif()

if (NOT DEFINED NET_GPUDIRECTTCPX_EXPORT)
 message(FATAL_ERROR "export type undefined, e.g. NET_GPUDIRECTTCPX_EXPORT=nccl")
endif()

set(NET_GPUDIRECTTCPX_ADAPTER ${NET_GPUDIRECTTCPX_EXPORT})
set(NET_GPUDIRECTTCPX_ADAPTER_LIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/adapter/${NET_GPUDIRECTTCPX_EXPORT})
set(NET_GPUDIRECTTCPX_DEVCOMM ${NET_GPUDIRECTTCPX_EXPORT})
set(NET_GPUDIRECTTCPX_FLAGS_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_LIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/rx_buf_mgr_client/)
set(NET_GPUDIRECTTCPX_MISC_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/misc)
set(NET_GPUDIRECTTCPX_GPU_LIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/gpu)

#

configure_file(src/config.h.in src/config.h)

add_subdirectory(src)

add_library(${NET_GPUDIRECTTCPX_EXPORT}-net SHARED
  src/nccl_plugin.cc
)
target_link_libraries(${NET_GPUDIRECTTCPX_EXPORT}-net
  PRIVATE
  net_tcpx
)

message("${NET_GPUDIRECTTCPX_EXPORT}-net built")
