# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

enable_language(CUDA)

function(DETECT_PATH name path)
  if(NOT DEFINED ${path})
    message(FATAL_ERROR "${name} undefined, define ${path}")
  elseif(NOT EXISTS ${${path}})
    message(FATAL_ERROR "${name} not found, ${path}=${${path}}")
  else()
    message(STATUS "${name} found ${path}=${${path}}")
  endif()
endfunction()

DETECT_PATH(nccl_src_include NCCL_SRC_INCLUDE_PATH)
DETECT_PATH(nccl_build_include NCCL_BUILD_INCLUDE_PATH)

file(GLOB NET_GPUDIRECTTCPX_ADAPTER_NCCL_LIB_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)
file(GLOB NET_GPUDIRECTTCPX_ADAPTER_NCCL_LIB_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cu
)

# message("building net_gpudirecttcpx_adapter_nccl_lib...")
add_library(net_gpudirecttcpx_adapter_nccl_lib STATIC
  ${NET_GPUDIRECTTCPX_ADAPTER_NCCL_LIB_HEADERS}
  ${NET_GPUDIRECTTCPX_ADAPTER_NCCL_LIB_SOURCES}
)
target_include_directories(net_gpudirecttcpx_adapter_nccl_lib
  PUBLIC
  ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES}
  ${NCCL_SRC_INCLUDE_PATH}
  ${NCCL_BUILD_INCLUDE_PATH}
)
