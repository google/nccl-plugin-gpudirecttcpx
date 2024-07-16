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
find_package(CUDAToolkit REQUIRED)

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
DETECT_PATH(nccl_unpack NCCL_UNPACK_INCLUDE_PATH)
DETECT_PATH(misc NET_GPUDIRECTTCPX_MISC_PATH)
DETECT_PATH(adapter NET_GPUDIRECTTCPX_ADAPTER_LIB_PATH)
DETECT_PATH(gpu NET_GPUDIRECTTCPX_GPU_LIB_PATH)

#
file(GLOB NET_GPUDIRECTTCPX_DEVCOMM_NCCL_LIB_HEADERS 
  ${CMAKE_CURRENT_SOURCE_DIR}/inline.h
  ${CMAKE_CURRENT_SOURCE_DIR}/unpack1.h
)
file(GLOB NET_GPUDIRECTTCPX_DEVCOMM_NCCL_LIB_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/inline.cu
  ${CMAKE_CURRENT_SOURCE_DIR}/unpack1.cu
)

add_library(net_gpudirecttcpx_devcomm_nccl_lib STATIC 
  ${NET_GPUDIRECTTCPX_DEVCOMM_NCCL_LIB_HEADERS} ${NET_GPUDIRECTTCPX_DEVCOMM_NCCL_LIB_SOURCES})

set_target_properties(net_gpudirecttcpx_devcomm_nccl_lib
  PROPERTIES 
    LINKER_LANGUAGE CXX
    CUDA_RUNTIME_LIBRARY Shared
)
target_link_libraries(net_gpudirecttcpx_devcomm_nccl_lib
  PRIVATE 
    CUDA::cuda_driver
    net_gpudirecttcpx_misc
)
target_include_directories(net_gpudirecttcpx_devcomm_nccl_lib 
  PUBLIC
    ${NCCL_SRC_INCLUDE_PATH}
    ${NCCL_BUILD_INCLUDE_PATH}
    ${NCCL_UNPACK_INCLUDE_PATH}
    ${NCCL_UNPACK_INCLUDE_PATH}/network/unpack
    ${NET_GPUDIRECTTCPX_ADAPTER_LIB_PATH}
    ${NET_GPUDIRECTTCPX_MISC_PATH}
    ${NET_GPUDIRECTTCPX_GPU_LIB_PATH}
)

if (USE_CUDA)
  enable_language(CUDA)
  target_include_directories(net_gpudirecttcpx_devcomm_nccl_lib
    PRIVATE
    ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES}
  )
endif()

target_include_directories(net_gpudirecttcpx_devcomm_nccl_lib 
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

message("net_gpudirecttcpx_devcomm_nccl_lib built")
