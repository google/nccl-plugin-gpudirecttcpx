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

DETECT_PATH(adapter NET_GPUDIRECTTCPX_ADAPTER_LIB_PATH)
DETECT_PATH(rxbufmgrclient NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_LIB_PATH)
DETECT_PATH(flags NET_GPUDIRECTTCPX_FLAGS_PATH)
DETECT_PATH(misc NET_GPUDIRECTTCPX_MISC_PATH)

#
file(GLOB NET_GPUDIRECTTCPX_POOLS_LIB_HEADERS 
  ${CMAKE_CURRENT_SOURCE_DIR}/rx_pool.h
  ${CMAKE_CURRENT_SOURCE_DIR}/tx_pool.h
)
file(GLOB NET_GPUDIRECTTCPX_POOLS_LIB_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/rx_pool.cu
  ${CMAKE_CURRENT_SOURCE_DIR}/tx_pool.cu
)

add_library(net_gpudirecttcpx_pools_lib STATIC 
  ${NET_GPUDIRECTTCPX_POOLS_LIB_HEADERS} ${NET_GPUDIRECTTCPX_POOLS_LIB_SOURCES})
target_link_libraries(net_gpudirecttcpx_pools_lib
  PRIVATE
  net_gpudirecttcpx_adapter_lib
  net_gpudirecttcpx_rxbufmgrclient_lib
  net_gpudirecttcpx_misc
)

set_target_properties(net_gpudirecttcpx_pools_lib
  PROPERTIES 
    LINKER_LANGUAGE CXX
    CUDA_RUNTIME_LIBRARY Shared
)
target_link_libraries(net_gpudirecttcpx_pools_lib
  PUBLIC
    net_gpudirecttcpx_rxbufmgrclient_lib 
  PRIVATE 
    CUDA::cuda_driver
)

target_include_directories(net_gpudirecttcpx_pools_lib
  PRIVATE
    ${NET_GPUDIRECTTCPX_FLAGS_PATH}
)

target_include_directories(net_gpudirecttcpx_pools_lib 
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

#
file(GLOB NET_GPUDIRECTTCPX_GPU_LIB_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/common.h
  ${CMAKE_CURRENT_SOURCE_DIR}/cuda_wrapper.h
)
file(GLOB NET_GPUDIRECTTCPX_GPU_LIB_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/common.cu
  ${CMAKE_CURRENT_SOURCE_DIR}/cuda_wrapper.cu
)

add_library(net_gpudirecttcpx_gpu_lib STATIC
  ${NET_GPUDIRECTTCPX_GPU_LIB_HEADERS} ${NET_GPUDIRECTTCPX_GPU_LIB_SOURCES})
target_link_libraries(net_gpudirecttcpx_gpu_lib
  PUBLIC
  net_gpudirecttcpx_adapter_lib
  net_gpudirecttcpx_pools_lib
  net_gpudirecttcpx_rxbufmgrclient_lib
  net_gpudirecttcpx_misc
  PRIVATE
  CUDA::cuda_driver
)
target_include_directories(net_gpudirecttcpx_gpu_lib
  PRIVATE
  ${NET_GPUDIRECTTCPX_ADAPTER_LIB_PATH}
  ${NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_LIB_PATH}
  ${NET_GPUDIRECTTCPX_MISC_PATH}
  ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES}
)

if (USE_CUDA)
  enable_language(CUDA)
  target_include_directories(net_gpudirecttcpx_gpu_lib
    PRIVATE
    ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES}
  )
endif()


target_include_directories(net_gpudirecttcpx_gpu_lib
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

message("net_gpudirecttcpx_gpu_lib built")
