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
DETECT_PATH(misc NET_GPUDIRECTTCPX_MISC_PATH)
find_package(GTest CONFIG REQUIRED)
find_package(absl REQUIRED)
file(GLOB NET_GPUDIRECTTCPX_STATS_LIB_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/monitoring.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/tracepoint.cc
)

file(GLOB NET_GPUDIRECTTCPX_STATS_LIB_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/exporter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/stats_buffer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/monitoring.h
  ${CMAKE_CURRENT_SOURCE_DIR}/tracepoint.h
)

add_library(net_gpudirecttcpx_stats_lib STATIC
  ${NET_GPUDIRECTTCPX_STATS_LIB_HEADERS} ${NET_GPUDIRECTTCPX_STATS_LIB_SOURCES})
target_link_libraries(net_gpudirecttcpx_stats_lib
  PUBLIC
    net_tcpx
    net_gpudirecttcpx_adapter_lib
    net_gpudirecttcpx_gpu_lib
    net_gpudirecttcpx_misc
    net_gpudirecttcpx_devcomm_lib
    net_gpudirecttcpx_rxbufmgrclient_lib
    net_gpudirecttcpx_sock_lib
)
target_include_directories(net_gpudirecttcpx_stats_lib
  PRIVATE
  ${NET_GPUDIRECTTCPX_ADAPTER_LIB_PATH}
  ${NET_GPUDIRECTTCPX_MISC_PATH}
)

if (USE_CUDA)
  enable_language(CUDA)
  target_include_directories(net_gpudirecttcpx_stats_lib
    PRIVATE
    ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES}
  )
endif()

target_include_directories(net_gpudirecttcpx_stats_lib
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

enable_testing()

add_executable(tracepoint_test
${CMAKE_CURRENT_SOURCE_DIR}/tracepoint_test.cc
)
target_link_libraries(tracepoint_test
  PUBLIC
    net_gpudirecttcpx_stats_lib
)
enable_testing()
add_executable(stats_buffer_test ${CMAKE_CURRENT_SOURCE_DIR}/stats_buffer_test.cc)

target_link_libraries(stats_buffer_test
  PUBLIC
    net_gpudirecttcpx_stats_lib GTest::gtest_main absl::synchronization
)

message("net_gpudirecttcpx_stats_lib built")