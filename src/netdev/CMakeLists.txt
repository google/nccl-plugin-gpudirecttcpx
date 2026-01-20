# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
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

file(GLOB NET_GPUDIRECTTCPX_NETDEV_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.h)
file(GLOB NET_GPUDIRECTTCPX_NETDEV_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cc)

add_library(net_gpudirecttcpx_netdev STATIC
  ${NET_GPUDIRECTTCPX_NETDEV_HEADERS} ${NET_GPUDIRECTTCPX_NETDEV_SOURCES})

set_target_properties(net_gpudirecttcpx_netdev
  PROPERTIES
    LINKER_LANGUAGE CXX
)

target_link_libraries(net_gpudirecttcpx_netdev
  PRIVATE
    libmnl.so
)

target_link_libraries(net_gpudirecttcpx_netdev
  PUBLIC
    net_gpudirecttcpx_adapter_lib
)

target_include_directories(net_gpudirecttcpx_netdev
     PRIVATE
     ${NET_GPUDIRECTTCPX_ADAPTER_LIB_PATH})

target_include_directories(net_gpudirecttcpx_netdev
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

message("net_gpudirecttcpx_netdev built")
