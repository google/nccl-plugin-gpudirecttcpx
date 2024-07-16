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

find_package(absl REQUIRED)

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


add_subdirectory(proto)

file(GLOB NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_LIB_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/application_registry_client.h
  ${CMAKE_CURRENT_SOURCE_DIR}/flow_steer_ntuple.h
  ${CMAKE_CURRENT_SOURCE_DIR}/flow_steer_proto_utils.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rx_rule_client.h
  ${CMAKE_CURRENT_SOURCE_DIR}/unix_socket_client.h
  ${CMAKE_CURRENT_SOURCE_DIR}/unix_socket_connection.h
)
file(GLOB NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_LIB_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/application_registry_client.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/flow_steer_proto_utils.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rx_rule_client.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/unix_socket_client.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/unix_socket_connection.cc
)

add_library(net_gpudirecttcpx_rxbufmgrclient_lib STATIC 
  ${NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_LIB_HEADERS} ${NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_LIB_SOURCES})

set_target_properties(net_gpudirecttcpx_rxbufmgrclient_lib
  PROPERTIES
    LINKER_LANGUAGE CXX
    POSITION_INDEPENDENT_CODE ON
)
target_link_libraries(net_gpudirecttcpx_rxbufmgrclient_lib
  PUBLIC
    proto
  PRIVATE 
    net_gpudirecttcpx_adapter_lib
    net_gpudirecttcpx_misc
    absl::raw_hash_set
    absl::status
    absl::statusor
    absl::strings
    absl::str_format
)
target_include_directories(net_gpudirecttcpx_rxbufmgrclient_lib
  PRIVATE
  ${NET_GPUDIRECTTCPX_ADAPTER_LIB_PATH}
  ${NET_GPUDIRECTTCPX_MISC_PATH}
)

if (USE_CUDA)
  enable_language(CUDA)
  target_include_directories(net_gpudirecttcpx_rxbufmgrclient_lib
    PRIVATE
    ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES}
  )
endif()


target_include_directories(net_gpudirecttcpx_rxbufmgrclient_lib
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
