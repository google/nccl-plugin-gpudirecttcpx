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

#
file(GLOB NET_GPUDIRECTTCPX_DATAPIPE_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/datapipe.h)
file(GLOB NET_GPUDIRECTTCPX_DATAPIPE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/datapipe.cc)

add_library(net_gpudirecttcpx_datapipe STATIC 
  ${NET_GPUDIRECTTCPX_DATAPIPE_HEADERS} ${NET_GPUDIRECTTCPX_DATAPIPE_SOURCES})

set_target_properties(net_gpudirecttcpx_datapipe
  PROPERTIES 
    LINKER_LANGUAGE CXX
)
target_link_libraries(net_gpudirecttcpx_datapipe
  PRIVATE
    net_gpudirecttcpx_devcomm_lib
    net_gpudirecttcpx_misc
)

target_include_directories(net_gpudirecttcpx_datapipe 
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

#
file(GLOB NET_GPUDIRECTTCPX_SOCK_LIB_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/tcpx.h)
file(GLOB NET_GPUDIRECTTCPX_SOCK_LIB_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tcpx.cc)

add_library(net_gpudirecttcpx_sock_lib STATIC 
  ${NET_GPUDIRECTTCPX_SOCK_LIB_HEADERS} ${NET_GPUDIRECTTCPX_SOCK_LIB_SOURCES})

set_target_properties(net_gpudirecttcpx_sock_lib
  PROPERTIES 
    LINKER_LANGUAGE CXX
)
target_link_libraries(net_gpudirecttcpx_sock_lib
  PUBLIC
    net_gpudirecttcpx_datapipe
)

target_include_directories(net_gpudirecttcpx_sock_lib 
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})