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

add_subdirectory(adapter)
add_subdirectory(gpu)
add_subdirectory(misc)
add_subdirectory(devcomm)
add_subdirectory(rx_buf_mgr_client)
add_subdirectory(sock)
add_subdirectory(stats)

add_library(net_gpudirecttcpx_flags STATIC
  flags.cc)
target_link_libraries(net_gpudirecttcpx_flags
  PUBLIC
    net_gpudirecttcpx_adapter_lib
)

add_library(net_gpudirecttcpx_timeout_lib STATIC
  timeout.cc)
target_link_libraries(net_gpudirecttcpx_timeout_lib
  PUBLIC
    net_gpudirecttcpx_adapter_lib
    net_gpudirecttcpx_flags
)

file(GLOB LIB_HEADERS
  common.h
  connect.h
  flow_mapper.h
  macro.h
  net_tcpx.h
  work_queue.h
)
file(GLOB LIB_SOURCES
  common.cc
  connect.cc
  net_tcpx.cc
  work_queue.cc
)

add_library(net_tcpx STATIC ${LIB_HEADERS} ${LIB_SOURCES})

set_target_properties(net_tcpx
  PROPERTIES
    CUDA_RUNTIME_LIBRARY Shared
)
target_include_directories(net_tcpx
  PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
  PRIVATE
    ${NCCL_INCLUDE_PATH}
    ${NCCL_UNPACK_INCLUDE_PATH}
)

target_link_libraries(net_tcpx
  PUBLIC
    net_gpudirecttcpx_adapter_lib
    net_gpudirecttcpx_gpu_lib
    net_gpudirecttcpx_misc
    net_gpudirecttcpx_devcomm_lib
    net_gpudirecttcpx_rxbufmgrclient_lib
    net_gpudirecttcpx_sock_lib
    net_gpudirecttcpx_stats_lib
    net_gpudirecttcpx_timeout_lib
    net_gpudirecttcpx_flags
  PRIVATE
    Threads::Threads
    CUDA::cuda_driver
    -static-libgcc -static-libstdc++
)
