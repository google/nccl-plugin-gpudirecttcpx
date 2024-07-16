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

if(NOT DEFINED NET_GPUDIRECTTCPX_ADAPTER)
  message(FATAL_ERROR "define adapter, e.g. NET_GPUDIRECTTCPX_ADAPTER=nccl")
elseif(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${NET_GPUDIRECTTCPX_ADAPTER}/)
  message(FATAL_ERROR "selected invalid adapter, ${CMAKE_CURRENT_SOURCE_DIR}/${NET_GPUDIRECTTCPX_ADAPTER}/")
endif()

add_subdirectory(${NET_GPUDIRECTTCPX_ADAPTER})

# message("building net_gpudirecttcpx_adapter_lib...")
add_library(net_gpudirecttcpx_adapter_lib STATIC
  adapter1.cc # cmake doesn't allow empty target
)
target_link_libraries(net_gpudirecttcpx_adapter_lib
  PUBLIC
  net_gpudirecttcpx_adapter_${NET_GPUDIRECTTCPX_ADAPTER}_lib
)
target_include_directories(net_gpudirecttcpx_adapter_lib
  INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}
)

#
message("built adapter ${NET_GPUDIRECTTCPX_ADAPTER}")