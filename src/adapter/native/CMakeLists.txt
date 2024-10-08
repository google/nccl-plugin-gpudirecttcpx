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

file(GLOB NET_GPUDIRECTTCPX_ADAPTER_NATIVE_LIB_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)
file(GLOB NET_GPUDIRECTTCPX_ADAPTER_NATIVE_LIB_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cu
)

# message("building net_gpudirecttcpx_adapter_native_lib...")
add_library(net_gpudirecttcpx_adapter_native_lib STATIC
  ${NET_GPUDIRECTTCPX_ADAPTER_NATIVE_LIB_HEADERS}
  ${NET_GPUDIRECTTCPX_ADAPTER_NATIVE_LIB_SOURCES}
)
target_include_directories(net_gpudirecttcpx_adapter_native_lib
  PUBLIC
  ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES}
)
