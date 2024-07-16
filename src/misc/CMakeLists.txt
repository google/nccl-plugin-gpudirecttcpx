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

#
file(GLOB NET_GPUDIRECTTCPX_MISC_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.h)
file(GLOB NET_GPUDIRECTTCPX_MISC_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cc)

add_library(net_gpudirecttcpx_misc STATIC
  ${NET_GPUDIRECTTCPX_MISC_HEADERS} ${NET_GPUDIRECTTCPX_MISC_SOURCES})
target_link_libraries(net_gpudirecttcpx_misc
  PUBLIC
  net_gpudirecttcpx_adapter_lib
)
target_include_directories(net_gpudirecttcpx_misc
  PRIVATE
  ${NET_GPUDIRECTTCPX_ADAPTER_LIB_PATH}
)

if (USE_CUDA)
  enable_language(CUDA)
  target_include_directories(net_gpudirecttcpx_misc
    PRIVATE
    ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES}
  )
endif()


target_include_directories(net_gpudirecttcpx_misc
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

message("net_gpudirecttcpx_misc built")
