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

# Proto
include(FindProtobuf)
find_package(Protobuf REQUIRED)
find_package(absl REQUIRED)
include_directories(${Protobuf_INCLUDE_DIR})

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS unix_socket_proto.proto)
get_filename_component(PROTO_HDRS_DIR ${PROTO_HDRS} DIRECTORY)

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS unix_socket_proto.proto unix_socket_message.proto)
add_library(proto STATIC ${PROTO_HDRS} ${PROTO_SRCS})

message("PROTO_HDRS_DIR is ${PROTO_HDRS_DIR}")

target_include_directories(proto
  PUBLIC
  ${PROTO_HDRS_DIR}
)
target_link_libraries(proto
  PUBLIC
  ${Protobuf_LIBRARIES}
  absl::log_internal_message
  absl::log_internal_check_impl
  utf8_range
  utf8_validity
)
