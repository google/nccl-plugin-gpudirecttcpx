/*
 Copyright 2024 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#include "flow_steer_proto_utils.h"

#include <linux/ethtool.h>

#include "flow_steer_ntuple.h"
#include "unix_socket_proto.pb.h"

#include <absl/log/check.h>
#include <absl/strings/match.h>
#include <arpa/inet.h>
#include <string>
#include <sys/socket.h>

#include "debug1.h"
#include "socket_utils.h"

void SetPortnum(union socketAddress *addr, uint16_t port) {
  if (addr->sa.sa_family == AF_INET) {
    addr->sin.sin_port = htons(port);
  } else {
    addr->sin6.sin6_port = htons(port);
  }
}

uint16_t GetPortnum(const union socketAddress *addr) {
  if (addr->sa.sa_family == AF_INET) {
    return ntohs(addr->sin.sin_port);
  } else {
    return ntohs(addr->sin6.sin6_port);
  }
}

union socketAddress AddressFromStr(const std::string &str) {
  union socketAddress addr;

  bool is_ipv6 = false;
  if (!absl::StrContains(str, '.')) {
    is_ipv6 = true;
  }
  int sa_family = is_ipv6 ? AF_INET6 : AF_INET;
  void *dst =
      is_ipv6 ? (void *)&addr.sin6.sin6_addr : (void *)&addr.sin.sin_addr;
  int ret = inet_pton(sa_family, str.c_str(), dst);
  CHECK(ret == 1);
  addr.sa.sa_family = sa_family;
  return addr;
}

std::string AddressToString(const union socketAddress &addr) {
  char buf[256];
  std::stringstream ss;
  if (addr.sa.sa_family == AF_INET) {
    const char *str =
        inet_ntop(addr.sa.sa_family, &addr.sin.sin_addr, buf, 256);
    ss << str;
    return ss.str();
  } else {
    CHECK(addr.sa.sa_family == AF_INET6);
    const char *str =
        inet_ntop(addr.sa.sa_family, &addr.sin6.sin6_addr, buf, 256);
    ss << str;
    return ss.str();
  }
  WARN("Unknown protocol");
  return "";
}

struct FlowSteerNtuple
ConvertProtoToStruct(const FlowSteerNtupleProto &ntuple_proto) {
  struct FlowSteerNtuple ntuple;
  ntuple.flow_type = ntuple_proto.flow_type();

  union socketAddress src_socket_address =
      AddressFromStr(ntuple_proto.src().ip_address());
  SetPortnum(&src_socket_address, ntuple_proto.src().port());

  union socketAddress dst_socket_address =
      AddressFromStr(ntuple_proto.dst().ip_address());
  SetPortnum(&dst_socket_address, ntuple_proto.dst().port());

  CHECK_EQ(src_socket_address.sa.sa_family, dst_socket_address.sa.sa_family);
  if (src_socket_address.sa.sa_family == AF_INET) {
    ntuple.src_sin = src_socket_address.sin;
    ntuple.dst_sin = dst_socket_address.sin;
  } else {
    ntuple.src_sin6 = src_socket_address.sin6;
    ntuple.dst_sin6 = dst_socket_address.sin6;
  }

  return ntuple;
}
FlowSteerNtupleProto
ConvertStructToProto(const struct FlowSteerNtuple &ntuple_struct) {
  FlowSteerNtupleProto ntuple_proto;
  ntuple_proto.set_flow_type(ntuple_struct.flow_type);

  auto *proto_src = ntuple_proto.mutable_src();
  auto *proto_dst = ntuple_proto.mutable_dst();

  const auto *src_address =
      ntuple_struct.flow_type == TCP_V4_FLOW
          ? (const union socketAddress *)&ntuple_struct.src_sin
          : (const union socketAddress *)&ntuple_struct.src_sin6;
  const auto *dst_address =
      ntuple_struct.flow_type == TCP_V4_FLOW
          ? (const union socketAddress *)&ntuple_struct.dst_sin
          : (const union socketAddress *)&ntuple_struct.dst_sin6;

  proto_src->set_ip_address(AddressToString(*src_address));
  proto_src->set_port(GetPortnum(src_address));

  proto_dst->set_ip_address(AddressToString(*dst_address));
  proto_dst->set_port(GetPortnum(dst_address));

  return ntuple_proto;
}