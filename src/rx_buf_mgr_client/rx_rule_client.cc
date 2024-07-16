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

#include "rx_rule_client.h"

#include <memory>
#include <absl/status/status.h>
#include <absl/strings/str_format.h>

#include "debug1.h"
#include "flow_steer_ntuple.h"
#include "flow_steer_proto_utils.h"
#include "linux/ethtool.h"
#include "socket_utils.h"
#include "unix_socket_client.h"
#include "unix_socket_message.pb.h"

RxRuleClient::RxRuleClient(const std::string& prefix) {
  prefix_ = prefix;
  if (prefix_.back() == '/') {
    prefix_.pop_back();
  }
}

absl::Status RxRuleClient::UpdateFlowSteerRule(
    FlowSteerRuleOp op, const FlowSteerNtuple& flow_steer_ntuple,
    std::string gpu_pci_addr, int qid) {
  std::string server_addr =
      (op == CREATE) ? "rx_rule_manager" : "rx_rule_uninstall";

  auto us_client = std::make_unique<UnixSocketClient>(
      absl::StrFormat("%s/%s", prefix_, server_addr));

  UnixSocketMessage message;

  UnixSocketProto* proto = message.mutable_proto();
  FlowSteerRuleRequest* fsr = proto->mutable_flow_steer_rule_request();
  *fsr->mutable_flow_steer_ntuple() = ConvertStructToProto(flow_steer_ntuple);

  if (!gpu_pci_addr.empty()) {
    fsr->set_gpu_pci_addr(gpu_pci_addr);
  }

  if (qid >= 0) {
    fsr->set_queue_id(qid);
  }

  UnixSocketMessage response;

  if (auto status = ConnectAndSendMessage(message, &response, us_client.get());
      !status.ok()) {
    return status;
  }

  if (!response.has_proto() || !response.proto().has_raw_bytes() ||
      response.proto().raw_bytes() != "Ok.") {
    return absl::InternalError(absl::StrFormat(
        "%s FlowSteerRule Failed: %s, request was %s", op == CREATE ? "Create" : "Delete", response.DebugString(), fsr->DebugString()));
  }

  return absl::OkStatus();
}

absl::Status UpdateFlowSteerRule(const union socketAddress& from,
                                 const union socketAddress& to, FlowSteerRuleOp op, std::string gpu_pci_addr) {
  char buf_f[128], buf_t[128];
  INFO(TCPX_NET, "%s flow steer rule: %s -> %s",
       (op == 0 ? "Create" : "Delete"), socketToString(&from, buf_f),
       socketToString(&to, buf_t));

  std::unique_ptr<RxRuleClient> client;
  char* env = TCPX_GET_ENV("UNIX_CLIENT_PREFIX");
  if (env) {
    INFO(TCPX_NET, "using unix client prefix '%s'", env);
    client = std::make_unique<RxRuleClient>(env);
  } else {
    client = std::make_unique<RxRuleClient>("/tmp");  // default
  }
  FlowSteerNtuple ntuple;
  if (from.sa.sa_family == AF_INET) {
    ntuple.flow_type = TCP_V4_FLOW;
    memcpy(&ntuple.src_sin, &from.sin, sizeof(ntuple.src_sin));
    memcpy(&ntuple.dst_sin, &to.sin, sizeof(ntuple.dst_sin));
  } else {
    ntuple.flow_type = TCP_V6_FLOW;
    memcpy(&ntuple.src_sin6, &from.sin6, sizeof(ntuple.src_sin6));
    memcpy(&ntuple.dst_sin6, &to.sin6, sizeof(ntuple.dst_sin6));
  }
  if (auto status = client->UpdateFlowSteerRule(
          (op == CREATE ? FlowSteerRuleOp::CREATE : FlowSteerRuleOp::DELETE),
          ntuple, gpu_pci_addr);
      !status.ok()) {
    return status;
  }

  return absl::OkStatus();
}