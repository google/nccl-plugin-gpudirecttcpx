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

#ifndef NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_RX_RULE_CLIENT_H_
#define NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_RX_RULE_CLIENT_H_

#include <memory>
#include <string>

#include <absl/status/status.h>

#include "flow_steer_ntuple.h"


enum FlowSteerRuleOp {
  CREATE = 0,
  DELETE = 1,
};

class RxRuleClient {
 public:
  explicit RxRuleClient(const std::string& prefix);
  absl::Status UpdateFlowSteerRule(FlowSteerRuleOp op,
                                   const FlowSteerNtuple& flow_steer_ntuple,
                                   std::string gpu_pci_addr = "", int qid = -1);

 private:
  std::string prefix_;
};

absl::Status UpdateFlowSteerRule(const union socketAddress& from,
                                 const union socketAddress& to, FlowSteerRuleOp op, std::string gpu_pci_addr = "");


#endif  // NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_RX_RULE_CLIENT_H_