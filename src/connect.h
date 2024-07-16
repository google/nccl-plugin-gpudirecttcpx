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

#ifndef NET_GPUDIRECTTCPX_CONNECT_H_
#define NET_GPUDIRECTTCPX_CONNECT_H_

#include <stdint.h>

#include "adapter1.h"

/***** external API *****/

extern int kFlowSteeringStrategy;

enum FlowSteeringStrategy {
  OFF = 0,
  FIXED_PORTS = 1,
  SIMULATE = 2,
  UNIX_CLIENT = 3,
};

struct tcpxConnectionSetup {
  tcpxResult_t (*listen)(void* ctx, int dev, void *opaqueHandle, void **listenComm);
  tcpxResult_t (*connect)(void* ctx, int dev, void* opaqueHandle, void** sendComm);
  tcpxResult_t (*accept)(void* ctx, void *listenComm, void **recvComm);

  void* ctx;
};
tcpxResult_t tcpxInitConnectionSetup(void** osetup);
tcpxResult_t DeleteFlowSteerRule(int fd, void* gpu);

#endif  // NET_GPUDIRECTTCPX_CONNECT_H_