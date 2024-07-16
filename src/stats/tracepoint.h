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

#ifndef NET_GPUDIRECTTCPX_STATS_TRACEPOINTS_H_
#define NET_GPUDIRECTTCPX_STATS_TRACEPOINTS_H_

#include "../macro.h"
#include "../work_queue_states.h"
#include "monitoring.h"

#define VA_ARGS(...) , ##__VA_ARGS__
#define TCPX_TP(type, point, ...) tcpxTP_##type(point VA_ARGS(__VA_ARGS__))

enum tcpxTaskTp {
  // Trace point for TCPX task inactive state
  TCPX_TASK_TP_STATE_INACTIVE = TASK_INACTIVE,
  // Trace point for TCPX task completing state
  TCPX_TASK_TP_STATE_COMPLETING = TASK_COMPLETING,
  // Trace point for TCPX task active state
  TCPX_TASK_TP_STATE_ACTIVE = TASK_ACTIVE,
  // Trace point for TCPX task free state
  TCPX_TASK_TP_STATE_FREE = TASK_FREE,

  // Trace point for TCPX tx send msg
  TCPX_TASK_TP_SENDMSG = TASK_MAX_STATES + 0,
  // Trace point for TCPX rx recv msg
  TCPX_TASK_TP_RECVMSG = TASK_MAX_STATES + 1,
  // Trace point for TCPX tx completion
  TCPX_TASK_TP_COMPLETION = TASK_MAX_STATES + 2,
};

enum tcpxRequestTp {
  // Trace point for TCPX request inactive state
  TCPX_REQUEST_TP_STATE_INACTIVE = REQUEST_INACTIVE,
  // Trace point for TCPX request transmitting state
  TCPX_REQUEST_TP_STATE_TRANSMITTING = REQUEST_TRANSMITTING,
  // Trace point for TCPX request active state
  TCPX_REQUEST_TP_STATE_ACTIVE = REQUEST_ACTIVE,
  // Trace point for TCPX request posted state
  TCPX_REQUEST_TP_STATE_POSTED = REQUEST_POSTED,
  // Trace point for TCPX request free state
  TCPX_REQUEST_TP_STATE_FREE = REQUEST_FREE,
};

enum {
  REQUEST_FREE_TS=0,
  REQUEST_INACTIVE_TS = 1,
  REQUEST_TRANSMITTING_TS = 2,
  REQUEST_ACTIVE_TS = 3,
  REQUEST_POSTED_TS = 4,
  REQUEST_TS_MAX = 5,
};

enum {
  TASK_FREE_TS=0,
  TASK_INACTIVE_TS = 1,
  TASK_COMPLETING_TS = 2,
  TASK_ACTIVE_TS = 3,
  TASK_TS_MAX = 4,
  TASK_COMPLETION_TS = 5,
  TASK_SENDMSG_TS = 6,
  TASK_RECVMSG_TS = 7,
};

void tcpxTP_TASK(tcpxTaskTp point, struct tcpxTask* t, int bytes,
                 uint64_t count);

// A special TP for tx completion slowness, as the caller has
// info from comm/fd_data, not task.
void tcpxTP_TASK(tcpxTaskTp point, struct tcpxComm* comm, int idx);

void tcpxTP_REQUEST(tcpxRequestTp point, struct tcpxRequest* request);

#endif  // NET_GPUDIRECTTCPX_STATS_TRACEPOINTS_H_
