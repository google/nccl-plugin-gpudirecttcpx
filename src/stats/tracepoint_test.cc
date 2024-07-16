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

#include "tracepoint.h"

#include <cassert>
#include <iostream>

#include "../common.h"
#include "../work_queue.h"
#include "monitoring.h"

void testSetup(struct tcpxTask* task) {
#ifdef TCPX_TRACEPOINT
  tcpxTaskInit(task, NULL, 0);
  TCPXASSERT(tcpxCalloc(&(task->r), 1));

  struct tcpxComm* comm;
  TCPXASSERT(tcpxCalloc(&comm, 1));
  for (int i = 0; i < MAX_SOCKETS; i++) {
    tcpxSocketStatsInit(&(comm->fd_data[i].stats));
  }
  task->r->comm = comm;
#endif
}

void testTearDown(struct tcpxTask* task) {
#ifdef TCPX_TRACEPOINT
  tcpxCommFree(task->r->comm);
  free(task->r);
#endif
}

bool testTcpxTpTaskTxCnt(struct tcpxTask* task) {
#ifdef TCPX_TRACEPOINT
  uint64_t initialTxCount = task->r->comm->fd_data[task->fd_idx].stats.tx_cnt;
  int bytes = 100;
  tcpxTP_TASK(TCPX_TASK_TP_SENDMSG, task, bytes, 1);
  if (task->r->comm->fd_data[task->fd_idx].stats.tx_cnt != initialTxCount + 1) {
    return false;
  }
  bytes = -1;
  tcpxTP_TASK(TCPX_TASK_TP_SENDMSG, task, bytes, 1);
  if (task->r->comm->fd_data[task->fd_idx].stats.tx_cnt != initialTxCount + 1) {
    return false;
  }
#endif
  return true;
}

bool testTcpxTpTaskRxCnt(struct tcpxTask* task) {
#ifdef TCPX_TRACEPOINT
  uint64_t initialRxCount = task->r->comm->fd_data[task->fd_idx].stats.rx_cnt;
  int bytes = 1000;
  tcpxTP_TASK(TCPX_TASK_TP_RECVMSG, task, bytes, 1);
  if (task->r->comm->fd_data[task->fd_idx].stats.rx_cnt != initialRxCount + 1) {
    return false;
  }
  bytes = -100;
  tcpxTP_TASK(TCPX_TASK_TP_RECVMSG, task, bytes, 1);
  // Rx cnt alway ++
  if (task->r->comm->fd_data[task->fd_idx].stats.rx_cnt != initialRxCount + 2) {
    return false;
  }
#endif
  return true;
}

bool testTcpxTpTaskCompleteCnt(struct tcpxTask* task) {
#ifdef TCPX_TRACEPOINT
  uint64_t initialCompleteCount =
      task->r->comm->fd_data[task->fd_idx].stats.tx_completion_cnt;
  int bytes = 1000;
  tcpxTP_TASK(TCPX_TASK_TP_COMPLETION, task, bytes, 10);
  if (task->r->comm->fd_data[task->fd_idx].stats.tx_completion_cnt !=
      initialCompleteCount + 10) {
    return false;
  }
#endif
  return true;
}

bool testTcpxTpTaskCompleteSlowCnt(struct tcpxTask* task) {
#ifdef TCPX_TRACEPOINT
  tcpxTP_TASK(TCPX_TASK_TP_COMPLETION, task->r->comm, task->fd_idx);
#endif
  return true;
}

bool testTcpxTpTaskStates(struct tcpxTask* t) {
#ifdef TCPX_TRACEPOINT
  tcpxTP_TASK(TCPX_TASK_TP_STATE_INACTIVE, t, 0, 0);
  tcpxTP_TASK(TCPX_TASK_TP_STATE_ACTIVE, t, 0, 0);
  tcpxTP_TASK(TCPX_TASK_TP_STATE_COMPLETING, t, 0, 0);
  tcpxTP_TASK(TCPX_TASK_TP_STATE_FREE, t, 0, 0);
#endif
  return true;
}

bool testTcpxTpRequestStates(struct tcpxRequest* r) {
#ifdef TCPX_TRACEPOINT
  tcpxTP_REQUEST(TCPX_REQUEST_TP_STATE_INACTIVE, r);
  tcpxTP_REQUEST(TCPX_REQUEST_TP_STATE_ACTIVE, r);
  tcpxTP_REQUEST(TCPX_REQUEST_TP_STATE_TRANSMITTING, r);
  tcpxTP_REQUEST(TCPX_REQUEST_TP_STATE_FREE, r);
#endif
  return true;
}

int main() {
  struct tcpxTask task;
  testSetup(&task);
  if (testTcpxTpTaskTxCnt(&task) && testTcpxTpTaskRxCnt(&task) &&
      testTcpxTpTaskCompleteCnt(&task) && testTcpxTpTaskStates(&task)) {
    std::cout << "All tests passed!" << std::endl;
    return 0;
  } else {
    std::cerr << "Some tests failed!" << std::endl;
    return 1;
  }
}