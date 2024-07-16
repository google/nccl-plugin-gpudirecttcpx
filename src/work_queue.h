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

#ifndef NET_GPUDIRECTTCPX_WORK_QUEUE_H_
#define NET_GPUDIRECTTCPX_WORK_QUEUE_H_

#define MAX_REQUESTS 16
#define MAX_TASKS 6

#include <atomic>
#include <chrono>

#include <string.h>

#include "adapter1.h"
#include "alloc1.h"
#include "checks1.h"
#include "datapipe.h"
#include "inline.h"
#include "timeout.h"
#include "stats/tracepoint.h"
#include "unpack1.h"
#include "work_queue_states.h"

struct tcpxTask {
  int op;
  int size;
  int page_off;  // starting offset of this block of data on the GPUDirectTCPX Tx page
  int offset;
  int request_offset;  // request offset for recv tasks
  void* data;
  struct tcpxRequest* r;
  uint32_t tx_count;  // TX_ZCOPY
  uint32_t tx_bound;  // TX_ZCOPY

#define MAX_TX_COUNT 64
  uint32_t tx_sz[MAX_TX_COUNT];  // TX_ZCOPY
  uint32_t tx_i;

  tcpxResult_t result;

  tcpxDataPipe *pipe;

  int fd_idx; // task's socket index
  struct tcpxTimeoutDetection* timeout;
};
void tcpxTaskInit(struct tcpxTask* t, void* gpu, int fd_idx);
void tcpxTaskFree(struct tcpxTask* t);

struct tcpxRequest {
  struct tcpxComm* comm;
  void* data;
  int op;
  int mem_type;
  int next_sock_id;
  int next_size;
  int offset;
  int size;
  int size_pending;
  int gpu_mem_fd;
  int gpu_mem_off;
  struct unpackSlot unpack_slot;
};

template <typename IndexType, typename IndexUnderType, typename ItemType,
          int MAX_ITEMS, int NSTATES>
struct tcpxItemQueue {
  // 0: next dequeue slot, NSTATES - 1: next enqueue slot
  alignas(128) IndexType idx[NSTATES];
  alignas(128) ItemType items[MAX_ITEMS];
  tcpxItemQueue() {
    for (int i = 0; i < NSTATES; ++i) idx[i] = 0;
  }

  bool empty() { return idx[0] == idx[NSTATES - 1]; }
  int num_free() const { return (MAX_ITEMS - (idx[NSTATES - 1] - idx[0])); }
  bool has_free() const { return num_free() > 0; }

  template <int STATE>
  IndexType get_index() {
    if (STATE == 0) return idx[NSTATES - 1];
    return idx[STATE - 1];
  }

  template <int STATE>
  bool has() {
    if (STATE == 0) return has_free();
    return idx[STATE] > idx[STATE - 1];
  }

  template <int STATE>
  ItemType* first() {
    if (STATE == 0) return items + idx[NSTATES - 1] % MAX_ITEMS;
    return items + idx[STATE - 1] % MAX_ITEMS;
  }

  template <int STATE>
  void advance() {
    ++idx[STATE - 1];
  }

  void enqueue_internal() { ++idx[NSTATES - 1]; }
  void dequeue_internal() { ++idx[0]; }

  // For cases when we need to iterate through all items in a state (other than
  // 0).
  template <int STATE>
  IndexUnderType get_iterator() {
    return idx[STATE - 1];
  }
  IndexUnderType next(IndexUnderType it) { return it + 1; }
  template <int STATE>
  bool is(IndexUnderType it) {
    return it < idx[STATE];
  }
  ItemType* to_item(IndexUnderType it) { return items + it % MAX_ITEMS; }
};

struct tcpxTaskQueue
    : tcpxItemQueue<std::atomic_uint, unsigned, tcpxTask, MAX_TASKS,
                    TASK_MAX_STATES> {
  bool constructed;
  using Base = tcpxItemQueue<std::atomic_uint, unsigned, tcpxTask,
                             MAX_TASKS, TASK_MAX_STATES>;
  tcpxTaskQueue() : Base(), constructed(false) {}
  void construct(void* gpu, int fd_idx) {
    this->constructed = true;
    for (int i = 0; i < MAX_TASKS; ++i) tcpxTaskInit(items + i, gpu, fd_idx);
  }
  void destruct() {
    if (this->constructed) {
      for (int i = 0; i < MAX_TASKS; ++i)
        tcpxTaskFree(items + i);
    }
  }
  bool has_active() { return has<TASK_ACTIVE>(); }
  bool has_inactive() { return has<TASK_INACTIVE>(); }
  bool has_completing() { return has<TASK_COMPLETING>(); }
  tcpxTask* next_free() { return first<TASK_FREE>(); }
  tcpxTask* next_active() { return first<TASK_ACTIVE>(); }
  tcpxTask* next_completing() { return first<TASK_COMPLETING>(); }
  tcpxTask* next_inactive() { return first<TASK_INACTIVE>(); }
  void enqueue() {
    TCPX_TP(TASK, TCPX_TASK_TP_STATE_ACTIVE, next_free(), 0, 0);
    enqueue_internal();
  }
  void finish_active() {
    TCPX_TP(TASK, TCPX_TASK_TP_STATE_COMPLETING, next_active(), 0, 0);
    advance<TASK_ACTIVE>();
  }
  void finish_completing() {
    TCPX_TP(TASK, TCPX_TASK_TP_STATE_INACTIVE, next_completing(), 0, 0);
    advance<TASK_COMPLETING>();
  }
  void dequeue() {
    TCPX_TP(TASK, TCPX_TASK_TP_STATE_FREE, next_inactive(), 0, 0);
    dequeue_internal();
  }
};

struct tcpxRequestQueue
    : tcpxItemQueue<uint32_t, uint32_t, struct tcpxRequest, MAX_REQUESTS,
                    REQUEST_MAX_STATES> {
  using Base = tcpxItemQueue<uint32_t, uint32_t, struct tcpxRequest,
                             MAX_REQUESTS, REQUEST_MAX_STATES>;
  tcpxRequestQueue() : Base() {}
  bool has_posted() { return has<REQUEST_POSTED>(); }
  bool has_active() { return has<REQUEST_ACTIVE>(); }
  bool has_transmitting() { return has<REQUEST_TRANSMITTING>(); }
  bool has_inactive() { return has<REQUEST_INACTIVE>(); }
  struct tcpxRequest *next_free() { return first<REQUEST_FREE>(); }
  struct tcpxRequest *next_posted() { return first<REQUEST_POSTED>(); }
  struct tcpxRequest *next_active() { return first<REQUEST_ACTIVE>(); }
  struct tcpxRequest *next_transmitting() { return first<REQUEST_TRANSMITTING>(); }
  struct tcpxRequest *next_inactive() { return first<REQUEST_INACTIVE>(); }
  void enqueue() {
    TCPX_TP(REQUEST, TCPX_REQUEST_TP_STATE_ACTIVE, next_free());
    enqueue_internal();
  }
  void finish_posted() {
    TCPX_TP(REQUEST, TCPX_REQUEST_TP_STATE_POSTED, next_posted());
    advance<REQUEST_POSTED>();
  }
  void finish_active() {
    TCPX_TP(REQUEST, TCPX_REQUEST_TP_STATE_TRANSMITTING, next_active());
    advance<REQUEST_ACTIVE>();
  }
  void finish_transmitting() {
    TCPX_TP(REQUEST, TCPX_REQUEST_TP_STATE_INACTIVE, next_transmitting());
    advance<REQUEST_TRANSMITTING>();
  }
  uint32_t get_posted_idx() {
    return get_index<REQUEST_POSTED>();
  }
  void dequeue() {
    TCPX_TP(REQUEST, TCPX_REQUEST_TP_STATE_FREE, next_inactive());
    dequeue_internal();
  }
};

#endif  // NET_GPUDIRECTTCPX_WORK_QUEUE_H_
