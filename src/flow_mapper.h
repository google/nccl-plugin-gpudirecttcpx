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

#ifndef NET_GPUDIRECTTCPX_FLOW_MAPPER_H_
#define NET_GPUDIRECTTCPX_FLOW_MAPPER_H_

#include <queue>
#include <vector>

#include <string.h>

#include "macro.h"
#include "work_queue.h"

#define likely(x)     __builtin_expect(!!(x), 1)
#define unlikely(x)   __builtin_expect(!!(x), 0)

static constexpr int TCPX_FLOWMAPPER_SCHED_ALG_RR = 0; // default
static constexpr int TCPX_FLOWMAPPER_SCHED_ALG_KATY = 1;

static inline void setBit(uint64_t &bitmap, int pos) {
  bitmap |= ((uint64_t)0x1 << pos);
}

static inline bool isBitSet(uint64_t bitmap, int pos) {
  return ((bitmap >> pos) & 0x1);
}

static inline void toggleBit(uint64_t &bitmap, int pos) {
  bitmap ^= ((uint64_t)0x1 << pos);
}

static inline void clearBit(uint64_t &bitmap, int pos) {
  bitmap &= ~((uint64_t)0x1 << pos);
}

// FlowMapper maps a quanta to a flow with scheduling
class FlowMapper {
 public:
  virtual ~FlowMapper() = default;
  // clear data structure
  virtual void reset() = 0;
  // returns 1 if there is any flow scheduled
  // returns 0 if there is no flow scheduled
  virtual bool hasFlow() const = 0;
  // schedule the flow with priority
  virtual void scheduleFlow(int flow, int prio) = 0;
  // pick a flow based on the shceduling algorithm
  virtual int pickFlow() = 0;
};

class FlowMapperKaty final : public FlowMapper {
 public:
  FlowMapperKaty() {
    static_assert(MAX_TASKS * MAX_SOCKETS <= sizeof(flow_bitmap) * 8,
          "flow_bitmap size is smaller than MAX_TASKS * MAX_SOCKETS");
  }

  static constexpr int NUM_QUANTA_PER_SCHED = 2;

  inline void reset() override {
    flow_bitmap = 0;
    num_quanta_to_schedule = NUM_QUANTA_PER_SCHED;
  }

  inline bool hasFlow() const override {
    return (flow_bitmap != 0) && (num_quanta_to_schedule > 0);
  }

  // prio (priority) = # max slot (MAX_TASKS) - # empty slot
  // highest priority (0), lowest priority (MAX_TASKS - 1)
  // For flows with no empty slot, prio will be -1 and the flow
  // will not be scheduled.
  inline void scheduleFlow(int flow, int prio) override {
    if (unlikely(prio >= MAX_TASKS || prio < 0)) return;
    // mark flow with prio
    int fbit_idx = flow + MAX_SOCKETS * prio;
    setBit(flow_bitmap, fbit_idx);
  }

  // Returns a flow ID with the maximum priority
  inline int pickFlow() override {
    if (num_quanta_to_schedule <= 0 || !hasFlow())
      return -1;
    // find the index of a flow with highest priority
    int fbit_idx = ffsll(flow_bitmap) - 1;
    // convert the index to flow ID and priority
    int prio = fbit_idx / MAX_SOCKETS;
    int flow = fbit_idx % MAX_SOCKETS;

    // unschedule flow
    clearBit(flow_bitmap, fbit_idx);

    // reschedule flow
    if (prio < MAX_TASKS - 1) {
      setBit(flow_bitmap, fbit_idx + MAX_SOCKETS);
    }

    num_quanta_to_schedule--;
    return flow;
  }

 private:
  // the number of remaining quanta to schedule with a current
  // flow_mapper information.
  int num_quanta_to_schedule = NUM_QUANTA_PER_SCHED;
  // i-th bit represents: flow ID of (i-1) % max_flows,
  // priority of (i-1) // max_flows
  //
  //                           max_flows(= MAX_SOCKETS)
  //                           (8 in the following example)
  //              MSB          <------>               LSB
  // flow_bitmap: ...|________|_____1__|________|________
  // flow_id    :    |76543210|76543210|76543210|76543210
  // priority   : ...|   p3   |   p2   |   p1   |   p0
  //              <--- lower priority  higher priority --->
  // For example, 1 in the flow_bitmap in 19th bit (shown above)
  // reresents flow_id 2 with priority 2 is scheduled.
  uint64_t flow_bitmap = 0;
};

class FlowMapperRR final : public FlowMapper {
 public:
  FlowMapperRR() {}

  inline void reset() override {
    num_empty = 0;
  }

  inline bool hasFlow() const override { return (num_empty > 0); }

  inline void scheduleFlow(int flow, int prio) override {
    empty_tasks[num_empty++] = flow;
  }

  inline int pickFlow() override {
    if (!hasFlow()) return -1;
    return empty_tasks[--num_empty];
  }

 private:
  int empty_tasks[MAX_SOCKETS];
  int num_empty = 0;
};

#endif  // NET_GPUDIRECTTCPX_FLOW_MAPPER_H_
