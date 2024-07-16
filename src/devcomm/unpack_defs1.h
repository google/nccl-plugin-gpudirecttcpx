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

#ifndef NET_GPUDIRECTTCPX_DEVCOMM_UNPACK_DEFS_H_
#define NET_GPUDIRECTTCPX_DEVCOMM_UNPACK_DEFS_H_

#include "nccl/unpack_defs1.h"

#define TCPX_UNPACK_MAX_QUEUE_DEPTH __TCPX_UNPACK_MAX_QUEUE_DEPTH 
#define TCPX_UNPACK_MAX_SLICE_PAGES __TCPX_UNPACK_MAX_SLICE_PAGES

#include "arpa/inet.h"
#include <stdint.h>
#include <stdlib.h>

#include "../macro.h"

#define MSG_SOCK_DEVMEM 0x2000000
#define NET_GPUDIRECTTCPX_MSG_MAX_CTRL_DATA 1 * TCPX_UNPACK_MAX_SLICE_PAGES

#define MAX_INLINE_THRESHOLD 2048
#define GPUDIRECTTCPX_CTRL_DATA_LEN \
  NET_GPUDIRECTTCPX_MSG_MAX_CTRL_DATA * CMSG_SPACE(sizeof(struct iovec))

#include "linux/types.h"
struct devmemtoken {
  __u32 token_start;
  __u32 token_count;
};

typedef devmemtoken pgtok_t;

struct tcpxRecord {
  size_t fds_cnts[TCPX_UNPACK_MAX_QUEUE_DEPTH];
  size_t pgtok_cnts[TCPX_UNPACK_MAX_QUEUE_DEPTH][MAX_SOCKETS];
  int fds[TCPX_UNPACK_MAX_QUEUE_DEPTH][MAX_SOCKETS];
  pgtok_t pgtoks[TCPX_UNPACK_MAX_QUEUE_DEPTH][MAX_SOCKETS][TCPX_UNPACK_MAX_SLICE_PAGES];
};

struct tcpxNetDeviceQueue {
  struct netUnpackMeta *meta;
  uint64_t head, tail;

  void* gpu_dev;
  struct tcpxRecord record;
};

struct unpackSlot {
  bool active;
  uint64_t idx;            // slot in queue

  void *mem; // [TCPX_UNPACK_MAX_SLICE_PAGES * sizeof(LoadMeta)]
  uint64_t *cnt;
  uint64_t cnt_cache; // accumulate before 1 write to cnt
  
  // records to free
  size_t* fds_cnt;     // [1] just socks per comm, i.e. ns = nt * num socks per thread, remove in migration
  size_t* pgtok_cnts;  // [MAX_SOCKETS]
  int* fds;            // [MAX_SOCKETS]
  pgtok_t* pgtoks;     // [MAX_SOCKETS][TCPX_UNPACK_MAX_SLICE_PAGES]  // was [...][GPUDIRECTTCPX_PKT_PER_MSG_MAX_CNT]
};

#endif  // NET_GPUDIRECTTCPX_DEVCOMM_UNPACK_DEFS_H_
