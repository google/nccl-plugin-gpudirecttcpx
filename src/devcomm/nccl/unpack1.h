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

#ifndef NET_GPUDIRECTTCPX_CUDA_UNPACK_QUEUE_H_
#define NET_GPUDIRECTTCPX_CUDA_UNPACK_QUEUE_H_

#include "../unpack_defs1.h"
#include "adapter1.h"
#include "ret.h"

#define __TCPX_UNPACK_VERSION 0x7
static_assert(DEV_UNPACK_VERSION == __TCPX_UNPACK_VERSION, "unpack version mismatch");

tcpxResult_t __tcpxNetDeviceQueueNew(void* gpu_dev, bool passive, void** handle, void** d_handle);

// tcpxResult_t tcpxNetDeviceQueueNextFree(struct tcpxNetDeviceQueue* handle, void* slot);
static inline tcpxResult_t __tcpxNetDeviceQueueNextFree(struct tcpxNetDeviceQueue* handle, void* slot) {
  struct unpackSlot* _slot = (struct unpackSlot*) slot;
  if (handle->tail - handle->head >= NCCL_NET_DEVICE_UNPACK_MAX_QUEUE_DEPTH) {
    _slot->active = false;

    _slot->idx = 0;

    _slot->mem = nullptr;
    _slot->cnt = nullptr;
    _slot->cnt_cache = 0;

    _slot->fds_cnt = nullptr;
    _slot->pgtok_cnts = nullptr;
    _slot->fds = nullptr;
    _slot->pgtoks = nullptr;
  } else {
    _slot->active = true;

    uint64_t q_idx = handle->tail % NCCL_NET_DEVICE_UNPACK_MAX_QUEUE_DEPTH;

    _slot->idx = q_idx;

    _slot->mem = handle->meta->mem[_slot->idx];
    _slot->cnt = handle->meta->cnt + _slot->idx;
    _slot->cnt_cache = 0;

    _slot->fds_cnt = handle->record.fds_cnts + q_idx;
    _slot->pgtok_cnts = handle->record.pgtok_cnts[q_idx];
    _slot->fds = handle->record.fds[q_idx];
    _slot->pgtoks = (pgtok_t *)handle->record.pgtoks[q_idx];

    handle->tail += 1;
    // INFO(TCPX_NET, "NNFF head %d tail %d", handle->head, handle->tail);
  }
  return tcpxSuccess;
}

void __tcpxNetDeviceQueueFree(void* handle, void* d_handle);

#endif  // NET_GPUDIRECTTCPX_CUDA_UNPACK_QUEUE_H_