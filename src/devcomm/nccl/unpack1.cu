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

#include "unpack1.h"

#include "cuda.h"

#include "checks1.h"
#include "cuda_checks.h"
#include "cuda_wrapper.h"
#include "debug1.h"

#ifdef DRIVER_API

tcpxResult_t __tcpxNetDeviceQueueNew(void* gpu_dev, bool passive, void** handle, void** d_handle) {
  TCPXCHECK(gpu_push_current(gpu_dev));

  struct tcpxNetDeviceQueue* h;
  struct unpackNetDeviceHandle* d;
  INFO(TCPX_NET, "NetDeviceHandle size %zu", sizeof *h);
  INFO(TCPX_NET, "NetDeviceDevHandle size %zu", sizeof *d);

  // clang-format off

  // host side handle
  CUASSERT(cuMemHostAlloc((void**) &h, sizeof *h, 0));
  memset(h, 0, sizeof *h);
  CUASSERT(cuMemHostAlloc((void**) &(h->meta), sizeof *(h->meta), 
                              CU_MEMHOSTALLOC_DEVICEMAP
                            | CU_MEMHOSTALLOC_PORTABLE));
                            // | CU_MEMHOSTALLOC_WRITECOMBINED));
  h->gpu_dev = gpu_dev;
  h->head = h->tail = 0;

  INFO(TCPX_NET, "handle %p size %zu", h, sizeof *h);
  INFO(TCPX_NET, "h->meta %p size %zu", h->meta, sizeof *(h->meta));

  // cuda side handle
  CUASSERT(cuMemAlloc((CUdeviceptr*) &d, sizeof *d));
  struct unpackNetDeviceHandle h_d;
  CUASSERT(cuMemHostGetDevicePointer((CUdeviceptr*) &(h_d.meta), h->meta, 0));

  if (passive) {
    TCPXASSERT(gpu_get_rxmem(gpu_dev, &(h_d.bounce_buf)));
  }

  // initialize nccl side head, nccl side increments the counter prior to performing copy
  h_d.head = (uint64_t) -1;

  CUASSERT(cuMemcpyHtoD((CUdeviceptr) d, &h_d, sizeof h_d));

  TCPXCHECK(gpu_pop_current(nullptr, nullptr));  // we don't care about output

  *handle = h;
  *d_handle = d;

  return tcpxSuccess;
}

void __tcpxNetDeviceQueueFree(void* handle, void* d_handle) {
  struct tcpxNetDeviceQueue* h =
      static_cast<struct tcpxNetDeviceQueue*>(handle);
  struct unpackNetDeviceHandle* d =
      static_cast<struct unpackNetDeviceHandle*>(d_handle);

  TCPXASSERT(gpu_push_current(h->gpu_dev));

  CUASSERT(cuMemFree((CUdeviceptr) d));
  CUASSERT(cuMemFreeHost(h->meta));
  CUASSERT(cuMemFreeHost(h));

  TCPXASSERT(gpu_pop_current(nullptr, nullptr));  // we don't care about output
}

#else // not DRIVER_API

tcpxResult_t __tcpxNetDeviceQueueNew(void* gpu_dev, bool passive, void** handle, void** d_handle) {
  TCPXCHECK(gpu_push_current(gpu_dev));

  struct tcpxNetDeviceQueue* h;
  struct unpackNetDeviceHandle* d;
  INFO(NCCL_NET, "NetDeviceHandle size %zu", sizeof *h);
  INFO(NCCL_NET, "NetDeviceDevHandle size %zu", sizeof *d);

  // clang-format off

  // host side handle
  CUDACHECK(cudaHostAlloc((void**) &h, sizeof *h, 0));
  memset(h, 0, sizeof *h);
  CUDACHECK(cudaHostAlloc((void**) &(h->meta), sizeof *(h->meta), 
                              cudaHostAllocMapped
                            | cudaHostAllocPortable));
  h->gpu_dev = gpu_dev;
  h->head = h->tail = 0;

  INFO(NCCL_NET, "handle %p size %zu", h, sizeof *h);
  INFO(NCCL_NET, "h->meta %p size %zu", h->meta, sizeof *(h->meta));

  // cuda side handle
  CUDACHECK(cudaMalloc(&d, sizeof *d));
  struct unpackNetDeviceHandle h_d;
  CUDACHECK(cudaHostGetDevicePointer(&(h_d.meta), h->meta, 0));
  if (passive) {
    NCCLASSERT(gpu_get_rxmem(gpu_dev, &(h_d.bounce_buf)));
  }
  // INFO(NCCL_NET, "111 setting meta to %p [%p,%p], bounce_buf to %p", h_d.meta, h_d.meta->mem, h_d.meta->cnt, h_d.bounce_buf);
  CUDACHECK(cudaMemcpy(d, &h_d, sizeof h_d, cudaMemcpyHostToDevice));

  *handle = h;
  *d_handle = d;

  return tcpxSuccess;
}

void __tcpxNetDeviceQueueFree(void* handle, void* d_handle) {
  struct tcpxNetDeviceQueue* h =
      static_cast<struct tcpxNetDeviceQueue*>(handle);
  struct unpackNetDeviceHandle* d =
      static_cast<struct unpackNetDeviceHandle*>(d_handle);

  TCPXASSERT(gpu_push_current(h->gpu_dev));

  CUDAASSERT(cudaFree(d));
  CUDAASSERT(cudaFreeHost(h->meta));
  CUDAASSERT(cudaFreeHost(h));
}

#endif
