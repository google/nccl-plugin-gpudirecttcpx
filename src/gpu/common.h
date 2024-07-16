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

#ifndef NET_GPUDIRECTTCPX_GPU_COMMON_H_
#define NET_GPUDIRECTTCPX_GPU_COMMON_H_

#include <memory>

#include "cuda.h"

#include "../macro.h"

#define MAX_TX_BUFS 128 * 1024
struct gpuTx {
  int gpu_mem_fd;
  int dma_buf_fd;
};

class CuIpcMemfdHandle {
 public:
  CuIpcMemfdHandle(const CUcontext ctx, int fd, int dev_id, size_t size, size_t align);
  ~CuIpcMemfdHandle();
  CUdeviceptr GetGpuMem() { return ptr_; }
 private:
  CUcontext ctx_;
  CUdevice dev_;
  CUmemGenericAllocationHandle handle_;
  CUdeviceptr ptr_;
  size_t size_;
};
struct gpuRx {
#ifdef DRIVER_API
  CUdeviceptr rxmem;
#else
  void* rxmem;
#endif

  std::unique_ptr<CuIpcMemfdHandle> handle;
};

#define CU_PCI_ADDR_LEN 16  // documentation: 13 + '\0'
struct gpuDev {
#ifdef DRIVER_API
  CUdevice  dev;
  CUcontext ctx;
#else
  int dev;
#endif
  char pci_addr[CU_PCI_ADDR_LEN];

  struct gpuRx rx;
};

#endif // NET_GPUDIRECTTCPX_GPU_COMMON_H_
