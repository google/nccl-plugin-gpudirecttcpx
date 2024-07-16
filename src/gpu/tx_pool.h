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

#ifndef NET_GPUDIRECTTCPX_CUDA_TX_POOL_H_
#define NET_GPUDIRECTTCPX_CUDA_TX_POOL_H_

#include <stddef.h>

#include "cuda.h"


int get_gpumem_pages_fd(char* pci_addr, CUdeviceptr gpu_mem, size_t gpu_mem_sz,
                         int* align_offp);

int get_gpumem_dmabuf_pages_fd(char* gpu_pci_addr, char* nic_pci_addr,
                               CUdeviceptr gpu_mem, size_t gpu_mem_sz,
                               int* dma_buf_fd);

#endif  // NET_GPUDIRECTTCPX_CUDA_TX_POOL_H_
