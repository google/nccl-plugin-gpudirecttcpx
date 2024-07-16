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

#ifndef NET_GPUDIRECTTCPX_CUDA_WRAPPER_H_
#define NET_GPUDIRECTTCPX_CUDA_WRAPPER_H_

#include "ret.h"

tcpxResult_t gpu_n_dev(/*output=*/int *n);

tcpxResult_t gpu_init(/*output=*/void **gpus, int n);
tcpxResult_t gpu_deinit(/*output=*/void *gpus);

tcpxResult_t gpu_current_dev(void* gpus, /*output=*/void **gpu);
tcpxResult_t gpu_push_current(void* gpu);
tcpxResult_t gpu_pop_current(void* gpus, void** gpu);

tcpxResult_t gpu_get_rxmem(void *gpu, /*output=*/void **rxmem);

tcpxResult_t gpu_tx_reg_mr(void *gpu, /*output=*/void **gpu_tx, /*output=*/int *fd, char *nic_pci_addr, void *buf, size_t sz);
tcpxResult_t gpu_tx_dereg_mr(void *gpu, void *gpu_tx);

tcpxResult_t gpu_pci_addr(void* gpu, char *buf, int len);

char *gpu_tostring(void* gpu, char *buf, int n);

tcpxResult_t gpu_node(void* gpu, /*output=*/int *n);
tcpxResult_t gpu_ordinal(void* gpu, /*output=*/int *ordinal);

#endif  // NET_GPUDIRECTTCPX_CUDA_WRAPPER_H_
