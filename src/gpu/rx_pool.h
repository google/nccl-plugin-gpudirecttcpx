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

#ifndef NET_GPUDIRECTTCPX_GPU_RXMEM_H_
#define NET_GPUDIRECTTCPX_GPU_RXMEM_H_

#include "common.h"

CUdeviceptr gpumem_import(char* gpu_pci_addr);

// CUdeviceptr gpumem_import_unix_socket(char* gpu_pci_addr);

CuIpcMemfdHandle* GpumemImport(const CUcontext ctx, const char* gpu_pci_addr);
CuIpcMemfdHandle* GpumemImport(const CUcontext ctx, const char* gpu_pci_addr,
                               const char* ipc_prefix);
// CuIpcMemfdHandle* GpumemImport(int dev);
// CuIpcMemfdHandle* GpumemImport(int dev, const char* ipc_prefix);

#endif  // NET_GPUDIRECTTCPX_GPU_RXMEM_H_
