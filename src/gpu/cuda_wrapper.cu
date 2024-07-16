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

#include "cuda_wrapper.h"

#include <ctype.h>
#include <memory>
#include <unistd.h>

#ifdef DRIVER_API
#include "cuda.h"
#else
#include "cuda_runtime.h"
#endif

#include "alloc1.h"
#include "checks1.h"
#include "common.h"
#include "cuda_checks.h"
#include "param1.h"
#include "rx_pool.h"
#include "tx_pool.h"
#include "../flags.h"
#include "../macro.h"

bool init = 0;
void lazyInit() {
#ifdef DRIVER_API
  if (!init)
    CUASSERT(cuInit(0));
#else
#endif
  init = 1; 
}

tcpxResult_t gpu_n_dev(int* n) {
  lazyInit();

  int _n;
#ifdef DRIVER_API
  CUASSERT(cuDeviceGetCount(&_n));
#else
  CUDAASSERT(cudaGetDeviceCount(&_n));
#endif
  if (_n <= 0) {
    WARN("NET/" PRODUCT_NAME "/CUDA : no cuDevices found");
    return tcpxInternalError;
  }

  INFO(TCPX_NET | TCPX_INIT, "NET/" PRODUCT_NAME "/CUDA : cuDevices count %d", _n);
  *n = _n;
  return tcpxSuccess;
}

tcpxResult_t gpu_init_internal(struct gpuDev *gpu, int ordinal) {
  lazyInit();

  int i = ordinal;

  char *pci_addr = gpu->pci_addr;

#ifdef DRIVER_API
  INFO(NCCL_NET, "new cuda context on dev %d", i);
  CUASSERT(cuDeviceGet(&(gpu->dev), i));

  if (kCudaUsePrimaryCtx) {
    CUASSERT(cuDevicePrimaryCtxRetain(&(gpu->ctx), gpu->dev));
  } else {
    CUASSERT(cuCtxCreate(&(gpu->ctx), CU_CTX_MAP_HOST, gpu->dev));
    CUcontext _;
    CUASSERT(cuCtxPopCurrent(&_));
  }

  CUASSERT(cuDeviceGetPCIBusId(pci_addr, CU_PCI_ADDR_LEN, gpu->dev));
#else
  CUDACHECK(cudaDeviceGetPCIBusId(pci_addr, CU_PCI_ADDR_LEN, gpu->dev));
#endif
  gpu->dev = i;
  for (int j = 0; j < CU_PCI_ADDR_LEN; j++) {
    pci_addr[j] = tolower(pci_addr[j]);
  }
  INFO(TCPX_NET, "NET/" PRODUCT_NAME "/CUDA : gpu dev %d pci [%s](%zu)", i, pci_addr, strlen(pci_addr));

  return tcpxSuccess;
}

TCPX_PARAM(UseGpuPciClient, "TCPX_RXMEM_IMPORT_USE_GPU_PCI_CLIENT", 1);
TCPX_PARAM(RxmemSkipOdds, "TCPX_RXMEM_IMPORT_SKIP_ODDS", 0);

struct gpuDev* _gpus = nullptr;
int _n;

tcpxResult_t gpu_init(void** gpus, int n) {
  if (_gpus != nullptr) {
    WARN("gpu lib init twice");
    return ncclInternalError;
  }
  TCPXCHECK(tcpxCalloc(&_gpus, n));

  for (int i = 0; i < n; i++) {
#ifdef GPU_LAZY_INIT
    _gpus[i].dev = -1;
#else
    gpu_init_internal(_gpus + i, i);
#endif
  }

  *gpus = _gpus;
  _n = n;
  return tcpxSuccess;
}

tcpxResult_t gpu_deinit(void* gpus) {
  free(gpus);
  return tcpxSuccess;
}

// a bit hacky requires setting primary context first by application
tcpxResult_t gpu_current_dev(void *gpus, void **gpu) {
  struct gpuDev *_gpus = (struct gpuDev*) gpus;
  int ordinal;
  CUDACHECK(cudaGetDevice(&ordinal));
  *gpu = _gpus + ordinal;
#ifdef GPU_LAZY_INIT
  if ((_gpus + ordinal)->dev < 0) {
    gpu_init_internal(_gpus + ordinal, ordinal);
  }
#endif
  return tcpxSuccess;
}

tcpxResult_t gpu_push_current(void* gpu) {
  struct gpuDev *_gpu = (struct gpuDev*) gpu;
  int ordinal = _gpu - _gpus;
  if (ordinal >= _n) {
    WARN("invalid GPU %d/%d", ordinal, _n);
    return ncclInternalError;
  }
#ifdef GPU_LAZY_INIT
  if (_gpu->dev < 0) {
    gpu_init_internal(_gpu, ordinal);
  }
#endif
#ifdef DRIVER_API
  CUCHECK(cuCtxPushCurrent(_gpu->ctx));
#else
  CUDACHECK(cudaSetDevice(_gpu->dev));
#endif
  return tcpxSuccess;
}

tcpxResult_t gpu_pop_current(void* gpus, void** gpu) {
  if (gpus && gpu) {
    TCPXCHECK(gpu_current_dev(gpus, gpu));
  }
#ifdef DRIVER_API
  CUcontext ctx;
  CUCHECK(cuCtxPopCurrent(&ctx));
#else
#endif
  return tcpxSuccess;
}

// lazy init
tcpxResult_t gpu_rx_init_internal(struct gpuDev* gpu) {
  bool use_gpu_pci_client = TCPX_GET_PARAM(UseGpuPciClient);
  bool rx_8_gpu = !TCPX_GET_PARAM(RxmemSkipOdds);

  char *gpu_pci_addr = gpu->pci_addr;
  int ordinal;
  TCPXCHECK(gpu_ordinal(gpu, &ordinal));

  if (!use_gpu_pci_client) {
#ifdef DRIVER_API
    gpu->rx.rxmem = gpumem_import(gpu_pci_addr);
#else
    gpu->rx.rxmem = (void *)gpumem_import(gpu_pci_addr);
#endif
  } else {

    if (!rx_8_gpu && ordinal % 2 == 1) {
      gpu->rx.handle = nullptr;
      gpu->rx.rxmem = 0;
    } else {
      gpu->rx.handle =
          std::unique_ptr<CuIpcMemfdHandle>(GpumemImport(gpu->ctx, gpu_pci_addr));
      if (!gpu->rx.handle) {
        return tcpxSystemError;
      }
#ifdef DRIVER_API
      gpu->rx.rxmem = gpu->rx.handle->GetGpuMem();
#else
      gpu->rx.rxmem = (void *)gpu->rx.handle->GetGpuMem();
#endif
    }
  }

  return tcpxSuccess;
}

tcpxResult_t gpu_get_rxmem(void* gpu, void** rxmem) {
  struct gpuDev *_gpu = (struct gpuDev *)gpu;
  if ((void*) _gpu->rx.rxmem == nullptr) {
    TCPXCHECK(gpu_rx_init_internal(_gpu));
  }
  *rxmem = (void*) _gpu->rx.rxmem;
  char buf[CU_PCI_ADDR_LEN];
  gpu_pci_addr(gpu, buf, CU_PCI_ADDR_LEN);
  INFO(TCPX_NET, "gpu [%s] rxmem %s", buf, *rxmem ? "ready" : "skip");
  return tcpxSuccess;
}

tcpxResult_t gpu_tx_reg_mr(void* gpu, void** gpu_tx, int* fd, char* nic_pci_addr, void* buf, size_t sz) {
  struct gpuDev *_gpu = (struct gpuDev *)gpu;

  struct gpuTx *_gpu_tx;

  TCPXCHECK(gpu_push_current(gpu));

  TCPXCHECK(tcpxCalloc(&_gpu_tx, 1));
  int ret = get_gpumem_dmabuf_pages_fd(_gpu->pci_addr, nic_pci_addr,
                                 (CUdeviceptr)buf, sz, &(_gpu_tx->dma_buf_fd));
  if (ret < 0) {
    WARN("gpu_tx_reg_mr failed %d", ret);
    return tcpxInternalError;
  }
  _gpu_tx->gpu_mem_fd = ret;

  TCPXCHECK(gpu_pop_current(nullptr, nullptr));

  *gpu_tx = _gpu_tx;
  *fd = _gpu_tx->gpu_mem_fd;
  return tcpxSuccess;
}

tcpxResult_t gpu_tx_dereg_mr(void* gpu, void* gpu_tx) {
  struct gpuTx *_gpu_tx = (struct gpuTx *)gpu_tx;

  if (_gpu_tx->dma_buf_fd) close(_gpu_tx->dma_buf_fd);

  return tcpxSuccess;
}

tcpxResult_t gpu_pci_addr(void* gpu, char *buf, int len) {
  struct gpuDev *_gpu = (struct gpuDev *)gpu;

  if (len < CU_PCI_ADDR_LEN)  {
    WARN("gpu_pci_addr buf too short %d vs expected at least %d", len, CU_PCI_ADDR_LEN);
  }

  memcpy(buf, _gpu->pci_addr, CU_PCI_ADDR_LEN);

  return tcpxSuccess;
}

char *gpu_tostring(void* gpu, char *buf, int n) {
  if (gpu == nullptr) snprintf(buf, n, "null");

  struct gpuDev *_gpu = (struct gpuDev *)gpu;

  snprintf(buf, n, "cudaDev %d", _gpu->dev);
  return buf;
}

tcpxResult_t gpu_node(void* gpu, int *n) {
  struct gpuDev* _gpu = (struct gpuDev*) gpu;
  *n = _gpu->dev < 4 ? 0 : 1;
  return tcpxSuccess;
}

tcpxResult_t gpu_ordinal(void* gpu, /*output=*/int *ordinal) {
  struct gpuDev* _gpu = (struct gpuDev*) gpu;
  *ordinal = _gpu->dev;
  return tcpxSuccess;
}
