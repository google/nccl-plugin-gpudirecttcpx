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

#include "common.h"

#include <unistd.h>

#include "cuda_checks.h"
#include "debug1.h"
#include "ret.h"

CuIpcMemfdHandle::CuIpcMemfdHandle(CUcontext ctx, int fd, int dev_id, size_t size, size_t align) {
  ctx_ = ctx;
  CUASSERT(cuCtxPushCurrent(ctx_));
  cuCtxGetDevice(&dev_);
  if ((int) dev_ != dev_id) {
    WARN("unexpected dev_id %d, vs input %d", (int) dev_, dev_id);
    dev_id = (int) dev_;
  }

  INFO(TCPX_NET, "Importing CUDA IPC mem from from fd: %ld, dev_id: %ld, size: %ld, "
       "align: %ld", fd, dev_id, size, align);
  // CUASSERT(cuDeviceGet(&dev_, dev_id));
  // CUASSERT(cuDevicePrimaryCtxRetain(&ctx_, dev_));

  size_ = size;
  CUASSERT(
      cuMemImportFromShareableHandle(
        &handle_, (void*)(long long)fd,
        CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR));
  CUASSERT(cuMemAddressReserve(&ptr_, size_, align, 0, 0));
  CUASSERT(cuMemMap(ptr_, size_, 0, handle_, 0));
  close(fd);
  CUmemAccessDesc desc = {};
  desc.location.type = CU_MEM_LOCATION_TYPE_DEVICE;
  desc.location.id = dev_id;
  desc.flags = CU_MEM_ACCESS_FLAGS_PROT_READWRITE;
  CUASSERT(cuMemSetAccess(ptr_, size_, &desc, 1 /*count*/));

  CUcontext _;
  CUASSERT(cuCtxPopCurrent(&_));
}
CuIpcMemfdHandle::~CuIpcMemfdHandle() {
  CUASSERT(cuCtxPushCurrent(ctx_));

  cuMemUnmap(ptr_, size_);
  cuMemRelease(handle_);
  cuMemAddressFree(ptr_, size_);

  CUcontext _;
  CUASSERT(cuCtxPopCurrent(&_));
}
