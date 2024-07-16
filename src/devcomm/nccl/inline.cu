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

#include "inline.h"

#include "cuda.h"

#include "alloc1.h"
#include "checks1.h"
#include "cuda_wrapper.h"
#include "cuda_checks.h"
#include "debug1.h"

struct inlineHandle {
  void* gpu_dev;
};

tcpxResult_t __gpu_inline_alloc(void* gpu_dev, void** inline_handle) {
  struct inlineHandle* _inline_handle;
  TCPXCHECK(tcpxCalloc(&_inline_handle, 1));
  _inline_handle->gpu_dev = gpu_dev;

  *inline_handle = _inline_handle;
  return tcpxSuccess;
}

tcpxResult_t __gpu_inline_free(void* inline_handle) {
  struct inlineHandle* _inline_handle = (struct inlineHandle*) inline_handle;

  free(_inline_handle);

  return tcpxSuccess;
}

tcpxResult_t __gpu_inline_memcpy(void* inline_handle, void* dst, void* src, size_t len) {
  return tcpxSuccess;
}

tcpxResult_t __gpu_inline_sync(void* inline_handle) {
  return tcpxSuccess;
}

tcpxResult_t __gpu_inline_test(void* inline_handle, int* done) {
  *done = 1;

  return tcpxSuccess;
}
