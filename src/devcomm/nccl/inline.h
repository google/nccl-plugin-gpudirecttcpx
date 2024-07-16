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

#ifndef NET_GPUDIRECTTCPX_CUDA_INLINE_H_
#define NET_GPUDIRECTTCPX_CUDA_INLINE_H_

#include <unistd.h>

#include "ret.h"

tcpxResult_t __gpu_inline_alloc(void* gpu_dev, void** inline_handle);
tcpxResult_t __gpu_inline_free(void* inline_handle);
tcpxResult_t __gpu_inline_memcpy(void* inline_handle, void* dst, void* src, size_t len);
tcpxResult_t __gpu_inline_test(void* inline_handle, int* done);
tcpxResult_t __gpu_inline_sync(void* inline_handle);

#endif  // NET_GPUDIRECTTCPX_CUDA_INLINE_H_