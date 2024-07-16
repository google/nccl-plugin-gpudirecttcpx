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

#ifndef NET_GPUDIRECTTCPX_MISC_ALLOC_H_
#define NET_GPUDIRECTTCPX_MISC_ALLOC_H_

#include <malloc.h>
#include <string.h>

#include "adapter1.h"

template <typename T>
static tcpxResult_t tcpxCalloc(T** ptr, size_t nelem) {
  void* p = malloc(nelem * sizeof(T));
  if (p == NULL) {
    WARN("Failed to malloc %ld bytes", nelem * sizeof(T));
    return tcpxSystemError;
  }
  memset(p, 0, nelem * sizeof(T));
  *ptr = (T*)p;
  return tcpxSuccess;
}

#endif  // NET_GPUDIRECTTCPX_MISC_ALLOC_H_