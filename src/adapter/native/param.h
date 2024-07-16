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

#ifndef NET_GPUDIRECTTCPX_ADAPTER_NATIVE_PARAM_H_
#define NET_GPUDIRECTTCPX_ADAPTER_NATIVE_PARAM_H_

#include <stdint.h>

void nativeLoadParam(char const* env, int64_t deftVal, int64_t uninitialized, int64_t* cache);

#define NATIVE_PARAM(name, env, deftVal) \
  int64_t nativeParam##name() { \
    constexpr int64_t uninitialized = INT64_MIN; \
    static_assert(deftVal != uninitialized, "default value cannot be the uninitialized value."); \
    static int64_t cache = uninitialized; \
    if (__builtin_expect(__atomic_load_n(&cache, __ATOMIC_RELAXED) == uninitialized, false)) { \
      nativeLoadParam("NATIVE_" env, deftVal, uninitialized, &cache); \
    } \
    return cache; \
  }

#define __TCPX_ENV_PREFIX "NET_TCPX_"
  
#endif  // NET_GPUDIRECTTCPX_ADAPTER_NATIVE_PARAM_H_