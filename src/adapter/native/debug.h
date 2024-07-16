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

#ifndef NET_GPUDIRECTTCPX_ADAPTER_NATIVE_DEBUG_H_
#define NET_GPUDIRECTTCPX_ADAPTER_NATIVE_DEBUG_H_

#include "tcpx.h"

extern nativeDebugLogger_t native_log_func;
#define __tcpxDebugLogger_t nativeDebugLogger_t

#define ADAPTED_DEBUG_WARN(fmt, ...)                                                     \
  (*native_log_func)(NATIVE_LOG_WARN, NATIVE_ALL, __PRETTY_FUNCTION__, __LINE__, \
                   fmt, ##__VA_ARGS__)

#define ADAPTED_DEBUG_INFO(flags, fmt, ...)                                                \
  (*native_log_func)(NATIVE_LOG_INFO, flags, __PRETTY_FUNCTION__, __LINE__, fmt, \
                   ##__VA_ARGS__)

#define ADAPTED_DEBUG_TRACE(flags, fmt, ...)                                                \
  (*native_log_func)(NATIVE_LOG_TRACE, flags, __PRETTY_FUNCTION__, __LINE__, fmt, \
                   ##__VA_ARGS__)

#define NATIVE_DEBUG_WARN(fmt, ...) ADAPTED_DEBUG_WARN(fmt, ##__VA_ARGS__)
#define NATIVE_DEBUG_INFO(flags, fmt, ...) ADAPTED_DEBUG_INFO(flags, fmt, ##__VA_ARGS__)
#define NATIVE_DEBUG_TRACE(flags, fmt, ...) ADAPTED_DEBUG_TRACE(flags, fmt, ##__VA_ARGS__)

#define __TCPX_INIT NATIVE_INIT
#define __TCPX_COLL NATIVE_COLL
#define __TCPX_P2P NATIVE_P2P
#define __TCPX_SHM NATIVE_SHM
#define __TCPX_NET NATIVE_NET
#define __TCPX_GRAPH NATIVE_GRAPH
#define __TCPX_TUNING NATIVE_TUNING
#define __TCPX_ENV NATIVE_ENV
#define __TCPX_ALLOC NATIVE_ALLOC
#define __TCPX_CALL NATIVE_CALL
#define __TCPX_PROXY NATIVE_PROXY
#define __TCPX_NVLS NATIVE_NVLS
#define __TCPX_ALL NATIVE_ALL


#endif  // NET_GPUDIRECTTCPX_ADAPTER_NATIVE_DEBUG_H_