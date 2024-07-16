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

#ifndef NET_GPUDIRECTTCPX_ADAPTER_NCCL_DEBUG_H_
#define NET_GPUDIRECTTCPX_ADAPTER_NCCL_DEBUG_H_

#include "nccl_net.h"

using __tcpxDebugLogger_t = ncclDebugLogger_t;
extern __tcpxDebugLogger_t tcpx_log_func;

#define ADAPTED_DEBUG_WARN(fmt, ...)                                                     \
  (*tcpx_log_func)(NCCL_LOG_WARN, NCCL_ALL, __PRETTY_FUNCTION__, __LINE__, \
                   fmt, ##__VA_ARGS__)

#define ADAPTED_DEBUG_INFO(flags, fmt, ...)                                                \
  (*tcpx_log_func)(NCCL_LOG_INFO, flags, __PRETTY_FUNCTION__, __LINE__, fmt, \
                   ##__VA_ARGS__)

#define ADAPTED_DEBUG_TRACE(flags, fmt, ...)                                                \
  (*tcpx_log_func)(NCCL_LOG_TRACE, flags, __PRETTY_FUNCTION__, __LINE__, fmt, \
                   ##__VA_ARGS__)

#define NCCL_DEBUG_WARN(fmt, ...) ADAPTED_DEBUG_WARN(fmt, ##__VA_ARGS__)
#define NCCL_DEBUG_INFO(flags, fmt, ...) ADAPTED_DEBUG_INFO(flags, fmt, ##__VA_ARGS__)
#define NCCL_DEBUG_TRACE(flags, fmt, ...) ADAPTED_DEBUG_TRACE(flags, fmt, ##__VA_ARGS__)

#define __TCPX_INIT NCCL_INIT
#define __TCPX_COLL NCCL_COLL
#define __TCPX_P2P NCCL_P2P
#define __TCPX_SHM NCCL_SHM
#define __TCPX_NET NCCL_NET
#define __TCPX_GRAPH NCCL_GRAPH
#define __TCPX_TUNING NCCL_TUNING
#define __TCPX_ENV NCCL_ENV
#define __TCPX_ALLOC NCCL_ALLOC
#define __TCPX_CALL NCCL_CALL
#define __TCPX_PROXY NCCL_PROXY
#define __TCPX_NVLS NCCL_NVLS
#define __TCPX_ALL NCCL_ALL


#endif  // NET_GPUDIRECTTCPX_ADAPTER_NCCL_DEBUG_H_