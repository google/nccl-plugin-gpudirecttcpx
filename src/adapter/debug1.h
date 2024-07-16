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

#ifndef NET_GPUDIRECTTCPX_ADAPTER_DEBUG1_H_
#define NET_GPUDIRECTTCPX_ADAPTER_DEBUG1_H_

#include "nccl/debug.h"

using tcpxDebugLogger_t = __tcpxDebugLogger_t;
extern tcpxDebugLogger_t tcpx_log_func;

#define TCPX_INIT __TCPX_INIT
#define TCPX_COLL __TCPX_COLL
#define TCPX_P2P __TCPX_P2P
#define TCPX_SHM __TCPX_SHM
#define TCPX_NET __TCPX_NET
#define TCPX_GRAPH __TCPX_GRAPH
#define TCPX_TUNING __TCPX_TUNING
#define TCPX_ENV __TCPX_ENV
#define TCPX_ALLOC __TCPX_ALLOC
#define TCPX_CALL __TCPX_CALL
#define TCPX_PROXY __TCPX_PROXY
#define TCPX_NVLS __TCPX_NVLS
#define TCPX_ALL __TCPX_ALL

#define WARN(fmt, ...) ADAPTED_DEBUG_WARN(fmt, ##__VA_ARGS__)

#define INFO(flags, fmt, ...) ADAPTED_DEBUG_INFO(flags, fmt, ##__VA_ARGS__)

#ifdef ENABLE_TRACE
#define TRACE(flags, fmt, ...) ADAPTED_DEBUG_TRACE(flags, fmt, ##__VA_ARGS__)
#else
#define TRACE(...)
#endif

#endif  // NET_GPUDIRECTTCPX_ADAPTER_DEBUG1_H_