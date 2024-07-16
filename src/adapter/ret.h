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

#ifndef NET_GPUDIRECTTCPX_ADAPTER_RET_H_
#define NET_GPUDIRECTTCPX_ADAPTER_RET_H_

#include "nccl/ret.h"

#define tcpxSuccess ((tcpxResult_t) __tcpxSuccess)
#define tcpxUnhandledCudaError ((tcpxResult_t) __tcpxUnhandledCudaError)
#define tcpxSystemError ((tcpxResult_t) __tcpxSystemError)
#define tcpxInternalError ((tcpxResult_t) __tcpxInternalError)
#define tcpxInvalidArgument ((tcpxResult_t) __tcpxInvalidArgument)
#define tcpxInvalidUsage ((tcpxResult_t) __tcpxInvalidUsage)
#define tcpxRemoteError ((tcpxResult_t) __tcpxRemoteError)
#define tcpxInProgress ((tcpxResult_t) __tcpxInProgress)

#endif  // NET_GPUDIRECTTCPX_ADAPTER_RET_H_