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

#ifndef NET_GPUDIRECTTCPX_ADAPTER_NCCL_RET_H_
#define NET_GPUDIRECTTCPX_ADAPTER_NCCL_RET_H_

#include "nccl.h"

using tcpxResult_t = ncclResult_t;

#define __tcpxSuccess ncclSuccess
#define __tcpxUnhandledCudaError ncclUnhandledCudaError
#define __tcpxSystemError ncclSystemError
#define __tcpxInternalError ncclInternalError
#define __tcpxInvalidArgument ncclInvalidArgument
#define __tcpxInvalidUsage ncclInvalidUsage
#define __tcpxRemoteError ncclRemoteError
#define __tcpxInProgress ncclInProgress

tcpxResult_t initRet();

#endif  // NET_GPUDIRECTTCPX_ADAPTER_NCCL_RET_H_