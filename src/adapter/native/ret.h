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

#ifndef NET_GPUDIRECTTCPX_ADAPTER_NATIVE_RET_H_
#define NET_GPUDIRECTTCPX_ADAPTER_NATIVE_RET_H_

/* Error type */
typedef enum { nativeSuccess                 =  0,
               nativeUnhandledCudaError      =  1,
               nativeSystemError             =  2,
               nativeInternalError           =  3,
               nativeInvalidArgument         =  4,
               nativeInvalidUsage            =  5,
               nativeRemoteError             =  6,
               nativeInProgress              =  7,
               nativeNumResults              =  8 } nativeResult_t;

using tcpxResult_t = nativeResult_t;

#define __tcpxSuccess nativeSuccess
#define __tcpxUnhandledCudaError nativeUnhandledCudaError
#define __tcpxSystemError nativeSystemError
#define __tcpxInternalError nativeInternalError
#define __tcpxInvalidArgument nativeInvalidArgument
#define __tcpxInvalidUsage nativeInvalidUsage
#define __tcpxRemoteError nativeRemoteError
#define __tcpxInProgress nativeInProgress

tcpxResult_t initRet();

#endif  // NET_GPUDIRECTTCPX_ADAPTER_NATIVE_RET_H_