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

#ifndef NET_GPUDIRECTTCPX_ADAPTER_ADAPTER1_H_
#define NET_GPUDIRECTTCPX_ADAPTER_ADAPTER1_H_

#include "debug1.h"
#include "param1.h"
#include "ret.h"
#include "nccl/adapter.h"

extern tcpxResult_t initAdapter();

#define TCPX_PTR_HOST __TCPX_PTR_HOST
#define TCPX_PTR_CUDA __TCPX_PTR_CUDA

#define DEV_UNPACK __DEV_UNPACK
#define DEV_UNPACK_VERSION __DEV_UNPACK_VERSION
#define DEV_UNPACK_MAX_QUEUE_DEPTH __DEV_UNPACK_MAX_QUEUE_DEPTH

#define TCPX_NET_HANDLE_MAXSIZE __TCPX_NET_HANDLE_MAXSIZE

using devNetDeviceHandle = __DEV_NET_DEVICE_HANDLE;

using tcpxNetProperties_t = __TCPX_NET_PROPERTIES_T;

#endif  // NET_GPUDIRECTTCPX_ADAPTER_ADAPTER1_H_