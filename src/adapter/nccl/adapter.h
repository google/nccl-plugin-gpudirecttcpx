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

#ifndef NET_GPUDIRECTTCPX_ADAPTER_NCCL_ADAPTER_H_
#define NET_GPUDIRECTTCPX_ADAPTER_NCCL_ADAPTER_H_

#include "nccl.h"
#include "nccl_net.h"
#include "net_device.h"

#include "ret.h"


tcpxResult_t initAdapter();

#define __TCPX_PTR_HOST NCCL_PTR_HOST
#define __TCPX_PTR_CUDA NCCL_PTR_CUDA

#define __DEV_UNPACK NCCL_NET_DEVICE_UNPACK
#define __DEV_UNPACK_VERSION NCCL_NET_DEVICE_UNPACK_VERSION
#define __DEV_UNPACK_MAX_QUEUE_DEPTH NCCL_NET_DEVICE_UNPACK_MAX_QUEUE_DEPTH

#define __TCPX_NET_HANDLE_MAXSIZE NCCL_NET_HANDLE_MAXSIZE

#define __DEV_NET_DEVICE_HANDLE ncclNetDeviceHandle_v7_t
#define __TCPX_NET_PROPERTIES_T ncclNetProperties_v7_t

#endif  // NET_GPUDIRECTTCPX_ADAPTER_NCCL_ADAPTER_H_