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

#ifndef NET_GPUDIRECTTCPX_DEVCOMM_UNPACK_H_
#define NET_GPUDIRECTTCPX_DEVCOMM_UNPACK_H_

#include <stdint.h>

#include "unpack_defs1.h"
#include "nccl/unpack1.h"

#define TCPX_UNPACK_VERSION __TCPX_UNPACK_VERSION

#define tcpxNetDeviceQueueNew __tcpxNetDeviceQueueNew
#define tcpxNetDeviceQueueNextFree __tcpxNetDeviceQueueNextFree
#define tcpxNetDeviceQueueFree __tcpxNetDeviceQueueFree

#endif  // NET_GPUDIRECTTCPX_DEVCOMM_UNPACK_H_