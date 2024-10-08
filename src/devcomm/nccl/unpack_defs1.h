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

#ifndef NET_GPUDIRECTTCPX_DEVCOMM_NCCL_UNPACK_DEFS_H_
#define NET_GPUDIRECTTCPX_DEVCOMM_NCCL_UNPACK_DEFS_H_

#include "unpack_defs.h"

#define __TCPX_UNPACK_MAX_QUEUE_DEPTH NCCL_NET_DEVICE_UNPACK_MAX_QUEUE_DEPTH 
#define __TCPX_UNPACK_MAX_SLICE_PAGES NET_UNPACK_MAX_SLICE_PAGES

#endif  // NET_GPUDIRECTTCPX_DEVCOMM_NCCL_UNPACK_DEFS_H_