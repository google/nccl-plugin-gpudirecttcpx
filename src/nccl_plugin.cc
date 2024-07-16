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

#include "net_tcpx.h"

#include "nccl.h"
#include "nccl_net.h"

volatile ncclNet_v7_t ncclNetPlugin_v7 = {
    "GPUDirectTCPX_v7",
    tcpxInit,
    tcpxDevices,
    tcpxGetProperties,
    tcpxListen,
    tcpxConnect_v5,
    tcpxAccept_v5,
    tcpxRegMr,
    nullptr,  // TODO: tmp not using tcpx's DMA-BUF support, use ioctl for now
    tcpxDeregMr,
    tcpxIsend_v5,
    tcpxIrecv_v5,
    tcpxIflush_v5,
    tcpxTest,
    tcpxClose,
    tcpxClose,
    tcpxCloseListen,
    tcpxGetDeviceMr,
    tcpxIrecvConsumed,
};
