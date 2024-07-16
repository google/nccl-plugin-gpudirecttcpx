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

#ifndef NET_TCPX_SOCK_DATAPIPE_H_
#define NET_TCPX_SOCK_DATAPIPE_H_

#include <stdlib.h>

#include "../macro.h"
#include "unpack_defs1.h"

struct tcpxDataPipe {
  // cpu buf
  char* buf;
  void* gpu_inline;

  // gpu buf
  char ctrl_data[GPUDIRECTTCPX_CTRL_DATA_LEN];

  // total bytes
  int bytes_cnt;

  // ctx
  void* gpu;

  // cached vars for clean-up
  union loadMeta* scatter_list;
  uint64_t cnt_cache;
  size_t* pgtok_cnt;  // [1]
  pgtok_t* pgtoks;  // [TCPX_UNPACK_MAX_SLICE_PAGES]

  const char *flow_str;
};
void tcpxDataPipeInit(tcpxDataPipe* p, size_t sz, void* gpu);
void tcpxDataPipeFree(tcpxDataPipe* p);

#endif  // NET_TCPX_SOCK_DATAPIPE_H_