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

#include "datapipe.h"

#include "alloc1.h"
#include "checks1.h"
#include "inline.h"

void tcpxDataPipeInit(tcpxDataPipe* p, size_t sz, void *gpu) {
  p->buf = nullptr;
  p->gpu_inline = nullptr;

  p->bytes_cnt = 0;
  p->gpu = gpu;

  TCPXASSERT(tcpxCalloc((char **)&p->buf, sz));
  gpu_inline_alloc(p->gpu, &p->gpu_inline);

  memset(p->ctrl_data, 0, GPUDIRECTTCPX_CTRL_DATA_LEN);

  TCPXASSERT(tcpxCalloc(&(p->scatter_list), TCPX_UNPACK_MAX_SLICE_PAGES));
  memset(p->scatter_list, 0,
         sizeof(union loadMeta) * TCPX_UNPACK_MAX_SLICE_PAGES);
  p->cnt_cache = 0;
  p->pgtok_cnt = 0;
  p->pgtoks = nullptr;
}

void tcpxDataPipeFree(tcpxDataPipe* p) {
  if (p->buf != nullptr) {
    free(p->buf);
    gpu_inline_free(p->gpu_inline);
  }
  free(p->scatter_list);
}