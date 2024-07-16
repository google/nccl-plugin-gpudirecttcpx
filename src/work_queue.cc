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

#include "work_queue.h"

#include <string.h>

#include "common.h"
#include "flags.h"

void tcpxTaskInit(struct tcpxTask* t, void* gpu, int fd_idx) {
  memset(t, 0, sizeof *t);
  TCPXASSERT(tcpxCalloc(&(t->pipe), 1));
  tcpxDataPipeInit(t->pipe, kDynamicChunkSize, gpu);
  t->fd_idx = fd_idx;

  TCPXASSERT(tcpxCalloc(&(t->timeout), 1));
  tcpxTimeoutDetectionInit(t->timeout, {
    .threshold_ns = (uint64_t) kTimeoutThresholdNs,
    .frequency_ns = (uint64_t) kTimeoutFrequencyNs,
    .timenow = defaultTimenow,
  });
}

void tcpxTaskFree(struct tcpxTask* t) {
  tcpxDataPipeFree(t->pipe);
  free(t->pipe);
  free(t->timeout);
}
