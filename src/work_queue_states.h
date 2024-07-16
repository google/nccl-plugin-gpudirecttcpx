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

#ifndef NCCL_GPUDIRECTTCPX_WORK_QUEUE_STATES_H_
#define NCCL_GPUDIRECTTCPX_WORK_QUEUE_STATES_H_

// Task state transition:
// FREE->ACTIVE->COMPLETING->INACTIVE->FREE
enum tcpxTaskState {
  TASK_FREE = 0,
  TASK_INACTIVE = 1,
  TASK_COMPLETING = 2,
  TASK_ACTIVE = 3,
  TASK_MAX_STATES = 4,
};

// Request state transition:
// FREE->POSTED->ACTIVE->TRANSMITTING->INACTIVE->FREE
enum tcpxRequestState {
  REQUEST_FREE = 0,
  REQUEST_INACTIVE = 1,
  REQUEST_TRANSMITTING = 2,
  REQUEST_ACTIVE = 3,
  REQUEST_POSTED = 4,
  REQUEST_MAX_STATES = 5,
};

#endif  // NCCL_GPUDIRECTTCPX_WORK_QUEUE_STATES_H_
