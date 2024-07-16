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

#ifndef NET_GPUDIRECTTCPX_ADAPTER_PARAM1_H_
#define NET_GPUDIRECTTCPX_ADAPTER_PARAM1_H_

#include "nccl/param.h"

#define TCPX_PARAM(name, env, deftVal) __TCPX_PARAM(name, env, deftVal)

#define TCPX_GET_PARAM(name) (__TCPX_GET_PARAM(name))

#define TCPX_ENV_PREFIX __TCPX_ENV_PREFIX

#define TCPX_GET_ENV(name) (getenv(TCPX_ENV_PREFIX name))
#define TCPX_ENV_NAME(name) TCPX_ENV_PREFIX name

#endif  // NET_GPUDIRECTTCPX_ADAPTER_PARAM1_H_