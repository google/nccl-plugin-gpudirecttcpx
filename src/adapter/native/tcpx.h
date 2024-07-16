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

#ifndef NET_GPUDIRECTTCPX_ADAPTER_NATIVE_TCPX_H_
#define NET_GPUDIRECTTCPX_ADAPTER_NATIVE_TCPX_H_

typedef enum {NATIVE_LOG_NONE=0, NATIVE_LOG_VERSION=1, NATIVE_LOG_WARN=2, NATIVE_LOG_INFO=3, NATIVE_LOG_ABORT=4, NATIVE_LOG_TRACE=5} nativeDebugLogLevel;
typedef enum {NATIVE_INIT=1, NATIVE_COLL=2, NATIVE_P2P=4, NATIVE_SHM=8, NATIVE_NET=16, NATIVE_GRAPH=32, NATIVE_TUNING=64, NATIVE_ENV=128, NATIVE_ALLOC=256, NATIVE_CALL=512, NATIVE_PROXY=1024, NATIVE_NVLS=2048, NATIVE_ALL=~0} nativeDebugLogSubSys;

typedef void (*nativeDebugLogger_t)(nativeDebugLogLevel level, unsigned long flags, const char *file, int line, const char *fmt, ...);

#endif  // NET_GPUDIRECTTCPX_ADAPTER_NATIVE_TCPX_H_