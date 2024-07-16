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


/******** feature flags start ********/

#define PRODUCT_NAME "GPUDirectTCPX"

// requires TX_ZCOPY

#define BUFFERED_CTRL

#define DRIVER_API
#define GPU_LAZY_INIT

#define EXIT_ON_CMSG_ERRORS

#define TCPX_TRACEPOINT

/******** feature flags end ********/

/******** config flags start ********/
#define MAX_SOCKETS 8 // 32 // ok we really need no more than 8
#define MAX_THREADS 16

#define MAX_IFS 16
#define MAX_IF_NAME_SIZE 16

/******** config flags end ********/
