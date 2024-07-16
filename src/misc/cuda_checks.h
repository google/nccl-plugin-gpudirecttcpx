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

#ifndef NET_GPUDIRECTTCPX_CUDA_CHECKS_H_
#define NET_GPUDIRECTTCPX_CUDA_CHECKS_H_

#include "cuda.h"
#include "cuda_runtime.h"

#include "adapter1.h"

#define CUASSERT(cmd)                         \
  do {                                        \
    CUresult err = cmd;                       \
    if (err != CUDA_SUCCESS) {                \
      const char* name;                       \
      cuGetErrorName(err, &name);             \
      const char* msg;                        \
      cuGetErrorString(err, &msg);            \
      WARN("CU failure %s: %s", name, msg);   \
      exit(1);                                \
    }                                         \
  } while (false)

#define CUCHECK(cmd)                          \
  do {                                        \
    CUresult err = cmd;                       \
    if (err != CUDA_SUCCESS) {                \
      const char* name;                       \
      cuGetErrorName(err, &name);             \
      const char* msg;                        \
      cuGetErrorString(err, &msg);            \
      WARN("CU failure %s: %s", name, msg); \
      return tcpxUnhandledCudaError;          \
    }                                         \
  } while (false)

#define CUDAASSERT(cmd)                                                        \
  do {                                                                         \
    cudaError_t err = cmd;                                                     \
    if (err != cudaSuccess) {                                                  \
      const char *name = cudaGetErrorName(err);                                \
      const char *msg = cudaGetErrorString(err);                               \
      WARN("Cuda failure %s: %s", name, msg);                                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (false)

#define CUDACHECK(cmd)                                                         \
  do {                                                                         \
    cudaError_t err = cmd;                                                     \
    if (err != cudaSuccess) {                                                  \
      const char *name = cudaGetErrorName(err);                                \
      const char *msg = cudaGetErrorString(err);                               \
      WARN("Cuda failure %s: %s", name, msg);                                  \
      return tcpxUnhandledCudaError;                                           \
    }                                                                          \
  } while (false)

#endif // NET_GPUDIRECTTCPX_CUDA_CHECKS_H_