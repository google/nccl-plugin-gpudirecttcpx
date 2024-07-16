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

#ifndef NET_GPUDIRECTTCPX_MISC_CHECKS_H_
#define NET_GPUDIRECTTCPX_MISC_CHECKS_H_

#include <errno.h>
#include <stdlib.h>

#include "adapter1.h"

#define SYSCHECK(call, name)         \
  do {                               \
    int retval;                      \
    SYSCHECKVAL(call, name, retval); \
  } while (false)

#define SYSCHECKVAL(call, name, retval)                      \
  do {                                                       \
    SYSCHECKSYNC(call, name, retval);                        \
    if (retval == -1) {                                      \
      WARN("Call to " name " failed : %s", strerror(errno)); \
      return tcpxSystemError;                                \
    }                                                        \
  } while (false)

#define SYSCHECKSYNC(call, name, retval)                               \
  do {                                                                 \
    retval = call;                                                     \
    if (retval == -1 &&                                                \
        (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)) { \
      INFO(TCPX_ALL, "Call to " name " returned %s, retrying",         \
           strerror(errno));                                           \
    } else {                                                           \
      break;                                                           \
    }                                                                  \
  } while (true)

// Propagate errors up
#define TCPXCHECK(call)                                                 \
  do {                                                                  \
    tcpxResult_t res = call;                                            \
    if (res != tcpxSuccess) {                                           \
      /* Print the back trace*/                                         \
      INFO(TCPX_ALL, "TCPXCHECK %s:%d -> %d", __FILE__, __LINE__, res); \
      return res;                                                       \
    }                                                                   \
  } while (0);

#define TCPXASSERT(call)                                       \
  do {                                                         \
    tcpxResult_t res = call;                                   \
    if (res != tcpxSuccess) {                                  \
      /* Print the back trace*/                                \
      WARN("TCPXASSERT %s:%d -> %d", __FILE__, __LINE__, res); \
      exit(1);                                                 \
    }                                                          \
  } while (0);

#define TCPXCHECKRET(call, res, ret)                                    \
  do {                                                                  \
    if (call != res) {                                                  \
      /* Print the back trace*/                                         \
      INFO(TCPX_ALL, "TCPXCHECK %s:%d -> %d", __FILE__, __LINE__, res); \
      return ret;                                                       \
    }                                                                   \
  } while (0);

#endif  // NET_GPUDIRECTTCPX_MISC_CHECKS_H_