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

#include "debug.h"

#include <stdio.h>
#include <stdarg.h>

static void dummyDebugLog(ncclDebugLogLevel level, uint64_t flags,
                          const char* filefunc, int line, const char* fmt,
                          ...) {
  printf("%s:%d ", filefunc, line);
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  printf("\n");
}

ncclDebugLogger_t tcpx_log_func = dummyDebugLog;
