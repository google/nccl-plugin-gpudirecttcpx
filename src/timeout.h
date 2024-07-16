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

#ifndef NET_GPUDIRECTTCPX_TIMEOUT_H_
#define NET_GPUDIRECTTCPX_TIMEOUT_H_

#include <ctime>
#include <stdint.h>
#include <time.h>

void defaultTimenow(struct timespec *ts);

struct tcpxTimeoutDetection {
  struct Config {
    uint64_t threshold_ns;
    uint64_t frequency_ns;
    void (*timenow)(struct timespec *) = defaultTimenow;
  };

  struct timespec poll_0_ts;
  bool past_thresh;

  struct timespec prev_ts;
  uint32_t same_count;

  bool initialized = false;
  uint64_t threshold_ns;
  uint64_t frequency_ns;
  void (*timenow)(struct timespec *) = defaultTimenow;
};

bool tcpxTimeoutDetectionInit(struct tcpxTimeoutDetection *t,
                              const struct tcpxTimeoutDetection::Config &c);
void tcpxTimeoutDetectionReset(struct tcpxTimeoutDetection *t);
bool tcpxTimeoutDetectionShouldWarn(struct tcpxTimeoutDetection *t,
                                    uint64_t *nanos);

#endif // NET_GPUDIRECTTCPX_TIMEOUT_H_
