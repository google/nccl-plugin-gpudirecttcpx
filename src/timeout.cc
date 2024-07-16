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

#include <ctime>
#include <stdint.h>
#include <time.h>

#include "flags.h"
#include "timeout.h"

#include "debug1.h"

void defaultTimenow(struct timespec *ts) {
  if (clock_gettime(CLOCK_MONOTONIC, ts) < 0) {
    WARN("clock_gettime failure");
  }
}

bool tcpxTimeoutDetectionInit(struct tcpxTimeoutDetection *t,
                              const struct tcpxTimeoutDetection::Config &c) {
  if (t->initialized)
    return false;
  t->timenow = c.timenow;
  t->threshold_ns = c.threshold_ns;
  t->frequency_ns = c.frequency_ns;
  t->initialized = true;
  return true;
}

void tcpxTimeoutDetectionReset(struct tcpxTimeoutDetection *t) {
  t->past_thresh = false;
  t->same_count = 0;
}

#define NANOS_PER_SECOND 1000000000ULL
#define DIFFTIME(ts1, ts2)                                                     \
  (((ts2).tv_sec - (ts1).tv_sec) * NANOS_PER_SECOND + (ts2).tv_nsec -          \
   (ts1).tv_nsec)
bool tcpxTimeoutDetectionShouldWarn(struct tcpxTimeoutDetection* t, uint64_t *nanos) {
  if (t->same_count++ == 0) {
    (*t->timenow)(&t->poll_0_ts);
    return false;
  }

  struct timespec now_ts;
  t->timenow(&now_ts);
  if (!t->past_thresh) {
    *nanos = DIFFTIME(t->poll_0_ts, now_ts);
    if (*nanos < t->threshold_ns) {
      return false;
    }
    t->past_thresh = true;
  } else {
    uint64_t nanos_since_prev = DIFFTIME(t->prev_ts, now_ts);
    if (nanos_since_prev < t->frequency_ns) {
      return false;
    }
    *nanos = DIFFTIME(t->poll_0_ts, now_ts);
  }
  t->prev_ts = now_ts; // struct assignment
  return true;
}
