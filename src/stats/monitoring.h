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

#ifndef NET_GPUDIRECTTCPX_STATS_MONITORING_H_
#define NET_GPUDIRECTTCPX_STATS_MONITORING_H_

#include <stdint.h>
#include <string>

#include "../macro.h"

struct tcpxSocketStats {
  uint64_t flow_id;
#ifdef TCPX_TRACEPOINT
  uint64_t tx_ctrl_cnt;
  uint64_t tx_ctrl_done_cnt;
  uint64_t tx_cnt;
  uint64_t tx_slow_cnt;
  uint64_t tx_completion_slow_cnt;
  uint64_t tx_completion_cnt;
  uint64_t rx_ctrl_done_cnt;
  uint64_t rx_cnt;
  uint64_t rx_slow_cnt;
#endif
};
void tcpxSocketStatsInit(tcpxSocketStats *s);
std::string tcpxSocketStatsToString(const tcpxSocketStats &s, bool passive);
bool isInactive(tcpxSocketStats& s);

#endif  // NET_GPUDIRECTTCPX_STATS_MONITORING_H_