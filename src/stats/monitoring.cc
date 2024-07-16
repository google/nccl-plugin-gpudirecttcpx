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

#include "monitoring.h"

#include <sstream>

void tcpxSocketStatsInit(tcpxSocketStats *s) {
  s->flow_id = 0;
#ifdef TCPX_TRACEPOINT
  s->tx_ctrl_cnt = 0;
  s->tx_ctrl_done_cnt = 0;
  s->tx_cnt = 0;
  s->tx_slow_cnt = 0;
  s->tx_completion_slow_cnt = 0;
  s->tx_completion_cnt = 0;
  s->rx_ctrl_done_cnt = 0;
  s->rx_cnt = 0;
  s->rx_slow_cnt = 0;
#endif
}

bool isInactive(tcpxSocketStats& s) {
#ifdef TCPX_TRACEPOINT
  return s.tx_ctrl_cnt == 0 &&
    s.tx_ctrl_done_cnt == 0 &&
    s.tx_cnt == 0 &&
    s.tx_slow_cnt == 0 &&
    s.tx_completion_slow_cnt == 0 &&
    s.tx_completion_cnt == 0 &&
    s.rx_ctrl_done_cnt == 0 &&
    s.rx_cnt == 0 &&
    s.rx_slow_cnt == 0;
#else
  return true;
#endif
}

std::string tcpxSocketStatsToStringTx(const tcpxSocketStats &s) {
  std::stringstream ss;
#ifdef TCPX_TRACEPOINT
  // ss << "tx_ctrl " << s.pending_ctrl_cnt << "[" << s.tx_ctrl_cnt << "/" << s.tx_ctrl_done_cnt << "] ";
  ss << "tx [" << s.tx_completion_cnt << "/" << s.tx_cnt << "] ";
  ss << "tx_slow " << s.tx_slow_cnt << " ";
  ss << "tx_comp_slow " << s.tx_completion_slow_cnt << " ";
#endif
  return ss.str();
}

std::string tcpxSocketStatsToStringRx(const tcpxSocketStats &s) {
  std::stringstream ss;
#ifdef TCPX_TRACEPOINT
  // ss << "rx_ctrl " << s.pending_ctrl_cnt << "[" << s.rx_ctrl_done_cnt << "](" << s.rx_partial_ctrl_bytes<< ") ";
  ss << "rx " << s.rx_cnt << " ";
  ss << "rx_slow " << s.rx_slow_cnt << " ";
#endif
  return ss.str();
}

std::string tcpxSocketStatsToString(const tcpxSocketStats &s, bool passive) {
  if (passive) return tcpxSocketStatsToStringRx(s);

  return tcpxSocketStatsToStringTx(s);
}