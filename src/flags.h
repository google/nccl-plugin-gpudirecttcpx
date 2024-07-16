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

#ifndef NET_GPUDIRECTTCPX_FLAGS_H_
#define NET_GPUDIRECTTCPX_FLAGS_H_

#include <stdbool.h>
#include <stdint.h>

extern int kInlineThreshold;

extern int kDynamicChunkSize;

extern int kSchedAlg;

extern int kMinZcopySize;

extern int kEnableSpin;

extern int kNSocksPerThread;
extern int kNThreads;

extern bool kUseDmaBuf;

extern char *kUnixClientPrefix;

extern int kConnectionRetry;

extern int kForceAck;
extern int kRecvSync;

extern int kSleepNs;

extern int64_t kTimeoutThresholdNs;
extern int64_t kTimeoutFrequencyNs;

extern int kSpinWaitConnect;

extern int kLogStatsToStdout;

extern int kEnableTaskLevelStats;
extern int kEnableRequestLevelStats;
extern int kExportStatsToFile;

extern int kSamplingFactor;

extern uint64_t kLogLineLimit;

extern int kReportLifecycle;

enum tcpxSlownessSwitch {
  TX_COMP = 0,
  SENDRECV = 1,
  RX_CTRL = 2,
  TCPX_SLOWNESS_SWITCH_MAX_CNT = 3,
};
extern int kSlownessSwitch[TCPX_SLOWNESS_SWITCH_MAX_CNT];
extern int kSlownessReport[TCPX_SLOWNESS_SWITCH_MAX_CNT];
void parseSlownessSwitchFlags();

// Test only
void parseSlownessSwitchFlagInternal(const char *env_str,
                       int switches[TCPX_SLOWNESS_SWITCH_MAX_CNT]);

extern int kCudaUsePrimaryCtx;

#endif  // NET_GPUDIRECTTCPX_FLAGS_H_
