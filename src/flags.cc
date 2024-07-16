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

#include "flags.h"

int kInlineThreshold = 0;

int kDynamicChunkSize = 128 * 1024;

int kSchedAlg = 0;

int kMinZcopySize = 1;

int kEnableSpin = 0;

int kNSocksPerThread = 1;
int kNThreads = 1;

bool kUseDmaBuf = true;

char defaultUnixClientPrefix[] = "/tmp";
char* kUnixClientPrefix = defaultUnixClientPrefix;

int kConnectionRetry = 3;

int kForceAck = 0;
int kRecvSync = 1;

int kSleepNs = 0;

int64_t kTimeoutThresholdNs = 10000000000LL;  // 10s
int64_t kTimeoutFrequencyNs = 30000000000LL;  // 30s

int kSpinWaitConnect = 1;

int kLogStatsToStdout = 0;

int kEnableTaskLevelStats = 0;
int kEnableRequestLevelStats = 0;
uint64_t kLogLineLimit = 256;
int kExportStatsToFile = 0;
int kSamplingFactor = 1;

int kReportLifecycle = 0;

int kSlownessSwitch[TCPX_SLOWNESS_SWITCH_MAX_CNT] = {
    /*TX_COMP=*/
    0,
    /*SENDRECV=*/
    0,
    /*RX_CTRL=*/
    0,
};
int kSlownessReport[TCPX_SLOWNESS_SWITCH_MAX_CNT] = {
    /*TX_COMP=*/
    0,
    /*SENDRECV=*/
    0,
    /*RX_CTRL=*/
    0,
};

/* helpers */

#include "debug1.h"
#include "param1.h"
#include <stdlib.h>
#include <string.h>

#define TCPX_SLOWNESS_SWITCH_NAME_MAX_LEN 16
static char tcpxSlownessSwitchName[TCPX_SLOWNESS_SWITCH_MAX_CNT]
                                  [TCPX_SLOWNESS_SWITCH_NAME_MAX_LEN] = {
                                      "TX_COMP",
                                      "SENDRECV",
                                      "RX_CTRL",
};

void parseSlownessSwitchFlagInternal(
    const char *env_str, int switches[TCPX_SLOWNESS_SWITCH_MAX_CNT]) {
  /* Parse the "env_name" env var
   * This can be a comma separated list such as <opt1>,<opt2>
   */
  if (env_str != NULL) {
    const int enable = 1;
    char *env = strdup(env_str);
    char *opt = strtok(env, ",");
    while (opt != NULL) {
      if (!strcasecmp(opt, "TX_COMP")) {
        switches[TX_COMP] = enable;
      } else if (!strcasecmp(opt, "SENDRECV")) {
        switches[SENDRECV] = enable;
      } else if (!strcasecmp(opt, "RX_CTRL")) {
        switches[RX_CTRL] = enable;
      } else if (!strcasecmp(opt, "ALL")) {
        for (int i = 0; i < TCPX_SLOWNESS_SWITCH_MAX_CNT; i++) {
          switches[i] = enable;
        }
      }

      opt = strtok(NULL, ",");
    }
    free(env);
  }
}

void parseSlownessSwitchFlags() {
  constexpr char default_switches[] = "TX_COMP,SENDRECV,RX_CTRL";
  {
    const char *env_str = TCPX_GET_ENV("SLOWNESS_SWITCH");
    if (env_str) {
      INFO(TCPX_ENV, "NCCL_GPUDIRECTTCPX_SLOWNESS_SWITCH set by environment to: %s", env_str);
      parseSlownessSwitchFlagInternal(env_str, kSlownessSwitch);
    } else {
      parseSlownessSwitchFlagInternal(default_switches, kSlownessSwitch);
    }
  }

  {
    const char *env_str = TCPX_GET_ENV("SLOWNESS_REPORT");
    if (env_str) {
      INFO(TCPX_ENV, "NCCL_GPUDIRECTTCPX_SLOWNESS_REPORT set by environment to: %s", env_str);
      parseSlownessSwitchFlagInternal(env_str, kSlownessReport);
    } else {
      parseSlownessSwitchFlagInternal(default_switches, kSlownessReport);
    }
  }

  for (int i = 0; i < TCPX_SLOWNESS_SWITCH_MAX_CNT; i++) {
    if (!kSlownessSwitch[i] && kSlownessReport[i]) {
      INFO(NCCL_ENV,
           "%s slowness: detection is disabled, hence turning report off",
           tcpxSlownessSwitchName[i]);
      kSlownessReport[i] = 0;
    }
    INFO(NCCL_ENV, "%s slowness: detection %d report %d",
         tcpxSlownessSwitchName[i], kSlownessSwitch[i], kSlownessReport[i]);
  }
}

int kCudaUsePrimaryCtx = 1;
