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

#include <string.h>
#include <unistd.h>

#include <cstdlib>
#include <thread>
#include "common.h"
#include "flags.h"
#include "timeout.h"
#include "stats/exporter.h"
#include "work_queue.h"
#include <cstdlib>

// Global variables
struct tcpxGlobal global;

int kTcpxNetIfs = -1;
struct tcpxDev kTcpxCtrlDev;
struct tcpxDev kTcpxSocketDevs[MAX_IFS];
pthread_mutex_t kTcpxGPUDirectTCPXLock = PTHREAD_MUTEX_INITIALIZER;
constexpr int FILE_NAME_SIZE = 256;

//

void getNodeCpu(struct tcpxBindings *bindings, int i, int node_idx) {
  char fname[128];
  snprintf(fname, 128, "/sys/devices/system/node/node%d/cpulist", node_idx);
  FILE* f = fopen(fname, "r");

  bindings->n_ranges[i] = 0;

  int ret;
  int lo, hi;
  while ((ret = fscanf(f, "%d-%d", &lo, &hi)) == 2) {
    int cnt = bindings->n_ranges[i]++;
    bindings->lo[i][cnt] = lo;
    bindings->hi[i][cnt] = hi;
    if (fscanf(f, ",") == EOF) break;
  }
}

void inPlaceStrSplit(char* in, const char* delim, char** out1, char** out2) {
  *out1 = in;
  if ((*out2 = strstr(in, delim)) == NULL) return;

  **out2 = '\0';
  *out2 += 1;
}

void parseCoreRanges(char* _env_str, struct tcpxBindings *b) {
  if (!_env_str) return;

  char *const env_str = (char *)calloc(strlen(_env_str) + 2, sizeof(char));
  if (!env_str) {
    perror("calloc");
    return;
  }
  memcpy(env_str, _env_str, strlen(_env_str) + 1);

  if (env_str[strlen(env_str)-1] != ';') env_str[strlen(env_str)] = ';';
  char *rem = env_str;
  char *phrase = env_str;
  while (rem) {
    inPlaceStrSplit(rem, ";", &phrase, &rem);

    char* ifname, *ranges;
    inPlaceStrSplit(phrase, ":", &ifname, &ranges);
    if (!ranges) {
      // WARN("skip parsing %s", phrase);
      continue;
    }

    int* lo_range, * hi_range, *n_range;
    lo_range = hi_range = n_range = NULL;
    for (int i=0; i<kTcpxNetIfs; i++) {
      if (!strcmp(kTcpxSocketDevs[i].dev_name, ifname)) {
        n_range = b->n_ranges + i;
        lo_range = b->lo[i];
        hi_range = b->hi[i];
      }
    }
    if (lo_range == NULL) {
      INFO(TCPX_NET, "%s not a datapath NIC for this run", ifname);
      continue;
    }

    *n_range = 0;
    char* range;
    while (ranges) {
      inPlaceStrSplit(ranges, ",", &range, &ranges);

      char* lo, *hi;
      inPlaceStrSplit(range, "-", &lo, &hi);
      if (!hi) {
        WARN("invalid range %s", range);
        continue;
      }

      int i = *n_range;
      lo_range[i] = atoi(lo);
      hi_range[i] = atoi(hi);
      (*n_range)++;
      INFO(TCPX_INIT | TCPX_NET, "dev %s, cores %d-%d", ifname, lo_range[i], hi_range[i]);
    }
  }

  free(env_str);
}

tcpxResult_t tcpxMemHandleNew(struct tcpxMemHandle** mhandle) {
  TCPXCHECK(tcpxCalloc(mhandle, 1));
  (*mhandle)->uptr = nullptr;
  (*mhandle)->ptr = nullptr;
  (*mhandle)->mem_type = -1;
  (*mhandle)->gpu_mem_fd = -1;
  (*mhandle)->gpu = nullptr;
  (*mhandle)->gpu_tx = nullptr;
  return tcpxSuccess;
}

//

char* tcpxHandleToString(struct tcpxHandle* h, char* buf, int len) {
  char conn_line[256];
  char ctrl_line[256];
  int ret =
      snprintf(buf, len,
               "connect_addr %s, redirect[%d]ctrl_addr %s, port_start %d, "
               "port_count %d, num_socks %d, num_threads %d",
               socketToString(&h->connect_addr, conn_line), h->redirect_ctrl,
               socketToString(&h->ctrl_addr, ctrl_line), h->port_start,
               h->port_count, h->num_socks, h->num_threads);
  if (ret > len) {
    WARN("omitted part of handle info");
  }
  return buf;
}

//

tcpxResult_t tcpxNewListenComm(
    struct tcpxListenComm** comm, int dev) {
  TCPXCHECK(tcpxCalloc(comm, 1));
  (*comm)->host_fd = -1;
  TCPXCHECK(gpu_current_dev(global.gpus, &(*comm)->gpu));
  for (int i = 0; i < MAX_SOCKETS; i++) {
    (*comm)->cuda_fd[i] = -1;
    (*comm)->cuda_port[i] = -1;
  }
  (*comm)->dev = dev;
  (*comm)->num_socks = 0;
  (*comm)->num_threads = 0;
  (*comm)->accept_args = nullptr;
  return tcpxSuccess;
}

tcpxResult_t tcpxCommNew(struct tcpxComm** comm, int dev) {
  TCPXCHECK(tcpxCalloc(comm, 1));
  (*comm)->passive = false;
  (*comm)->conn_state = CONN_PENDING;
  for (int i = 0; i < MAX_SOCKETS; i++) {
    (*comm)->fd_data[i].fd = -1;
    (*comm)->fd_data[i].used = false;
    (*comm)->fd_data[i].stat_hi = 0;
    (*comm)->fd_data[i].stat_lo = 0;
    (*comm)->fd_data[i].tx_upper = 0;
    (*comm)->fd_data[i].tx_lower = 0;
    tcpxSocketStatsInit(&(*comm)->fd_data[i].stats);
    tcpxTimeoutDetectionInit(&(*comm)->fd_data[i].timeout, {
      .threshold_ns = (uint64_t) kTimeoutThresholdNs,
      .frequency_ns = (uint64_t) kTimeoutFrequencyNs,
      .timenow = defaultTimenow,
    });
  }
  (*comm)->num_socks = 0;
  (*comm)->num_threads = 0;
  (*comm)->begin_fd_idx = 0;
  (*comm)->end_fd_idx = 0;
  (*comm)->ctrl_fd = -1;
  tcpxTimeoutDetectionInit(&(*comm)->ctrl_timeout, {
    .threshold_ns = (uint64_t) kTimeoutThresholdNs,
    .frequency_ns = (uint64_t) kTimeoutFrequencyNs,
    .timenow = defaultTimenow,
  });
  tcpxSocketStatsInit(&(*comm)->ctrl_stats);
  (*comm)->dev = dev;
  TCPXCHECK(gpu_current_dev(global.gpus, &(*comm)->gpu));
  (*comm)->socket_direct_handle = nullptr;
  (*comm)->socket_direct_dev_handle = nullptr;

  if (kExportStatsToFile) {
    StatsBufferInit((*comm)->statsbuf);
    tcpxCommExporter(*comm, EXPORTER_PROFILING_INFO);
  }

  return tcpxSuccess;
}

void tcpxCommExporter(struct tcpxComm* comm, ExporterType exporter_type) {
  if (exporter_type == EXPORTER_PROFILING_INFO) {
    int cpu_core = -1;
    // When setting the core, do not use the cores that are running tasks.
    char* env = getenv("NCCL_GPUDIRECTTCPX_TELEMETRY_EXPORTER_CORE_INDEX");
    if (env) {
      cpu_core = std::atoi(env);
    } else {
      cpu_core = 171;
    }
    std::thread exporter([=]() {
      cpu_set_t cpuset;
      CPU_ZERO(&cpuset);
      CPU_SET(cpu_core, &cpuset);
      char fname[FILE_NAME_SIZE];
      if (sched_setaffinity(0, sizeof(cpuset), &cpuset) == -1) {
        std::cerr << "Failed to set CPU affinity" << std::endl;
      }

      char* env = getenv("NCCL_GPUDIRECTTCPX_TELEMETRY_EXPORTER_PATH");
      if (!env){
        strcpy(env,"tmp");
      }
      if (env) {
        snprintf(fname, FILE_NAME_SIZE, "/%s/exporter_%d_%p.log", env, getpid(), comm);
        INFO(TCPX_NET, "exporter %s started %d_%p", comm->passive ? "rx" : "tx",
             getpid(), comm);
      } else {
          INFO(TCPX_NET, "exporter %s skipped %d_%p",
               comm->passive ? "rx" : "tx", getpid(), comm);
          return;
      }
      net_gpudirecttcpx_stats::Exporter e{fname, comm};
      e.appendToFile();
    });
    comm->exporter_thread = std::move(exporter);
  } else if (exporter_type == EXPORTER_STATS_INFO) {
    char fname[FILE_NAME_SIZE];
    char* env = getenv("NCCL_GPUDIRECTTCPX_TELEMETRY_EXPORTER_PATH");
    if (env) {
      snprintf(fname, FILE_NAME_SIZE, "/%s/exporter_stats_%d_%p.log", env, getpid(), comm);
      INFO(TCPX_NET, "exporter %s started %d_%p", comm->passive ? "rx" : "tx",
           getpid(), comm);
    } else {
      INFO(TCPX_NET, "exporter %s skipped %d_%p", comm->passive ? "rx" : "tx",
           getpid(), comm);
      return;
    }
    net_gpudirecttcpx_stats::Exporter_stats e_stats{fname, comm};
    e_stats.appendToFile();
  }
}

void tcpxCommFree(struct tcpxComm* comm) {
  if (kExportStatsToFile) {
    StatsBufferDestructQueue(comm->statsbuf);
    comm->exporter_thread.join();
    StatsBufferDestruct(comm->statsbuf);
    tcpxCommExporter(comm, EXPORTER_STATS_INFO);
  }
  for (int i = 0; i < MAX_SOCKETS; i++) {
    comm->fd_data[i].tasks.destruct();
  }
  if (comm->socket_direct_handle) {
    tcpxNetDeviceQueueFree(comm->socket_direct_handle,
                                   comm->socket_direct_dev_handle);
  }
  free(comm);
}

uint64_t generateFlowId(char* flow_str) {
  std::hash<std::string> hasher;
  std::size_t flow_hash = hasher(std::string(flow_str));
  return static_cast<uint64_t>(flow_hash);
}
