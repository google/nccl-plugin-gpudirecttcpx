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

#include <assert.h>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <linux/tcp.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>

#include <immintrin.h>

#include <algorithm>
#include <atomic>
#include <string>
#include <filesystem>
#include <sys/stat.h>
#include <chrono>
#include <regex>

#include "adapter/ret.h"
#include "adapter1.h"
#include "checks1.h"
#include "common.h"
#include "config.h"
#include "connect.h"
#include "flags.h"
#include "flow_mapper.h"
#include "rx_buf_mgr_client/application_registry_client.h"
#include "unpack_defs1.h"
#include "cuda_wrapper.h"
#include "net_device.h"
#include "unpack1.h"
#include "work_queue.h"
#include "tcpx.h"
#include "timeout.h"
#include "socket_utils.h"

#define NANOS_PER_SECOND 1000000000ULL
constexpr int FILE_NAME_SIZE = 256;

// Whether to enable the plugin. Default is enabled.
TCPX_PARAM(EnableGPUDirectTCPX, "GPUDIRECTTCPX_SOCKET_ENABLE", 1);

// Minimum data size to use zero-copy. 0 means disabled.
TCPX_PARAM(MinZcopySize, "MIN_ZCOPY_SIZE", 0);

TCPX_PARAM(NSocksPerThread, "NSOCKS_PERTHREAD", -2);
TCPX_PARAM(NThreads, "SOCKET_NTHREADS", -2);

// must be specified
TCPX_PARAM(GPUDirectTCPXPortBegin, "GPUDIRECTTCPX_PORT_BEGIN", -2);
TCPX_PARAM(GPUDirectTCPXPortEnd, "GPUDIRECTTCPX_PORT_END", -2);

// Maximum size of data to inline with a control message.
// 0 means disable inlining.
TCPX_PARAM(InlineThreshold, "INLINE_THRESHOLD", 0);

// Maximum chunk size in bytes for dynamic loading balancing.
// Default is 128 KB
TCPX_PARAM(DynamicChunkSize, "DYNAMIC_CHUNK_SIZE", 0);

// Whether to spin the helper thread. Default is disabled.
TCPX_PARAM(EnableThreadSpin, "THREAD_SPIN_ENABLE", 0);

TCPX_PARAM(ScatterCopyMinMessageSize, "SCATTER_COPY_MIN_MESSAGE_SIZE", 8192);
TCPX_PARAM(StagingBufferSize, "STAGING_BUFFER_SIZE", 8192);

TCPX_PARAM(UseDmaBuf, "USE_DMA_BUF", -2);
// TCPX_PARAM(UseSocketDirect, "USE_SOCKET_DIRECT", -2);

TCPX_PARAM(ConnectionRetry, "GPUDIRECTTCPX_CONNECTION_RETRY", -2);

TCPX_PARAM(RecvSync, "GPUDIRECTTCPX_RECV_SYNC", 0);
TCPX_PARAM(ForceAck, "GPUDIRECTTCPX_FORCE_ACK", 0);

TCPX_PARAM(SleepNs, "GPUDIRECTTCPX_TX_COMPLETION_NANOSLEEP", 0);

TCPX_PARAM(TimeoutThresholdNs, "GPUDIRECTTCPX_TIMEOUT_THRESHOLD_NS", -2);
TCPX_PARAM(TimeoutFrequencyNs, "GPUDIRECTTCPX_TIMEOUT_FREQUENCY_NS", -2);

TCPX_PARAM(SpinWaitConnect, "GPUDIRECTTCPX_SPINWAIT_CONNECT", -2);

TCPX_PARAM(LogStatsToStdout, "GPUDIRECTTCPX_LOG_STATS_TO_STDOUT", 0);

TCPX_PARAM(EnableTaskLevelStats, "GPUDIRECTTCPX_TELEMETRY_ENABLE_TASK_LEVEL_STATS", 0);
TCPX_PARAM(EnableRequestLevelStats, "GPUDIRECTTCPX_TELEMETRY_ENABLE_REQUEST_LEVEL_STATS", 0);
TCPX_PARAM(ExportStatsToFile, "GPUDIRECTTCPX_TELEMETRY_EXPORT_STATS_TO_FILE", 0);

TCPX_PARAM(SamplingFactor, "GPUDIRECTTCPX_TELEMETRY_SAMPLING_FACTOR", 1);

TCPX_PARAM(LogLineLimit, "GPUDIRECTTCPX_TELEMETRY_LOG_LINE_LIMIT", 256);

TCPX_PARAM(ReportLifecycle, "GPUDIRECTTCPX_REPORT_LIFECYCLE", 0);

TCPX_PARAM(CudaUsePrimaryCtx, "GPUDIRECTTCPX_CUDA_USE_PRIMARY_CTX", 1);

static inline void setSockQuickAck(int fd, int v = 1) {
  if (setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &v, sizeof v) < 0) {
    WARN("Cannot set socket to TCP_QUICKACK");
  }
}

static inline bool seq32_lt(uint32_t seq1, uint32_t seq2)
{
  return (int32_t)(seq1-seq2) < 0;
}

static inline uint32_t seq32_max(uint32_t seq1, uint32_t seq2)
{
  return seq32_lt(seq1, seq2) ? seq2: seq1;
}

static inline uint32_t seq32_min(uint32_t seq1, uint32_t seq2)
{
  return seq32_lt(seq1, seq2) ? seq1: seq2;
}

//////
// helpers
//////
static int taskProgress(struct tcpxFdData* fd_data, struct tcpxTask* t, int* user_buffer_count) {
  int bytes = 0;
  char* data = reinterpret_cast<char*>(t->data);
  int count = 0;
  int gpudirecttcpx_count = 0;
  int op = t->op; int mem_type = t->r->mem_type;
  // do {
    int s = t->size - t->offset;
    int flags = MSG_DONTWAIT;
    if (op == TCPX_SOCKET_SEND && kMinZcopySize > 0 && s >= kMinZcopySize)
      flags |= MSG_ZEROCOPY;
    if (op == TCPX_SOCKET_RECV) {
      if (mem_type == TCPX_PTR_HOST) {
        WARN("NET/" PRODUCT_NAME " requested receive on host mem buffer");
        bytes = recv(fd_data->fd, data + t->offset, s, flags);
      } else {
        bytes = gpudirectTCPXRecv(fd_data->fd, t->data, t->size, t->offset, t->pipe, t->request_offset,
                              user_buffer_count);
      }
      TCPX_TP(TASK, TCPX_TASK_TP_RECVMSG, t, bytes, 1 /*place holder*/);
    }
    if (op == TCPX_SOCKET_SEND) {
      if (mem_type == TCPX_PTR_HOST) {
        // LL
        bytes = send(fd_data->fd, data + t->offset, s, flags);
      } else {
        bytes = gpudirectTCPXPostSend(fd_data->fd, t->r->gpu_mem_fd,
                                  t->size, t->offset, t->page_off,
                                  t->r->gpu_mem_off, t->pipe->buf);
        if (bytes > 0) {
          ++gpudirecttcpx_count;
          if (t->tx_i >= MAX_TX_COUNT) {
            // There is no good way to handle this. Just accumulate it to the last tx size.
            t->tx_sz[MAX_TX_COUNT - 1] += bytes;
            WARN("[%s] more than %d sends for %zuB", fd_data->flow_str, MAX_TX_COUNT, t->size);
          } else {
            t->tx_sz[t->tx_i++] = bytes;
          }
        }
      }
      TCPX_TP(TASK, TCPX_TASK_TP_SENDMSG, t, bytes, 1 /*place holder*/);
    }
    if (op == TCPX_SOCKET_RECV && bytes == 0) {
      WARN("Net : Connection closed by remote peer %s", t->pipe->flow_str);
      return -1;
    }
    if (bytes < 0) {
      if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN && errno != ENOBUFS) {
        WARN("Call to socket op %s(%d) %s flags %x failed : %s",
             op == TCPX_SOCKET_SEND ? "send" : "recv", op, t->pipe->flow_str, flags,
             strerror(errno));
        return -1;
      } else {
        bytes = 0;
      }
    }
    t->offset += bytes;
    if (bytes && (flags & MSG_ZEROCOPY)) ++count;
  // } while (...);

  if (op == TCPX_SOCKET_SEND && mem_type == TCPX_PTR_CUDA)
    count = gpudirecttcpx_count;

  return count;
}

static inline void tx_count_incr(struct tcpxTask* t, uint32_t v, uint64_t *comp_bytes) {
  for (uint32_t i = 0; i < v; i += 1) {
    *comp_bytes += t->tx_sz[t->tx_count + i];
  }

  t->tx_count += v;
}

void processCompletion(tcpxTaskQueue* tasks, uint32_t clower,
                       uint32_t lower, uint32_t upper, uint64_t *comp_bytes) {
  auto it = tasks->get_iterator<TASK_COMPLETING>();
  while (seq32_lt(lower, upper) && tasks->is<TASK_COMPLETING>(it)) {
    tcpxTask* t = tasks->to_item(it);
    uint32_t cupper = t->tx_bound;
    uint32_t left = seq32_max(clower, lower);
    uint32_t right = seq32_min(cupper, upper);
    if (seq32_lt(left, right)) {
      tx_count_incr(t, right - left, comp_bytes);
      TCPX_TP(TASK, TCPX_TASK_TP_COMPLETION, t, 0 /*placeholder*/, right - left);
    }
    lower = seq32_max(lower, cupper);
    clower = cupper;
    it = tasks->next(it);
  }
  if (seq32_lt(lower, upper) && tasks->is<TASK_ACTIVE>(it)) {
    tcpxTask* t = tasks->to_item(it);
    tx_count_incr(t, upper - lower, comp_bytes);
    TCPX_TP(TASK, TCPX_TASK_TP_COMPLETION, t, 0 /*placeholder*/, upper - lower);
  }
}

void trySleep() {
  if (kSleepNs > 0) {
    struct timespec sleep_ts = { 0, kSleepNs };
    nanosleep(&sleep_ts, NULL);
  }
}

static void* persistentSocketThread(void* args_) {
  struct tcpxThreadResources* resource =
      static_cast<struct tcpxThreadResources*>(args_);
  struct tcpxComm* comm = resource->comm;
  volatile enum ThreadState* state = &resource->state;
  int tid = resource->id;
  unsigned int mark = 0;

  INFO(TCPX_INIT | TCPX_NET, "Comm %p thread %d started", comm, tid);

  int nSocksPerThread = comm->num_socks / comm->num_threads;
  int nThreads = comm->num_threads;

  struct tcpxBindings *b =  comm->passive ? &global.rx_bindings : &global.tx_bindings;
  int n_ranges = b->n_ranges[comm->dev];
  int *lo = b->lo[comm->dev];
  int *hi = b->hi[comm->dev];

  int total_cores = 0;
  for (int i=0; i<n_ranges; i++) {
    total_cores += hi[i] - lo[i] + 1;
  }
  int range_id = (resource->stride * kNThreads + tid) % total_cores;
  INFO(TCPX_INIT | TCPX_NET, "Comm %p dev %d, range_id %d = stride %u + tid %d", comm, comm->dev, range_id, resource->stride, tid);

  cpu_set_t my_set;
  CPU_ZERO(&my_set);

  char *env_str;
  if ((env_str = TCPX_GET_ENV("WORKER_PIN_THREADS")) && env_str[0] == '1') {
    char *env_u = TCPX_GET_ENV("WORKER_SPRAY_COUNT");
    char *env_v = TCPX_GET_ENV("WORKER_SPRAY_STRIDE");
    int u = 0, v = 0;
    if (env_u) u = atoi(env_u);
    if (env_v) v = atoi(env_v);
    for (int j = 0; j <= u; j++) { // 0 is the base case
      range_id = (resource->stride * kNThreads + tid + v * j) % total_cores;
      for (int i = 0; i < n_ranges; i++) {
          int delta = hi[i] - lo[i] + 1;
          if (range_id < delta) { // in range
            CPU_SET(lo[i] + range_id, &my_set);
            // CPU_SET(lo[i] + range_id + 112, &my_set);
            break;
          } else {
            range_id -= delta;
          }
      }
    }
  } else {
    for (int i = 0; i < n_ranges; i++) {
      for (int c = lo[i]; c <= hi[i]; c++)
          CPU_SET(c, &my_set);
      INFO(TCPX_INIT | TCPX_NET, "Comm %p dev %d, cores %d-%d", comm, comm->dev, lo[i], hi[i]);
    }
  }
  sched_setaffinity(0, sizeof my_set, &my_set);

  int cpu = -2;
  if ((cpu = sched_getcpu()) < 0) {
    perror("sched_getcpu");
  } else {
    INFO(TCPX_INIT | TCPX_NET,
         "Comm %p thread %d running on (cpu) (%d)", comm, tid, cpu);
  }
  uint32_t lower = 0, upper = 0;  // avoid compiler warning
  while (true) {
    int idle = 1;
    // iterate all the sockets associate with the current thread
    for (int i = 0; i < nSocksPerThread; ++i) {
      // int idx = i + tid * nSocksPerThread; // sequential access
      int idx = tid + i * nThreads;  // strided access
      struct tcpxFdData* fd_data = comm->fd_data + idx;
      tcpxTaskQueue* tasks = &(fd_data->tasks);
      if (tasks->has_active()) {
        struct tcpxTask* t = fd_data->tasks.next_active();
        int old_offset = t->offset;
        int cnt = taskProgress(fd_data, t, &resource->user_buffer_count);
        if (cnt < 0) return nullptr;
        fd_data->tx_upper += cnt;
        if (t->op == TCPX_SOCKET_SEND) fd_data->stat_hi += t->offset - old_offset;
        if (t->offset == t->size) {
          t->tx_bound = fd_data->tx_upper;
          tasks->finish_active();
        }
        idle = 0;
      }

      // poll errqueue for send completion
      if (fd_data->tx_upper != fd_data->tx_lower) {
        TCPX_TP(TASK, TCPX_TASK_TP_COMPLETION, comm, idx);
        while (true) {
          int ret = readErrqueue(fd_data->fd, &lower, &upper);
          if (ret == 0) {
            if (idle) {
              trySleep();
            }
            break;
          }
          if (ret < 0) return nullptr;
          processCompletion(tasks, fd_data->tx_lower, lower, upper, &fd_data->stat_lo);
        }
        idle = 0;
      }

      if (tasks->has_completing()) {
        struct tcpxTask* t = tasks->next_completing();
        if (t->op == TCPX_SOCKET_SEND) {
          if (t->tx_count == t->tx_bound - fd_data->tx_lower) {
            fd_data->tx_lower = t->tx_bound;
            tasks->finish_completing();
          }
        } else {
          int done;
          TCPXASSERT(gpu_inline_test(t->pipe->gpu_inline, &done));
          if (done) {
            tasks->finish_completing();
          }
        }
        idle = 0;
      }
    }
    if (kEnableSpin) idle = 0;
    if (idle) {
      pthread_mutex_lock(&resource->thread_lock);
      while (mark == resource->next && *state != stop) {  // no new tasks, wait
        pthread_cond_wait(&resource->thread_cond, &resource->thread_lock);
      }
      mark = resource->next;
      pthread_mutex_unlock(&resource->thread_lock);
    }
    if (*state == stop) return nullptr;
  }
}

////
// API Impls
////

int countCpus() {
  return sysconf(_SC_NPROCESSORS_ONLN);
}

int cleanTelemetryLogFiles(int cpu_core) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu_core, &cpuset);
  char dirpath[FILE_NAME_SIZE];
  char* env = getenv("NCCL_GPUDIRECTTCPX_TELEMETRY_EXPORTER_PATH");
  if (!env) {
    strcpy(env, "tmp");
  }
  if (snprintf(dirpath, FILE_NAME_SIZE, "/%s", env) < 0) {
    return tcpxInternalError;
  }
  env = getenv("NCCL_GPUDIRECTTCPX_TELEMETRY_FILE_LIFE");
  uint64_t life_of_file = 24 * 60;  // 24 hrs
  if (env) {
    life_of_file = std::atoi(env);
  }
  env = getenv("NCCL_GPUDIRECTTCPX_TELEMETRY_FILE_REMOVE_FREQUENCY");
  uint64_t file_remove_freq = 24 * 60 * 60;  // 24 hrs
  if (env) {
    file_remove_freq = std::atoi(env);
  }

  while (true) {
    for (const auto& entry : std::filesystem::directory_iterator(dirpath)) {
      auto ds = (std::filesystem::file_time_type::clock::now() -
                 entry.last_write_time());
      if (ds.count() / NANOS_PER_SECOND > life_of_file * 60) {
        const std::regex txt_regex("/.*/exporter_.*.log");
        if (std::regex_match(entry.path().c_str(), txt_regex)) {
          remove(entry.path().c_str());
        }
      }
    }
    usleep(file_remove_freq * 1000000);  // sleep time in microsecond
  }
}

TCPX_PARAM(GPUDirectTCPXNicNRxqs, "GPUDIRECTTCPX_NIC_N_RXQS", -2);
size_t defaultRxqs() {
  int v = TCPX_GET_PARAM(GPUDirectTCPXNicNRxqs);
  if (v > 0) return (size_t) v;

  return 32;
}

#define TCPX_GET_INT_FLAG(kFlag, paramName, flagName, lo, hi)                  \
  do {                                                                         \
    int64_t v = TCPX_GET_PARAM(paramName);                                     \
    if (v >= lo && v < hi) {                                                   \
      kFlag = v;                                                               \
    } else {                                                                   \
      INFO(TCPX_ENV,                                                           \
           "NET/" PRODUCT_NAME " : " flagName                                 \
           " %ld invalid, restore to default.",                                \
           v);                                                                 \
    }                                                                          \
    INFO(TCPX_ENV, "NET/" PRODUCT_NAME " : " flagName ": %li", (int64_t) kFlag);          \
  } while (0);

tcpxResult_t tcpxInit(tcpxDebugLogger_t logFunction) {
  tcpx_log_func = logFunction;

  int enable = 1;
  TCPX_GET_INT_FLAG(enable, EnableGPUDirectTCPX, "GPUDirectTCPX enable",
                    /*lo=*/0,
                    /*hi=*/2);  // non-inclusive

#ifdef CHECK_COLLNET_ENABLE
  char* collnet_enable = getenv("NCCL_COLLNET_ENABLE");
  if (!collnet_enable || strcmp(collnet_enable, "0") == 0) {
    enable = 0;
  }
#endif

  INFO(TCPX_NET | TCPX_INIT, "NET/" PRODUCT_NAME " initialization start");
  if (!enable) {
    INFO(TCPX_NET | TCPX_INIT, "NET/" PRODUCT_NAME " disabled");
    return tcpxInternalError;
  }

  TCPX_GET_INT_FLAG(kInlineThreshold, InlineThreshold, "inline threshold",
                    /*lo=*/0,
                    /*hi=*/MAX_INLINE_THRESHOLD + 1); // non-inclusive

  TCPX_GET_INT_FLAG(kDynamicChunkSize, DynamicChunkSize, "dynamic chunk size",
                    /*lo=*/0,
                    /*hi=*/INT_MAX);

  TCPX_GET_INT_FLAG(kEnableSpin, EnableThreadSpin, "enable thread spin",
                    /*lo=*/0,
                    /*hi=*/2); // non-inclusive

  TCPX_GET_INT_FLAG(kMinZcopySize, MinZcopySize, "min zcopy size",
                    /*lo=*/0,
                    /*hi=*/INT_MAX);

  TCPX_GET_INT_FLAG(kUseDmaBuf, UseDmaBuf, "use dmabuf",
                    /*lo=*/0,
                    /*hi=*/2); // non-inclusive

  TCPX_GET_INT_FLAG(kNSocksPerThread, NSocksPerThread, "nsocks per thread",
                    /*lo=*/1,
                    /*hi=*/MAX_SOCKETS + 1); // non-inclusive

  TCPX_GET_INT_FLAG(kNThreads, NThreads, "nthreads",
                    /*lo=*/1,
                    /*hi=*/MAX_THREADS + 1); // non-inclusive

  TCPX_GET_INT_FLAG(kConnectionRetry, ConnectionRetry, "connection retry count",
                    /*lo=*/0,
                    /*hi=*/INT_MAX);

  TCPX_GET_INT_FLAG(kRecvSync, RecvSync, "receiver sync",
                    /*lo=*/0,
                    /*hi=*/2); // non-inclusive

  TCPX_GET_INT_FLAG(kForceAck, ForceAck, "enable quick ack",
                    /*lo=*/0,
                    /*hi=*/2); // non-inclusive

  TCPX_GET_INT_FLAG(kSleepNs, SleepNs, "tx completion nanosleep",
                    /*lo=*/0,
                    /*hi=*/INT_MAX); // non-inclusive

  TCPX_GET_INT_FLAG(kTimeoutThresholdNs, TimeoutThresholdNs, "timeout report threshold in nanos",
                    /*lo=*/100 * 1000, // 100 us min
                    /*hi=*/LLONG_MAX); // non-inclusive
  TCPX_GET_INT_FLAG(kTimeoutFrequencyNs, TimeoutFrequencyNs, "timeout report frequency in nanos",
                    /*lo=*/100 * 1000, // 100 us min
                    /*hi=*/LLONG_MAX); // non-inclusive

  TCPX_GET_INT_FLAG(kSpinWaitConnect, SpinWaitConnect, "spin wait connect",
                    /*lo=*/0,
                    /*hi=*/2); // non-inclusive

  TCPX_GET_INT_FLAG(kLogStatsToStdout, LogStatsToStdout, "log stats to stdout",
                    /*lo=*/0,
                    /*hi=*/2); // non-inclusive

  TCPX_GET_INT_FLAG(kEnableTaskLevelStats, EnableTaskLevelStats, "enable task level stats",
                    /*lo=*/0,
                    /*hi=*/2); // non-inclusive

  TCPX_GET_INT_FLAG(kEnableRequestLevelStats, EnableRequestLevelStats,
                    "enable request level stats",
                    /*lo=*/0,
                    /*hi=*/2);  // non-inclusive

  TCPX_GET_INT_FLAG(kExportStatsToFile, ExportStatsToFile,
                    "enable exporter to export stats to file",
                    /*lo=*/0,
                    /*hi=*/2);  // non-inclusive
  TCPX_GET_INT_FLAG(kSamplingFactor, SamplingFactor,
                    "enables sampling of telemetry, higher the value lesser the samples collected",
                    /*lo=*/1,
                    /*hi=*/1000000);  // non-inclusive
  TCPX_GET_INT_FLAG(kLogLineLimit, LogLineLimit,
                    "length of each log line exporter from telemetry",
                    /*lo=*/1,
                    /*hi=*/257);  // non-inclusive

  TCPX_GET_INT_FLAG(kReportLifecycle, ReportLifecycle,
                    "enable reporting workload's lifecycle to RxDM",
                    /*lo=*/0,
                    /*hi=*/2);  // non-inclusive

  parseSlownessSwitchFlags();

  TCPX_GET_INT_FLAG(kCudaUsePrimaryCtx, CudaUsePrimaryCtx, "use primary cuda ctx",
                    /*lo=*/0,
                    /*hi=*/2); // non-inclusive

  char* u = TCPX_GET_ENV("UNIX_CLIENT_PREFIX");
  if (u) kUnixClientPrefix = u;
  INFO(NCCL_INIT, "NET/" PRODUCT_NAME " : unix client prefix %s", kUnixClientPrefix);

  int n_gpus;
  TCPXCHECK(gpu_n_dev(&n_gpus));
  TCPXCHECK(gpu_init(&global.gpus, n_gpus));

  prctl(PR_SET_TIMERSLACK, 1UL);
  TCPXCHECK(tcpxInitConnectionSetup(&global.connection_setup));

  {
    int cpu_count = countCpus();
    if (cpu_count < 0) {
      return tcpxInternalError;
    }
    INFO(TCPX_NET | TCPX_INIT, "NET/" PRODUCT_NAME " total number of cpus: %d", cpu_count);

    for (int i = 0; i < kTcpxNetIfs; i++) {
      global.tx_bindings.n_ranges[i] = 0;
      global.rx_bindings.n_ranges[i] = 0;
      global.tx_irq_bindings.n_ranges[i] = 0;
      global.rx_irq_bindings.n_ranges[i] = 0;
    }

    {
      // defaults
      for (int i=0; i<kTcpxNetIfs; i++) {
        char fname[128];
        snprintf(fname, 128, "/sys/class/net/%s/device/numa_node", kTcpxSocketDevs[i].dev_name);
        FILE* f = fopen(fname, "r");
        if (!f) {
          global.tx_bindings.n_ranges[i] = 1;
          global.tx_bindings.lo[i][0] = 0;
          global.tx_bindings.hi[i][0] = cpu_count - 1;
          global.rx_bindings.n_ranges[i] = 1;
          global.rx_bindings.lo[i][0] = 0;
          global.rx_bindings.hi[i][0] = cpu_count - 1;
        } else {
          int node_idx = fgetc(f) == '0' ? 0 : 1;  // assume only two nodes
          getNodeCpu(&global.tx_bindings, i, node_idx);
          getNodeCpu(&global.rx_bindings, i, node_idx);
        }
      }
    }

    for (int i = 0; i < MAX_IFS; i++) {
      pthread_mutex_init(&global.rxq_record[i].mu, 0);
      pthread_mutex_lock(&global.rxq_record[i].mu);
      global.rxq_record[i].n_rxqs = defaultRxqs(); // assume same config for each NIC
      global.rxq_record[i].napi_id_cnt.clear();
      global.rxq_record[i].napi_id_cnt_counter = 0;
      global.rxq_record[i].napi_id_cnt_curr_hi = 1;
      pthread_mutex_unlock(&global.rxq_record[i].mu);
    }

    {
      char *env_str = TCPX_GET_ENV("TX_BINDINGS");
      INFO(TCPX_ENV, "TCPX_GPUDIRECTTCPX_TX_BINDINGS %s", env_str);
      parseCoreRanges(env_str, &global.tx_bindings);
    }
    {
      char *env_str = TCPX_GET_ENV("RX_BINDINGS");
      INFO(TCPX_ENV, "TCPX_GPUDIRECTTCPX_RX_BINDINGS %s", env_str);
      parseCoreRanges(env_str, &global.rx_bindings);
    }
    {
      char *env_str = TCPX_GET_ENV("TX_IRQ_BINDINGS");
      INFO(TCPX_ENV, "TCPX_GPUDIRECTTCPX_TX_IRQ_BINDINGS %s", env_str);
      parseCoreRanges(env_str, &global.tx_irq_bindings);
    }
    {
      char *env_str = TCPX_GET_ENV("RX_IRQ_BINDINGS");
      INFO(TCPX_ENV, "TCPX_GPUDIRECTTCPX_RX_IRQ_BINDINGS %s", env_str);
      parseCoreRanges(env_str, &global.rx_irq_bindings);
    }
    {
      std::string env_string;
      char *env_str = TCPX_GET_ENV("SCHED_ALG");

      if (!env_str) {
        env_string = std::string("RR");
        INFO(TCPX_ENV, "TPCX_GPUDIRECTTCPX_SCHED_ALG unset. Using RR by default");
      } else {
        env_string = std::string(env_str);
      }

      if (env_string == "RR") {
        kSchedAlg = TCPX_FLOWMAPPER_SCHED_ALG_RR;
        INFO(TCPX_ENV, "TCPX_GPUDIRECTTCPX_SCHED_ALG RR");
      } else if (env_string == "KATY") {
        kSchedAlg = TCPX_FLOWMAPPER_SCHED_ALG_KATY;
        INFO(TCPX_ENV, "TCPX_GPUDIRECTTCPX_SCHED_ALG KATY");
      } else {
        kSchedAlg = TCPX_FLOWMAPPER_SCHED_ALG_RR;
        INFO(TCPX_ENV, "invalid TCPX_GPUDIRECTTCPX_SCHED_ALG %s."
             " Using RR by default", env_string.c_str());
      }
    }
  }

  if (kReportLifecycle) {
    INFO(TCPX_INIT | TCPX_NET,
        "NET/" PRODUCT_NAME " registering with receive_datapath_manager.");
    global.application_registry_client =
        std::make_unique<ApplicationRegistryClient>(kUnixClientPrefix);
    auto status = global.application_registry_client->Init();
    if (!status.ok()) {
      WARN("NET/" PRODUCT_NAME
          " register failed against receive_datapath_manager, %s",
          status.ToString().c_str());
      return tcpxInternalError;
    }
  }
  if (kExportStatsToFile) {
    char* env = getenv("NCCL_GPUDIRECTTCPX_TELEMETRY_GARBAGE_COLLECTOR_INDEX");
    int cpu_core = -1;
    if (env) {
      cpu_core = std::atoi(env);
    } else {
      cpu_core = 172;
    }
    std::thread cleaner(cleanTelemetryLogFiles, cpu_core);
    cleaner.detach();
  }

  INFO(TCPX_INIT | TCPX_NET, "NET/" PRODUCT_NAME " plugin initialized");
  INFO(TCPX_INIT | TCPX_NET | TCPX_ENV, "NET/" PRODUCT_NAME " ver. " TCPX_VERSION_STRING);
  return tcpxSuccess;
}

tcpxResult_t tcpxDevices(int* ndev) {
  pthread_mutex_lock(&kTcpxGPUDirectTCPXLock);
  *ndev = kTcpxNetIfs;
  pthread_mutex_unlock(&kTcpxGPUDirectTCPXLock);
  return tcpxSuccess;
}

static tcpxResult_t tcpxGetSpeed(char* devName, int* speed) {
  *speed = 0;
  char speedPath[PATH_MAX];
  snprintf(speedPath, PATH_MAX, "/sys/class/net/%s/speed", devName);
  int fd = open(speedPath, O_RDONLY);
  if (fd != -1) {
    char speedStr[] = "        ";
    if (read(fd, speedStr, sizeof(speedStr) - 1) > 0) {
      *speed = strtol(speedStr, nullptr, 0);
    }
    close(fd);
  }
  if (*speed <= 0) {
    INFO(TCPX_NET, "Could not get speed from %s. Defaulting to 10 Gbps.",
         speedPath);
    *speed = 10000;
  }
  return tcpxSuccess;
}

tcpxResult_t tcpxGetProperties(int dev, tcpxNetProperties_t* props) {
  props->name = kTcpxSocketDevs[dev].dev_name;
  props->pciPath = kTcpxSocketDevs[dev].pci_path;
  props->guid = dev;
#ifdef HOST_PTR_ONLY
  props->ptrSupport = TCPX_PTR_HOST;
#else
  props->ptrSupport = TCPX_PTR_HOST | TCPX_PTR_CUDA;
#endif
  TCPXCHECK(tcpxGetSpeed(props->name, &props->speed));
  props->port = 0;
  props->maxComms = 65536;
  props->latency = 0;
  props->maxRecvs = 1;
  props->netDeviceType = DEV_UNPACK;
  props->netDeviceVersion = TCPX_UNPACK_VERSION;
  INFO(TCPX_INIT, "props: netDeviceType %d, netDeviceVersion %d", props->netDeviceType, props->netDeviceVersion);

  return tcpxSuccess;
}

tcpxResult_t tcpxListen(int dev, void* oHandle,
                                   void** listenComm) {
  struct tcpxConnectionSetup *conn = (struct tcpxConnectionSetup*) global.connection_setup;
  return conn->listen(conn->ctx, dev, oHandle, listenComm);
}

tcpxResult_t tcpxGetDeviceHandle(void* comm, devNetDeviceHandle* handle);

tcpxResult_t tcpxConnect_v5(int dev, void* oHandle,
                                  void** sendComm, devNetDeviceHandle** sendDevHandle) {
  struct tcpxConnectionSetup *conn = (struct tcpxConnectionSetup*) global.connection_setup;
  TCPXCHECK(conn->connect(conn->ctx, dev, oHandle, sendComm));
  return tcpxSuccess;
}

tcpxResult_t tcpxAccept_v5(void* listenComm, void** recvComm, devNetDeviceHandle** recvDevHandle) {
  struct tcpxConnectionSetup *conn = (struct tcpxConnectionSetup*) global.connection_setup;
  TCPXCHECK(conn->accept(conn->ctx, listenComm, recvComm));
  if (*recvComm && recvDevHandle)  {
    // connected and asking for a dev handle
    TCPXCHECK(tcpxGetDeviceHandle(*recvComm, *recvDevHandle));
  }
  return tcpxSuccess;
}

tcpxResult_t tcpxRegMr(void* ocomm, void* data, int size, int type,
                                void** mhandle) {
  // INFO(TCPX_NET, "tcpxRegMr, data %p, %d, type %s", data, size, type == TCPX_PTR_CUDA ? "cuda" : type == TCPX_PTR_HOST ? "host" : "unknown");

  struct tcpxComm* comm = static_cast<tcpxComm*>(ocomm);
  if (comm == nullptr) {
    WARN("NET/" PRODUCT_NAME ": regMr called with NULL communicator.");
    return tcpxInternalError;
  }

  struct tcpxMemHandle* memHandle;
  TCPXCHECK(tcpxMemHandleNew(&memHandle));
  memHandle->mem_type = type;

  switch (type) {
    case TCPX_PTR_HOST: {
      memHandle->uptr = data;
      memHandle->ptr = data;
      break;
    }
    case TCPX_PTR_CUDA: {
      if (kUseDmaBuf) {
        if ((uint64_t) data % PAGE_SIZE != 0) {
          WARN("data not aligned: %p vs 0x%012lu", data, PAGE_SIZE);
          return tcpxInternalError;
        }
        char* nic_pci_addr = strrchr(kTcpxSocketDevs[comm->dev].pci_path, '/') + 1;
        void* gpu;
        TCPXCHECK(gpu_current_dev(global.gpus, &gpu));
        TCPXCHECK(gpu_tx_reg_mr(gpu, &(memHandle->gpu_tx), &(memHandle->gpu_mem_fd),
            nic_pci_addr, data, size));
        if (memHandle->gpu_mem_fd < 0) {
          WARN("get_gpumem_dmabuf_pages_fd() failed!");
          return tcpxInternalError;
        }
      } else {
        WARN("p2pdma api won't work with only RegMr, due to alignment issue");
        return tcpxInternalError;
      }

      memHandle->uptr = data;
      memHandle->ptr = data;
      break;
    }
    default: {
      WARN("unknown mem type %d", type);
      return tcpxInternalError;
    }
  }

  *mhandle = memHandle;
  return tcpxSuccess;
}

tcpxResult_t tcpxDeregMr(void* ocomm, void* mhandle) {
  struct tcpxMemHandle* memHandle = static_cast<tcpxMemHandle*>(mhandle);

  if (memHandle == nullptr) return tcpxSuccess;

  int type = memHandle->mem_type;
  switch (type) {
    case TCPX_PTR_HOST: {
      break;
    }
    case TCPX_PTR_CUDA: {
      SYSCHECK(close(memHandle->gpu_mem_fd), "close gpu_mem_fd");
      if (kUseDmaBuf) {
        TCPXCHECK(gpu_tx_dereg_mr(memHandle->gpu, memHandle->gpu_tx));
      } else {
        WARN("p2pdma api shouldn't call DeregMr, due to alignment issue");
        return tcpxInternalError;
      }
      break;
    }
    default: {
      WARN("unknown mem type %d", type);
      return tcpxInternalError;
    }
  }

  free(mhandle);
  return tcpxSuccess;
}

void waitConnect(struct tcpxComm* comm) {
  while (comm->conn_state != CONN_OK) {
    // pthread_yield();
    sched_yield();
  }
}

static tcpxResult_t tcpxGetRequest(struct tcpxComm* comm,
                                            int op, void* data, int size,
                                            struct tcpxMemHandle* mhandle,
                                            struct tcpxRequest** req) {
  if (mhandle == nullptr) {
    WARN("NET/" PRODUCT_NAME " : mhandle is null");
    return tcpxInternalError;
  }
  if (!comm->rq.has_free()) {
    WARN("NET/" PRODUCT_NAME " : unable to allocate requests");
    return tcpxInternalError;
  }
  struct tcpxRequest* r = comm->rq.next_free();
  r->op = op;
  r->mem_type = mhandle->mem_type;
  r->next_sock_id = -1;
  r->next_size = 0;
  r->data = data;
  r->offset = 0;
  r->size = size;
  r->gpu_mem_fd = mhandle->gpu_mem_fd;
  r->gpu_mem_off = (char*)data - (char*)mhandle->ptr;
  if (op == TCPX_SOCKET_SEND)
    r->size_pending = size;
  else
    r->size_pending = -1;
  r->comm = comm;

  r->unpack_slot.cnt = nullptr;  // important marker

  *req = r;
  comm->rq.enqueue();

  return tcpxSuccess;
}

tcpxResult_t tcpxIsend_v5(void* sendComm, void* data, int size,
                                   int tag, void* mhandle, void** request) {
  struct tcpxComm* comm =
      static_cast<struct tcpxComm*>(sendComm);
  struct tcpxMemHandle* memhandle = static_cast<tcpxMemHandle*>(mhandle);

  if (comm->conn_state == CONN_FAILED) {
    return tcpxInternalError;
  }
  if (comm->conn_state != CONN_OK) {
    if (!kSpinWaitConnect) {
      *request = NULL;
      return tcpxSuccess;
    } else {
      waitConnect(comm); // else race on p2p
    }
  }
  TCPXCHECK(tcpxGetRequest(comm, TCPX_SOCKET_SEND, data, size,
                                    memhandle,
                                    (struct tcpxRequest**)request));
  return tcpxSuccess;
}

tcpxResult_t tcpxIrecv_v5(void* recvComm, int n, void** data,
                                   int* sizes, int* tags, void** mhandles,
                                   void** request) {
  struct tcpxComm* comm =
      static_cast<struct tcpxComm*>(recvComm);
  if (n != 1) return tcpxInternalError;
  struct tcpxMemHandle *memhandle = static_cast<tcpxMemHandle*>(mhandles[0]);

  if (comm->conn_state == CONN_FAILED) {
    return tcpxInternalError;
  }
  if (comm->conn_state != CONN_OK) {
    if (!kSpinWaitConnect) {
      *request = NULL;
      return tcpxSuccess;
    } else {
      waitConnect(comm); // else race on p2p
    }
  }
  TCPXCHECK(tcpxGetRequest(comm, TCPX_SOCKET_RECV, data[0], sizes[0],
                                    memhandle,
                                    (struct tcpxRequest**)request));
  return tcpxSuccess;
}

tcpxResult_t tcpxIflush_v5(void* recvComm, int n, void** data,
                                          int* sizes, void** mhandle,
                                          void** request) {
  // Iflush unused for now
  if (n != 1) return tcpxInternalError;
  struct tcpxRequest *r = static_cast<tcpxRequest*>(request[0]);
  sizes[0] = r->size;
  return tcpxSuccess;
}

#define CTRL_DONE(r) ((r)->next_sock_id >= 0)
#define RESET_CTRL(r) ((r)->next_sock_id = -1)

#define REQUEST_DONE(r) \
  (((r)->size == 0 && CTRL_DONE(r)) || ((r)->size && (r)->size_pending == 0))
#define REQUEST_INACTIVE(r) ((r)->size == (r)->offset)

#ifndef BUFFERED_CTRL
static tcpxResult_t tcpxProcessCtrl(struct tcpxComm* comm,
                                    struct tcpxRequest* r,
                                    struct tcpxCtrl* ctrl) {
  void* ctrl_pipe = ctrlPipe(comm, r->op);
  int s = 0;
  TCPXCHECK(socketSpin(r->op, comm->ctrl_fd, r->mem_type, ctrl_pipe, ctrl,
                       sizeof *ctrl, &s));
  if (s == 0) return tcpxSuccess;
  if (s < sizeof *ctrl) {
    TCPXCHECK(socketSpin(r->op, comm->ctrl_fd, r->mem_type, ctrl_pipe, ctrl,
                         sizeof *ctrl, &s));
  }
  if (s) {
    // save control information to request
    r->next_sock_id = ctrl->index;
    r->next_size = ctrl->size;
#ifndef HOST_PTR_ONLY
    // if (r->op == TCPX_SOCKET_SEND) {
    //   r->pipe = &comm->sender_pipes[ctrl->index];
    // } else {
    //   r->pipe = &comm->receiver_pipes[ctrl->index];
    // }
#endif
    if (r->size_pending < 0) {
      r->size_pending = r->size = ctrl->total;
    }
  }
  return tcpxSuccess;
}
#endif

static tcpxResult_t tcpxCtrlRecv(struct tcpxComm* comm,
                                 struct tcpxRequest* r,
                                 struct tcpxCtrl* ctrl) {
#ifdef BUFFERED_CTRL
  TCPXCHECK(comm->ctrl_recv.refill());
  if (comm->ctrl_recv.empty()) return tcpxSuccess;
  TCPXCHECK(comm->ctrl_recv.recv(ctrl, sizeof *ctrl));

  // save control information to request
  r->next_sock_id = ctrl->index;
  r->next_size = ctrl->size;
  if (r->size_pending < 0) {
    r->size_pending = r->size = ctrl->total;
  }

  return tcpxSuccess;
#else
  return tcpxProcessCtrl(comm, r, ctrl);
#endif
}

static inline tcpxResult_t tcpxCtrlSendSync(struct tcpxComm* comm) {
#ifdef BUFFERED_CTRL
  TCPXCHECK(comm->ctrl_send.sync());
#endif
  return tcpxSuccess;
}

static inline tcpxResult_t tcpxCtrlSend(struct tcpxComm* comm,
                                        struct tcpxRequest* r,
                                        struct tcpxCtrl* ctrl) {
#ifdef BUFFERED_CTRL
  TCPXCHECK(comm->ctrl_send.send(ctrl, sizeof *ctrl));
  r->next_sock_id = ctrl->index;
  r->next_size = ctrl->size;

  return tcpxSuccess;
#else
  return tcpxProcessCtrl(comm, r, ctrl);
#endif
}

static void enqueueTask(struct tcpxComm* comm,
                        struct tcpxRequest* r) {
  int sockId = r->next_sock_id;
  RESET_CTRL(r);
  int sz = r->next_size;
  struct tcpxTask* t = comm->fd_data[sockId].tasks.next_free();
  t->op = r->op;
  t->data = reinterpret_cast<char*>(r->data) + r->offset;
  t->r = r;
  t->result = tcpxSuccess;
  t->page_off = r->offset;
  t->offset = 0;
  t->request_offset = r->offset;
  t->size = sz;
  t->tx_count = 0;
  t->tx_i = 0;
  t->pipe->cnt_cache = 0;
  if (comm->passive) {
    struct unpackSlot *u = &(r->unpack_slot);
    u->fds[sockId] = comm->fd_data[sockId].fd;
    t->pipe->pgtoks = &(u->pgtoks[sockId * TCPX_UNPACK_MAX_SLICE_PAGES]);
    t->pipe->pgtok_cnt = &(u->pgtok_cnts[sockId]);
    if (t->pipe->pgtok_cnt)
      *(t->pipe->pgtok_cnt) = 0;
  }
  t->pipe->flow_str = comm->fd_data[sockId].flow_str;
  tcpxTimeoutDetectionReset(t->timeout);
  comm->fd_data[sockId].tasks.enqueue();


  r->offset += sz;
  if (REQUEST_INACTIVE(r)) {
    comm->rq.finish_active();
  }

  // notify thread
  // int tid = sockId * comm->nThreads / comm->nSocks;
  int tid = sockId % comm->num_threads;
  struct tcpxThreadResources* res = comm->thread_resource + tid;
  if (res->comm == nullptr) {
    res->id = tid;
    res->next = 0;
    res->comm = comm;
    res->state = start;
    res->user_buffer_count = 0;
    res->stride = comm->stride;
    pthread_mutex_init(&res->thread_lock, nullptr);
    pthread_cond_init(&res->thread_cond, nullptr);
    pthread_create(comm->helper_thread + tid, nullptr, persistentSocketThread,
                   res);
  } else {
    if (kEnableSpin) {
      ++res->next;
    } else {
      pthread_mutex_lock(&res->thread_lock);
      ++res->next;
      pthread_cond_signal(&res->thread_cond);
      pthread_mutex_unlock(&res->thread_lock);
    }
  }
}

static tcpxResult_t tcpxCommProgress(struct tcpxComm* comm) {

  if (unlikely(comm->flow_mapper.get() == nullptr)) {
    switch (kSchedAlg) {
      case TCPX_FLOWMAPPER_SCHED_ALG_RR:
        comm->flow_mapper = std::make_unique<FlowMapperRR>();
        break;
      case TCPX_FLOWMAPPER_SCHED_ALG_KATY:
        comm->flow_mapper = std::make_unique<FlowMapperKaty>();
        break;
      default:
        comm->flow_mapper = std::make_unique<FlowMapperRR>();
    }
  }

  comm->flow_mapper->reset();

  // no more requests
  if (comm->rq.empty()) return tcpxSuccess;

  for (int i = 0; i < comm->num_socks; ++i) {
    int idx = comm->end_fd_idx - i;
    if (idx < 0) idx += comm->num_socks;
    tcpxTaskQueue* tasks =
        &(comm->fd_data[comm->begin_fd_idx + idx].tasks);
    while (tasks->has_inactive()) {
      tcpxTask* t = tasks->next_inactive();
      t->r->size_pending -= t->size;
      if (t->op == TCPX_SOCKET_RECV && t->size > 0) {
        char* dst = ((char*)t->r->unpack_slot.mem) + t->r->unpack_slot.cnt_cache * sizeof(union loadMeta);
        memcpy(dst,
               t->pipe->scatter_list, sizeof(union loadMeta) * t->pipe->cnt_cache);
        // INFO(TCPX_NET,
        //      "memcpy(((char*)t->r->unpack_slot.mem %p) + t->r->unpack_slot.cnt_cache %lu * "
        //      "sizeof(union LoadMeta) %zu = %p, t->scatter_list %p, "
        //      "sizeof(union LoadMeta) %zu* t->pipe->cnt_cache % lu = %zu)",
        //      t->r->unpack_slot.mem, t->r->unpack_slot.cnt_cache, sizeof(union loadMeta), dst,
        //      t->scatter_list, sizeof(union loadMeta), t->pipe->cnt_cache,
        //      sizeof(union loadMeta) * t->pipe->cnt_cache);
        t->r->unpack_slot.cnt_cache += t->pipe->cnt_cache;
        // INFO(TCPX_NET,
        //      "t %p r %p moving %lu meta (%zu B) to mapped memory, total cnt "
        //      "%lu, t->size %zu, t->op %s",
        //      t, t->r, t->pipe->cnt_cache, t->pipe->cnt_cache * sizeof(union loadMeta),
        //      t->r->unpack_slot.cnt_cache, t->size,
        //      t->op == TCPX_SOCKET_SEND ? "send" : "recv");
        t->pipe->cnt_cache = 0;
      }
      tasks->dequeue();  // inactive -> free
      if (kForceAck && t->op == TCPX_SOCKET_RECV && tasks->empty()) {
        setSockQuickAck(comm->fd_data[comm->begin_fd_idx + idx].fd);
      }
    }
    if (tasks->has_free()) {
      // socket fd_idx has room for more tasks
      comm->flow_mapper->scheduleFlow(idx, MAX_TASKS - tasks->num_free());
    }
  }

  if (comm->rq.has_posted()) {
    if (kRecvSync) {
      tcpxRequest* ar = comm->rq.next_posted();
      uint32_t idx = comm->rq.get_posted_idx();
      if (ar->op == TCPX_SOCKET_RECV) {
        TCPXCHECK(socketSend(comm->ctrl_fd, &idx, sizeof idx));
        comm->rq.finish_posted();
      } else {
        uint32_t peer_idx;
        tcpxResult_t ret;
        ret = socketRecv(comm->ctrl_fd, &peer_idx, sizeof peer_idx, 0);
        if (ret != tcpxInProgress) {
          TCPXCHECK(ret);
          if (peer_idx != idx) {
            WARN("Recv sync mismatch, idx %u, peer %u", idx, peer_idx);
          }
          comm->rq.finish_posted();
        }
      }
    } else {
      comm->rq.finish_posted();
    }
  }

  // no active requests or no socket has room for new tasks
  if (!comm->rq.has_active() || !comm->flow_mapper->hasFlow()) return tcpxSuccess;

  tcpxRequest* ar = comm->rq.next_active();

  if (ar->op == TCPX_SOCKET_SEND) {
    // small enough to send via control socket
    if (ar->size <= kInlineThreshold) {
      tcpxCtrl ctrl = {CTRL_INLINE,
                       0,
                       static_cast<uint32_t>(ar->size),
                       0,
                       static_cast<uint32_t>(ar->size)};
      TCPXCHECK(tcpxCtrlSend(comm, ar, &ctrl));
      TCPXCHECK(tcpxCtrlSendSync(comm));
      if (CTRL_DONE(ar)) {
        if (ar->size > 0) {
          int off = 0;
          // send data through control socket
          TCPXCHECK(socketSpin(TCPX_SOCKET_SEND, comm->ctrl_fd,
                               ar->data, ar->size, &off));
          ar->offset = ar->size;
          ar->size_pending = 0;
        }
        // comm->rq.mark_inactive();
        comm->rq.finish_active();
        // comm->rq.finish_transmitting();
      }

      return tcpxSuccess;
    }

    // there are pending requests and we have available sockets
    int socket_idx = -1;
    while (ar->offset < ar->size && (socket_idx = comm->flow_mapper->pickFlow()) != -1) {
      uint32_t send_size = std::min(kDynamicChunkSize, ar->size - ar->offset);
      tcpxCtrl ctrl = {CTRL_NORMAL,
                       static_cast<uint16_t>(socket_idx),
                       send_size,
                       static_cast<uint32_t>(ar->offset),
                       static_cast<uint32_t>(ar->size)};
      TCPXCHECK(tcpxCtrlSend(comm, ar, &ctrl));
      if (!CTRL_DONE(ar)) break;

      enqueueTask(comm, ar);
      comm->end_fd_idx = socket_idx;
    }
    TCPXCHECK(tcpxCtrlSendSync(comm));
  } else {
    do {
      tcpxCtrl ctrl;
      if (!CTRL_DONE(ar)) {
        TCPXCHECK(tcpxCtrlRecv(comm, ar, &ctrl));
        uint64_t nanos;
        if (kSlownessSwitch[RX_CTRL] && tcpxTimeoutDetectionShouldWarn(&comm->ctrl_timeout, &nanos)) {
          if (kSlownessReport[RX_CTRL]) {
            WARN("%p:%p, nic %d, %s, %s %s ctrl timeout cnt %lu, nanos %lu", ar,
                 comm, comm->dev, kTcpxSocketDevs[comm->dev].dev_name,
                 comm->ctrl_flow_str, comm->passive ? "rx" : "tx",
                 comm->ctrl_timeout.same_count, nanos);
          }
        }
        if (!CTRL_DONE(ar)) break;
        if (kSlownessSwitch[RX_CTRL])
          tcpxTimeoutDetectionReset(&comm->ctrl_timeout);

        if (ctrl.type == CTRL_INLINE) {
          // use token to free, shouldn't need this
          struct tcpxNetDeviceQueue* h =
              static_cast<struct tcpxNetDeviceQueue*>(
                  ar->comm->socket_direct_handle);
          TCPXCHECK(tcpxNetDeviceQueueNextFree(h, &ar->unpack_slot));  // skip one
          if (!ar->unpack_slot.active) {
            WARN("no more socket direct task queue slot, head %d tail %d",
                 h->head, h->tail);
            break;
          }
          uint64_t q_idx = ar->unpack_slot.idx;
          h->meta->cnt[q_idx] = 0;
          h->record.fds_cnts[q_idx] = 0;

          if (ar->size) {
            WARN("ar->size through control socket shouldn't happen for GPUDirectTCPX");
#ifdef BUFFERED_CTRL
            ar->offset = comm->ctrl_recv.brecv(ar->data, ar->size);
#endif
            TCPXCHECK(socketSpin(TCPX_SOCKET_RECV, comm->ctrl_fd,
                                 ar->data, ar->size, &ar->offset));
            ar->size_pending = 0;
          }
          // comm->rq.mark_inactive();
          comm->rq.finish_active();
          // comm->rq.finish_transmitting();
          break;
        }
      }

      bool enqueue_meta = ar->op == TCPX_SOCKET_RECV;
      // enqueue_meta = enqueue_meta && ar->size > 0;
      enqueue_meta = enqueue_meta && ar->unpack_slot.cnt == nullptr;
      if (enqueue_meta) {
        struct tcpxNetDeviceQueue* h =
            static_cast<struct tcpxNetDeviceQueue*>(
                ar->comm->socket_direct_handle);
        TCPXCHECK(tcpxNetDeviceQueueNextFree(h, &ar->unpack_slot));
        if (!ar->unpack_slot.active) {
          WARN("no more socket direct task queue slot, head %d tail %d", h->head, h->tail);
          break;
        }

        *(ar->unpack_slot.cnt) = 0;
        ar->unpack_slot.cnt_cache = 0;
        *(ar->unpack_slot.fds_cnt) = comm->num_socks;
        memset(ar->unpack_slot.pgtok_cnts, 0, MAX_SOCKETS * sizeof(size_t));
      }
      struct tcpxTaskQueue* tasks =
          &(comm->fd_data[ar->next_sock_id].tasks);
      if (!tasks->has_free()) {
        WARN("No free space for recv task");
        break;
      }
      enqueueTask(comm, ar);
    } while (ar->offset < ar->size);
  }

  return tcpxSuccess;
}

// Called by netSendProxy and netRecvProxy from the proxy thread
tcpxResult_t tcpxTest(void* request, int* done, int* size) {

  *done = 0;
  struct tcpxRequest* r = static_cast<struct tcpxRequest*>(request);
  if (r == nullptr) {
    WARN("NET/" PRODUCT_NAME " : test called with NULL request");
    return tcpxInternalError;
  }
  TCPXCHECK(tcpxCommProgress(r->comm));

  // if (r->comm->rq.has_inactive()) {
  if (r->comm->rq.has_transmitting()) {
    tcpxRequest* ni = r->comm->rq.next_transmitting();

    if (r != ni) {
      WARN("NET/" PRODUCT_NAME " : test called with invalid request, send %d, r %p, ni %p", r->op == TCPX_SOCKET_SEND, r, ni);
      return tcpxInternalError;
    }

    if (REQUEST_DONE(r)) {
      // This block of code must be used with new CUcontexts
      // absl::string_view oopp = r->op == TCPX_SOCKET_SEND ? "send" : "recv";
      // size_t p_size = std::min(r->size, 32);
      // if (r->mem_type == TCPX_PTR_HOST) {
      //   printBytes(absl::StrFormat("%s host %p data %p", oopp, r, r->data), (char*)
      //   r->data, p_size);
      // } else {
      //   CUDAASSERT(cuCtxPushCurrent(global.ctx[0]));
      //   void* p;
      //   CUDAASSERT(cuMemAllocHost(&p, r->size));
      //   CUDAASSERT(cuMemcpyDtoH(p, (CUdeviceptr)r->data, r->size));
      //   printBytes(absl::StrFormat("%s cuda %p data %p", oopp, r, r->data), (char*) p,
      //   p_size); CUDAASSERT(cuMemFreeHost(p)); CUcontext ctx;
      //   CUDAASSERT(cuCtxPopCurrent(&ctx));
      // }

      if (r->op == TCPX_SOCKET_RECV) {

        if (r->size) {
          if (r->unpack_slot.cnt_cache > TCPX_UNPACK_MAX_SLICE_PAGES) {
            WARN("request too many pages %d, failstop", r->unpack_slot.cnt_cache);
            exit(1);
          }
          *(r->unpack_slot.cnt) = r->unpack_slot.cnt_cache;

          std::atomic_thread_fence(std::memory_order_release);
          _mm_sfence();

          // r->comm->rq.dequeue();
        } else {
          *(r->unpack_slot.cnt) = 0;
        }

      }

      r->comm->rq.finish_transmitting();
      if (r->op == TCPX_SOCKET_SEND) {
        r->comm->rq.dequeue(); // no IsendConsumed
      }
      *done = 1;
    }
  }
  return tcpxSuccess;
}

tcpxResult_t tcpxClose(void* oComm) {
  struct tcpxComm* comm =
      static_cast<struct tcpxComm*>(oComm);
  if (comm) {
    if (comm->socket_direct_handle) {
      // To free the pages, supposedly the dev side is done at this point.
      struct tcpxNetDeviceQueue* h =
          static_cast<struct tcpxNetDeviceQueue*>(
              comm->socket_direct_handle);
      int head = h->head;
      int tail = h->tail;
      INFO(TCPX_NET, "head %d tail %d", head, tail);
      if (head != tail) {
        WARN("head %d tail %d some pages not yet freed?", head, tail);
      }
    }

    for (int i = 0; i < comm->num_threads; i++) {
      struct tcpxThreadResources* res = comm->thread_resource + i;
      if (comm->helper_thread[i]) {
        pthread_mutex_lock(&res->thread_lock);
        res->state = stop;
        pthread_cond_signal(&res->thread_cond);
        pthread_mutex_unlock(&res->thread_lock);
        pthread_join(comm->helper_thread[i], nullptr);
      }
    }
    if (comm->ctrl_fd != -1) close(comm->ctrl_fd);
    uint64_t total = 0;
    for (int i = 0; i < comm->num_socks; i++) {
      if (comm->fd_data[i].fd != -1) {
        if (comm->passive && kFlowSteeringStrategy == UNIX_CLIENT) {
          DeleteFlowSteerRule(comm->fd_data[i].fd, comm->gpu);
        }
        close(comm->fd_data[i].fd);
      }
      if (comm->fd_data[i].stat_hi) {
        INFO(TCPX_NET, "Socket %i total bytes: %lu, passive = %d", i,
             comm->fd_data[i].stat_hi, (int)comm->passive);
        total += comm->fd_data[i].stat_hi;
      }
    }
    INFO(TCPX_NET, "All bytes: %lu", total);
    if (comm->thread_resource->user_buffer_count > 0) {
      WARN("copied %d times to user buffer",
           comm->thread_resource->user_buffer_count);
    }

    if (kLogStatsToStdout) {
      for (int i = 0; i < comm->num_socks; i++) {
        struct tcpxFdData* fd_data = comm->fd_data + i;
        if(!isInactive(fd_data->stats)) {
          printf("per_flow_stats[%lu:%s] = %s\n", fd_data->stats.flow_id,
            fd_data->flow_str, TCPX_SOCKET_STATS_TOSTRING(comm, i));
        }
      }
    }
    tcpxCommFree(comm);
  }
  return tcpxSuccess;
}

tcpxResult_t tcpxCloseListen(void* oComm) {
  struct tcpxListenComm* lComm = (struct tcpxListenComm*)oComm;
  if (lComm) {
    if (lComm->host_fd != -1) close(lComm->host_fd);
    for (int i = 0; i < MAX_SOCKETS; i++) {
      if (lComm->cuda_fd[i] != -1) close(lComm->cuda_fd[i]);
    }
    if (lComm->cuda_fd[0] != -1) {
    }
    free(lComm);
  }
  return tcpxSuccess;
}

tcpxResult_t tcpxGetDeviceHandle(void* ocomm, devNetDeviceHandle* handle) {
  struct tcpxComm* comm = static_cast<tcpxComm*>(ocomm);
  INFO(TCPX_INIT, "comm %p, GetDeviceHandle, passive %d", ocomm, comm->passive);

  TCPXCHECK(tcpxNetDeviceQueueNew(comm->gpu, comm->passive, &comm->socket_direct_handle, &comm->socket_direct_dev_handle));

  if (DEV_UNPACK_VERSION != TCPX_UNPACK_VERSION) {
    WARN("compiled with unmatching unpack versions: dev %d, tcpx %d", DEV_UNPACK_VERSION, TCPX_UNPACK_VERSION);
    return tcpxInternalError;
  }

  handle->netDeviceType = DEV_UNPACK;
  handle->netDeviceVersion = TCPX_UNPACK_VERSION;   // this is plugin version
  handle->handle = comm->socket_direct_dev_handle;
  handle->size = sizeof(struct unpackNetDeviceHandle);
  handle->needsProxyProgress = 1;

  INFO(TCPX_INIT, "comm %p, GetDeviceHandle %p", ocomm, handle);
  return tcpxSuccess;
}

tcpxResult_t tcpxGetDeviceMr(void* comm, void* mhandle, void** dptr_mhandle) {
  return tcpxSuccess;
}

tcpxResult_t tcpxIrecvConsumed(void* ocomm, int n, void* request) {
  // INFO(TCPX_NET, "NET/" PRODUCT_NAME " : irecvConsumed %p", request);
  if (request == nullptr) {
    WARN("NET/" PRODUCT_NAME " : irecvConsumed with null request");
    return tcpxInternalError;
  }

  if (n != 1) {
    return tcpxInternalError;
  }

  struct tcpxComm* comm = static_cast<tcpxComm*>(ocomm);
  struct tcpxNetDeviceQueue* h =
              static_cast<struct tcpxNetDeviceQueue*>(
                  comm->socket_direct_handle);
  struct tcpxRequest* r = static_cast<struct tcpxRequest*>(request);

  // no send
  if (r->op == TCPX_SOCKET_SEND) {
    WARN("NET/" PRODUCT_NAME " : irecvConsumed called for send request %p", request);
    return tcpxSuccess;
  }
  // skip empty
  if (!r->size) {
    comm->rq.dequeue();
    h->head += 1;
    return tcpxSuccess;
  }
  // shouldn't see no unpack if not empty
  if (!r->unpack_slot.active) {
    WARN("NET/" PRODUCT_NAME " : irecvConsumed called with r %p ->size %d inactive unpack slot %p", r, r->size, &(r->unpack_slot));
    return tcpxInternalError;
  }

  // error: request absent
  if (!comm->rq.has_inactive()) {
    WARN("NET/" PRODUCT_NAME " : irecvConsumed called with %p when no inactive request", request);
    return tcpxInternalError;
  }
  // error: request mismatch
  struct tcpxRequest *ir = comm->rq.next_inactive();
  if (ir != request) {
    WARN("NET/" PRODUCT_NAME " : irecvConsumed called with invalid request %p vs expected %p", ir, request);
    return tcpxInternalError;
  }

  // int q_idx = h->head;
  uint64_t q_idx = ir->unpack_slot.idx;

  // INFO(TCPX_NET, "NET/" PRODUCT_NAME " : irecvConsumed %p, q_idx %d, head %d", request, q_idx, h->head);

  if (h->head == h->tail) {
    WARN("irecvConsumed shouldn't be called when head == tail == %d", h->head);
    return tcpxInternalError;
  }
  if (h->head % DEV_UNPACK_MAX_QUEUE_DEPTH != q_idx) {
    WARN("irecvConsumed unexpected q_idx %d vs head %d", q_idx, h->head);
    return tcpxInternalError; // tcpxSuccess;
  }

  TCPXCHECK(recyclePages(h, q_idx));

  comm->rq.dequeue();

  h->head += 1;
  return tcpxSuccess;
}
