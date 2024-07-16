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

#ifndef NET_GPUDIRECTTCPX_COMMON_H_
#define NET_GPUDIRECTTCPX_COMMON_H_

#include <algorithm>
#include <memory>
#include <pthread.h>
#include <unordered_map>
#include <thread>

#include "adapter1.h"
#include "alloc1.h"
#include "checks1.h"
#include "ctrl_sock.h"
#include "flags.h"
#include "flow_mapper.h"
#include "gpu/cuda_wrapper.h"
#include "macro.h"
#include "rx_buf_mgr_client/application_registry_client.h"
#include "stats/monitoring.h"
#include "stats/stats_buffer.h"
#include "socket_utils.h"
#include "work_queue.h"

/***** global vars start *****/

struct tcpxDev {
  union socketAddress addr;
  char dev_name[MAX_IF_NAME_SIZE];
  char* pci_path;
};

#define MAX_RANGES 8
struct tcpxBindings {
  // int n_nics = kTcpxNetIfs
  int n_ranges[MAX_IFS];
  int lo[MAX_IFS][MAX_RANGES];
  int hi[MAX_IFS][MAX_RANGES];
};
void getNodeCpu(struct tcpxBindings *bindings, int i, int node_idx);
void parseCoreRanges(char *env_str, struct tcpxBindings *b);
#define MAX_CPU_CNT 256
#define MAX_NAPI_ID_CNT 64  // per NIC
struct tcpxNapiIdRecord {
  pthread_mutex_t mu;
  size_t n_rxqs;
  std::unordered_map<int, size_t> napi_id_cnt;
  size_t napi_id_cnt_counter;
  size_t napi_id_cnt_curr_hi;
};

struct tcpxGlobal {
  void* gpus;

  void* connection_setup;

  struct tcpxBindings tx_bindings, rx_bindings;
  struct tcpxBindings tx_irq_bindings, rx_irq_bindings;

  struct tcpxNapiIdRecord rxq_record[MAX_IFS];

  std::unique_ptr<ApplicationRegistryClient> application_registry_client;
};
extern tcpxGlobal global;

extern int kTcpxNetIfs;
extern struct tcpxDev kTcpxCtrlDev;
extern struct tcpxDev kTcpxSocketDevs[MAX_IFS];
extern pthread_mutex_t kTcpxGPUDirectTCPXLock;

/***** global vars end *****/

/*** to NCCL ***/

struct tcpxMemHandle {
  void* uptr;
  void* ptr;
  int mem_type;
  int gpu_mem_fd;
  // int dma_buf_fd;
  void* gpu;
  void* gpu_tx;
};
tcpxResult_t tcpxMemHandleNew(struct tcpxMemHandle** mhandle);

struct tcpxHandle {
  union socketAddress connect_addr;
  int port_start, port_count;
  int num_socks;
  int num_threads;
  bool redirect_ctrl;
  union socketAddress ctrl_addr;

  void* connect_args;
};
char* tcpxHandleToString(struct tcpxHandle* h, char* buf, int len);

struct tcpxListenComm {
  int host_fd;
  int cuda_fd[MAX_SOCKETS];
  int cuda_port[MAX_SOCKETS];
  int num_cuda_fds;
  int dev;
  void* gpu;
  int num_socks;
  int num_threads;

  void* accept_args;
};
tcpxResult_t tcpxNewListenComm(struct tcpxListenComm** comm, int dev);

struct tcpxCtrl {
  uint16_t type;
  uint16_t index;
  uint32_t size;
  uint32_t offset;
  uint32_t total;
} __attribute__((__packed__));

enum ThreadState { start, stop };
enum CtrlType {
  CTRL_NORMAL = 0,
  CTRL_INLINE = 1,
  CTRL_MAX_TYPE = 2,
};
enum ExporterType {
  EXPORTER_PROFILING_INFO = 0,
  EXPORTER_STATS_INFO = 1,
};
struct tcpxThreadResources {
  int id;  // thread index
  std::atomic_uint next;
  enum ThreadState state;
  struct tcpxComm* comm;
  pthread_mutex_t thread_lock;
  pthread_cond_t thread_cond;

  uint32_t stride;

  // dbg counter
  int user_buffer_count;
};

struct tcpxFdData {
  int fd;
  uint32_t tx_upper;  // TX_ZCOPY
  uint32_t tx_lower;  // TX_ZCOPY
  bool used;
  uint64_t stat_hi;
  uint64_t stat_lo;
  tcpxTaskQueue tasks;
  uint32_t tx_upper_cache;
  uint32_t tx_lower_cache;
  char flow_str[FLOW_STR_LEN];
  struct tcpxTimeoutDetection timeout;
  tcpxSocketStats stats;
};

enum ConnectionState {
  CONN_OK = 0,
  CONN_PENDING = 1,
  CONN_FAILED = 2,
};

struct tcpxComm {
  bool passive;
  std::atomic<ConnectionState> conn_state;
  struct tcpxFdData
      fd_data[MAX_SOCKETS];  // data socket fd and its auxiliary data
  int num_socks;     // total number of socket fds per comm
  int num_threads;   // number of helper threads per comm
  int begin_fd_idx;  // the first enqueued fd idx
  int end_fd_idx;    // the last enqueued fd idx

  int ctrl_fd;                // control socket fd
  char ctrl_flow_str[FLOW_STR_LEN];
  tcpxSocketStats ctrl_stats;
  tcpxRequestQueue rq;  // requests queue
#ifdef BUFFERED_CTRL
#define CTRL_BUFFER_SIZE (sizeof(tcpxCtrl) * 8)
  tcpxBufferedSendSocket<CTRL_BUFFER_SIZE> ctrl_send;
  tcpxBufferedRecvSocket<CTRL_BUFFER_SIZE> ctrl_recv;
#endif
  int dev;
  void* gpu;
  void* socket_direct_handle, *socket_direct_dev_handle;

  // helper threads
  pthread_t helper_thread[MAX_THREADS];
  // auxiliary data with helper threads
  struct tcpxThreadResources thread_resource[MAX_THREADS];
  union socketAddress connect_addr;

  uint32_t stride;

  struct tcpxTimeoutDetection ctrl_timeout;
  struct StatsBuffer statsbuf;

  std::thread exporter_thread;
  std::unique_ptr<FlowMapper> flow_mapper;
};
tcpxResult_t tcpxCommNew(struct tcpxComm** comm, int dev);
void tcpxCommExporter(struct tcpxComm* comm, ExporterType exporter_type);
void tcpxCommFree(struct tcpxComm* comm);

uint64_t generateFlowId(char* flow_str);

#ifdef TCPX_TRACEPOINT
#define TCPX_SOCKET_STATS_TOSTRING(comm, fd_idx)                               \
  (tcpxSocketStatsToString(comm->fd_data[fd_idx].stats,                        \
                           /*passive=*/comm->passive)                          \
       .c_str())
#else
#define TCPX_SOCKET_STATS_TOSTRING(comm, fd_idx) ""
#endif


#endif  // NET_GPUDIRECTTCPX_COMMON_H_
