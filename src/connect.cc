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

#include "connect.h"

#include <asm-generic/socket.h>
#include <atomic>
#include <fcntl.h>
#include <linux/limits.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>

#include "adapter/ret.h"
#include "adapter1.h"
#include "alloc1.h"
#include "checks1.h"
#include "common.h"
#include "cuda_wrapper.h"
#include "flags.h"
#include "socket_utils.h"
#include "rx_rule_client.h"

void setSockZcopy(int fd);
tcpxResult_t tcpxGetPciPath(char* devName, char** pciPath);
uint64_t initFdFlowInfo(struct tcpxComm* comm, bool passive, int tmpFd,
                        int sockIdx, int& ctrl_fd, char* flow_str);

/* redirect control traffic */
struct redirectControlCtx {
  bool active;
  union socketAddress ctrl_addr;
};
inline tcpxResult_t redirect_control_new(struct redirectControlCtx** r, union socketAddress ctrl_addr)  {
  struct redirectControlCtx* _r;
  TCPXCHECK(tcpxCalloc(&_r, 1));
  _r->active = true;
  _r->ctrl_addr = ctrl_addr;
  *r = _r;
  return tcpxSuccess;
}
inline tcpxResult_t redirect_control_free(struct redirectControlCtx* r) {
  if (r) free(r);
  return tcpxSuccess;
}
inline bool redirect_control(struct redirectControlCtx* r, union socketAddress** ctrl_addr) {
  if (!r) return false;

  *ctrl_addr = &r->ctrl_addr;
  return r->active;
}

/* fixed port range connect (with flow steering) */
#define CU_PCI_ADDR_LEN 16  // documentation: 13 + '\0'
#define MAX_GPU_DEVICES 8
struct fixedPortRangeCtx {
  bool active;
  int n_gpus;
  char pci_addr[MAX_GPU_DEVICES][CU_PCI_ADDR_LEN];
  int port_lo[MAX_GPU_DEVICES];
  int port_hi[MAX_GPU_DEVICES];
  int port_mask[MAX_GPU_DEVICES];
  int port_step[MAX_GPU_DEVICES];
  std::atomic<int> port_count[MAX_GPU_DEVICES];
};

tcpxResult_t parsePortMapping(struct fixedPortRangeCtx* info) {
  info->active = false;
  info->n_gpus = 0;
  for (int i = 0; i < MAX_GPU_DEVICES; i++) {
    memset(info->pci_addr[i], 0, CU_PCI_ADDR_LEN);
    info->port_lo[i] = 0;
    info->port_hi[i] = 0;
    info->port_mask[i] = 0;
    info->port_step[i] = 0;
    info->port_count[i] = 0;
  }

  char* port_mapping = TCPX_GET_ENV("PORT_MAPPING");
  if (port_mapping == nullptr || strlen(port_mapping) == 0) return tcpxSuccess;

  char hostname[128];
  int ret = gethostname(hostname, 128);
  if (ret < 0) {
    WARN("gethostname failed %d", ret);
    return tcpxInternalError;
  }
  char* start = strstr(port_mapping, hostname);
  start += strlen(hostname) + 1;
  *strstr(start, "/") = '\0'; // don't need the rest

  char* p = start; // port_mapping;
  while (*p != '\0') {
    char* comma = strstr(p, ",");
    char* dash = strstr(comma + 1, "-");
    char* comma1 = strstr(dash + 1, ",");
    char* comma2 = strstr(comma1 + 1, ",");
    char* semicolon = strstr(comma2 + 1, ";");
    *comma = '\0';
    *dash = '\0';
    *comma1 = '\0';
    *comma2 = '\0';
    *semicolon = '\0';

    char* pci_addr = p;
    char* port_l = comma + 1;
    char* port_h = dash + 1;
    char* port_mask = comma1 + 1;
    char* port_step = comma2 + 1;

    if (strlen(pci_addr) > CU_PCI_ADDR_LEN) {
      WARN("pci_addr '%s' too long", pci_addr);
      return tcpxInternalError;
    }
    int i = info->n_gpus;
    strncpy(info->pci_addr[i], pci_addr, CU_PCI_ADDR_LEN);
    info->port_lo[i] = atoi(port_l);
    info->port_hi[i] = atoi(port_h);
    info->port_mask[i] = atoi(port_mask);
    info->port_step[i] = atoi(port_step);

    p = semicolon + 1;

    info->n_gpus += 1;
  }

  for (int i = 0; i < info->n_gpus; i++) {
    INFO(TCPX_NET, "Dev %d, port range %d - %d, mask %x", i, info->port_lo[i],
         info->port_hi[i], info->port_mask[i]);
  }
  info->active = true;
  return tcpxSuccess;
}

/* program flows on the fly */
// struct connectProgramFlows {
//   bool active;
// };

struct connectionSetupCtx {
  struct redirectControlCtx *redirect_control_ctx;
  struct fixedPortRangeCtx *fixed_port_range_ctx;

  pthread_mutex_t tx_stride_mu;
  uint32_t tx_stride;
  pthread_mutex_t rx_stride_mu;
  uint32_t rx_stride;
};

/***** generic helpers *****/

tcpxResult_t tcpxGetNsockNthread(int dev, int* ns, int* nt) {
  int nSocksPerThread = kNSocksPerThread;  // TCPX_GET_PARAM(NsocksPerThread);
  int nThreads = kNThreads;  // TCPX_GET_PARAM(NThreads);
  if (nThreads > MAX_THREADS) {
    WARN(
        "NET/" PRODUCT_NAME " : TCPX_SOCKET_NTHREADS is greater than the maximum "
        "allowed, setting to %d",
        MAX_THREADS);
    nThreads = MAX_THREADS;
  }
  if (nThreads == -2 || nSocksPerThread == -2) {
    // Auto-detection
    int autoNt = 1, autoNs = 1;
    char vendorPath[PATH_MAX];
    snprintf(vendorPath, PATH_MAX, "/sys/class/net/%s/device/vendor",
             kTcpxSocketDevs[dev].dev_name);
    char* rPath = realpath(vendorPath, nullptr);
    int fd = open(rPath, O_RDONLY);
    free(rPath);
    if (fd == -1) {
      // Could not find device vendor. This is handled silently so
      // we don't want to print an INFO error.
      INFO(TCPX_NET, "Open of %s failed : %s\n", vendorPath, strerror(errno));
      goto end;
    }
    char vendor[7];
    strncpy(vendor, "0x0000", 7);
    int len;
    SYSCHECKVAL(read(fd, vendor, 6), "read", len);
    SYSCHECK(close(fd), "close");
    if (strcmp(vendor, "0x1d0f") == 0) {  // AWS
      autoNt = 2;
      autoNs = 8;
    } else if (strcmp(vendor, "0x1ae0") == 0) {  // GCP
      autoNt = 6;
      autoNs = 1;
    }
  end:
    if (nThreads == -2) nThreads = autoNt;
    if (nSocksPerThread == -2) nSocksPerThread = autoNs;
  }
  int nSocks = nSocksPerThread * nThreads;
  if (nSocks > MAX_SOCKETS) {
    nSocksPerThread = MAX_SOCKETS / nThreads;
    WARN(
        "NET/" PRODUCT_NAME " : the total number of sockets is greater than the "
        "maximum allowed, setting TCPX_NSOCKS_PERTHREAD to %d",
        nSocksPerThread);
    nSocks = nSocksPerThread * nThreads;
  }
  *ns = nSocks;
  *nt = nThreads;
  INFO(TCPX_INIT, "NET/" PRODUCT_NAME ": Using %d threads and %d sockets per thread",
       nThreads, nSocksPerThread);
  return tcpxSuccess;
}

void initCtrlFd(struct tcpxComm* comm, int fd) {
  comm->ctrl_fd = fd;
#ifdef BUFFERED_CTRL
  comm->ctrl_send.setFd(fd);
  comm->ctrl_recv.setFd(fd);
#endif
}

tcpxResult_t GetSocketAddr(int dev, union socketAddress* addr) {
  if (dev >= kTcpxNetIfs) return tcpxInternalError;
  memcpy(addr, &kTcpxSocketDevs[dev].addr, sizeof(*addr));
  return tcpxSuccess;
}

int GetPortNum(int fd) {
  struct sockaddr_in sin;
  socklen_t len = sizeof(sin);
  if (getsockname(fd, (struct sockaddr*)&sin, &len) == -1) {
    perror("getsockname");
    return -1;
  }
  return ntohs(sin.sin_port);
}

struct tcpxGPUDirectTCPXAsyncConnectArgs {
  int dev;
  void* gpu;
  struct tcpxHandle* handle;
  struct tcpxComm* comm;
  struct redirectControlCtx *redirect_control_ctx;

  uint32_t stride;

  tcpxResult_t ret;
};

void printtcpxGPUDirectTCPXAsyncConnectArgs(char *tag,
    struct tcpxGPUDirectTCPXAsyncConnectArgs* args) {
  char buf[2048];
  char buf1[128];
  INFO(TCPX_NET, "%s args %p, dev %d, %s, comm %p, handle %p: %s", tag,
       args, args->dev, gpu_tostring(args->gpu, buf1, 128), args->handle, args->comm,
       tcpxHandleToString(args->handle, buf, 2048));
}

struct tcpxAsyncAcceptArgs {
  int dev;
  void* gpu;
  struct tcpxListenComm* lComm;
  struct tcpxComm* rComm;

  uint32_t stride;

  tcpxResult_t ret;
};

#define PRINT_PORTS(fd, tag) \
  char tttt[32] = tag;       \
  printPorts(fd, tttt);

void printPorts(int fd, char* tag) {
  struct sockaddr_in peer_addr;
  socklen_t peer_len = sizeof(peer_addr);
  if (getpeername(fd, (struct sockaddr*)&peer_addr, &peer_len) != 0) {
    WARN("getpeername %s", strerror(errno));
  }
  struct sockaddr_in sock_addr;
  socklen_t sock_len = sizeof(sock_addr);
  if (getsockname(fd, (struct sockaddr*)&sock_addr, &sock_len) != 0) {
    WARN("getsockname %s", strerror(errno));
  }
  INFO(TCPX_NET, "%s host local: %d, remote %d", tag, ntohs(sock_addr.sin_port),
       ntohs(peer_addr.sin_port));
}

struct sockCondCtx {
  int dev;

  void* gpu;
  bool node0;
  bool even;
  uint32_t stride;

  uint32_t cnt;

  int fd;

  bool ctrl;
};

typedef ConnectionState (*sockCondFn)(struct sockCondCtx*);

inline int getSoIncomingNapiId(int fd) {
  int napi_id = -1;
  socklen_t opt_len = sizeof napi_id;

  if (getsockopt(fd, SOL_SOCKET, SO_INCOMING_NAPI_ID, &napi_id, &opt_len) < 0) {
    WARN("Cannot get incoming NAPI_ID.");
    return -1;
  }

  return napi_id;
}

inline int getSoIncomingCpu(int fd) {
  int cpu = -1;
  socklen_t opt_len = sizeof cpu;

  if (getsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, &cpu, &opt_len) < 0) {
    WARN("Cannot get incoming CPU.");
    return -1;
  }

  return cpu;
}

ConnectionState sockCondCtrl(struct sockCondCtx* ctx) {
  int cpu = getSoIncomingCpu(ctx->fd);
  // int napi_id = getSoIncomingNapiId(ctx->fd);

  INFO(TCPX_NET, "fd %d ctrl cpu %d", ctx->fd, cpu);

  bool ok = false;
  char *env_str;
  if (!(env_str = TCPX_GET_ENV("CTRL_SOCKCOND")) || env_str[0] == '0') {
    ok = true;
  } else {
    int o;
    TCPXCHECKRET(gpu_ordinal(ctx->gpu, &o), tcpxSuccess, CONN_FAILED);
    ctx->even = o % 2 == 0;
    TCPXCHECKRET(gpu_node(ctx->gpu, &o), tcpxSuccess, CONN_FAILED);
    ctx->node0 = o == 0;

    // clang-format off
    ok = ok || ( ctx->node0 && ((  0 <= cpu && cpu <  56)));
    ok = ok || (!ctx->node0 && (( 56 <= cpu && cpu < 112)));
    // clang-format on
  }

  return CONN_OK;
}

ConnectionState sockCondDummy(struct sockCondCtx* ctx) {
  return CONN_OK;
}

ConnectionState UpdateFlowSteerRule(int fd, FlowSteerRuleOp op, void* gpu);
ConnectionState sockCondProgramFlowSteering(struct sockCondCtx* ctx) {
  return UpdateFlowSteerRule(ctx->fd, CREATE, ctx->gpu);
}

tcpxResult_t ConnectSocketWithRetryInternal(int* fd, int max_retry,
                                union socketAddress* connect_addr,
                                union socketAddress* local_addr, 
                                int ctrl_fd, sockCondFn sc, struct sockCondCtx *ctx) {
  int tmpFd = 0;

  int o;
  TCPXCHECK(gpu_ordinal(ctx->gpu, &o)); ctx->even = o % 2 == 0;
  TCPXCHECK(gpu_node(ctx->gpu, &o)); ctx->node0 = o == 0;

  int retry = 0;
  while (retry < max_retry) {
    TCPXCHECK(connectAddress(&tmpFd, connect_addr, local_addr));

    ctx->fd = tmpFd;

    ConnectionState conn_state = (*sc)(ctx);
    ConnectionState r_conn_state = CONN_PENDING;

    int exchange_fd = ctrl_fd > 0 ? ctrl_fd : tmpFd;

    int offset = 0;
    TCPXCHECK(socketWait(TCPX_SOCKET_RECV, exchange_fd, nullptr,
                         &r_conn_state, sizeof(int), &offset));
    offset = 0;
    TCPXCHECK(socketWait(TCPX_SOCKET_SEND, exchange_fd, nullptr,
                         &conn_state, sizeof(int), &offset));

    if (conn_state == CONN_OK && r_conn_state == CONN_OK) {
      break;
    }

    close(tmpFd);
    tmpFd = 0;
    ++retry;

    if (conn_state == CONN_FAILED || r_conn_state == CONN_FAILED) {
      break;
    }

    usleep(10000);
  }
  if (!tmpFd) {
    WARN("NET/" PRODUCT_NAME " failed to connect socket");
    return tcpxInternalError;
  } else {
    // INFO(TCPX_INIT, "NET/" PRODUCT_NAME ": socket connected after %d retries",
    //      retry);
  }
  *fd = tmpFd;

  return tcpxSuccess;
}

tcpxResult_t ConnectSocketWithRetry(int *fd, int max_retry,
                                    union socketAddress *connect_addr,
                                    union socketAddress *local_addr,
                                    int ctrl_fd, sockCondFn sc,
                                    struct sockCondCtx *ctx) {
  return ConnectSocketWithRetryInternal(fd, max_retry, connect_addr, local_addr,
                                        ctrl_fd, sc, ctx);
}

tcpxResult_t AcceptSocketWithRetryInternal(int *fd, int max_retry,
                                           int listen_fd, int ctrl_fd,
                                           sockCondFn sc,
                                           struct sockCondCtx *ctx) {
  int tmpFd = 0;
  struct sockaddr_in sockaddr;
  socklen_t socklen;

  int o;
  TCPXCHECK(gpu_ordinal(ctx->gpu, &o)); ctx->even = o % 2 == 0;
  TCPXCHECK(gpu_node(ctx->gpu, &o)); ctx->node0 = o == 0;

  int retry = 0;
  while (retry < max_retry) {
    socklen = sizeof(struct sockaddr_in);
    SYSCHECKVAL(accept(listen_fd, (struct sockaddr*)&sockaddr, &socklen),
                "accept", tmpFd);

    ctx->fd = tmpFd;

    // bool ok = true;
    // bool r_ok = true;
    ConnectionState conn_state = (*sc)(ctx);
    ConnectionState r_conn_state = CONN_PENDING;

    int exchange_fd = ctrl_fd > 0 ? ctrl_fd : tmpFd;

    int offset = 0;
    TCPXCHECK(socketWait(TCPX_SOCKET_SEND, exchange_fd, nullptr,
                         &conn_state, sizeof(int), &offset));
    offset = 0;
    TCPXCHECK(socketWait(TCPX_SOCKET_RECV, exchange_fd, nullptr,
                         &r_conn_state, sizeof(int), &offset));

    if (conn_state == CONN_OK && r_conn_state == CONN_OK) {
      break;
    }

    if (!ctx->ctrl && conn_state == CONN_OK && r_conn_state != CONN_OK) {
      struct tcpxNapiIdRecord *rxq_record = &global.rxq_record[ctx->dev];
      pthread_mutex_lock(&rxq_record->mu);
      int cpu = getSoIncomingCpu(tmpFd);
      int napi_id = getSoIncomingNapiId(tmpFd);
      if (rxq_record->napi_id_cnt_counter == 0) {
        rxq_record->napi_id_cnt_counter = rxq_record->n_rxqs - 1;  // there could be a case where we have some temporary imbalance here, but we will allocate the next new connection (at least this one) to the most balanced slot.
        rxq_record->napi_id_cnt_curr_hi--;
      }
      rxq_record->napi_id_cnt[napi_id]--;
      INFO(TCPX_NET, "rollback cpu[%d] napi_id_cnt[%d] %lu", cpu, napi_id, rxq_record->napi_id_cnt[napi_id]);
      pthread_mutex_unlock(&rxq_record->mu);
    }

    close(tmpFd);
    tmpFd = 0;
    ++retry;

    if (conn_state == CONN_FAILED || r_conn_state == CONN_FAILED) {
      break;
    }
  }
  if (!tmpFd) {
    WARN("NET/" PRODUCT_NAME " failed accept socket");
    return tcpxInternalError;
  } else {
    // INFO(TCPX_INIT, "NET/" PRODUCT_NAME ": socket accepted after %d retries",
    //      retry);
  }
  *fd = tmpFd;

  return tcpxSuccess;
}

tcpxResult_t AcceptSocketWithRetry(int *fd, int max_retry, int listen_fd, int ctrl_fd,
                                   sockCondFn sc, struct sockCondCtx *ctx) {
  return AcceptSocketWithRetryInternal(fd, max_retry, listen_fd, ctrl_fd, sc, ctx);
}

/***** connection V3 (no flow steering) *****/

tcpxResult_t tcpxListenV3(void* octx, int dev, void* opaqueHandle,
                                 void** listenComm) {
  struct connectionSetupCtx *ctx = (struct connectionSetupCtx *)octx;
  if (ctx == nullptr) return tcpxInternalError;
  if (dev < 0) {  // data transfer socket is based on specified dev
    return tcpxInternalError;
  }
  struct tcpxHandle* handle =
      static_cast<struct tcpxHandle*>(opaqueHandle);
  static_assert(sizeof(struct tcpxHandle) < TCPX_NET_HANDLE_MAXSIZE,
                "tcpxHandle size too large");
  struct tcpxListenComm* lComm;
  TCPXCHECK(tcpxNewListenComm(&lComm, dev));
  TCPXCHECK(tcpxGetNsockNthread(dev, &lComm->num_socks,
                                         &lComm->num_threads));

  TCPXCHECK(GetSocketAddr(dev, &handle->connect_addr));
  handle->port_start = -1;  // unused
  handle->port_count = -1;  // unused
  handle->num_socks = lComm->num_socks;
  handle->num_threads = lComm->num_threads;
  handle->connect_args = nullptr;

  char buf[128];
  if (createListenSocket(lComm->cuda_fd, &handle->connect_addr, 0) !=
      tcpxSuccess) {
    WARN("%s, net dev %d, listen FAILED (no flow steering)", gpu_tostring(lComm->gpu, buf, 128),
         dev);
    return tcpxInternalError;
  }
  INFO(TCPX_INIT, "NET/" PRODUCT_NAME ": %s listen port %d, fd %d", gpu_tostring(lComm->gpu, buf, 128),
       GetPortNum(lComm->cuda_fd[0]), lComm->cuda_fd[0]);

  // create control listen socket
  union socketAddress* ctrl_addr;
  handle->redirect_ctrl = redirect_control(ctx->redirect_control_ctx, &ctrl_addr);
  if (!handle->redirect_ctrl) {
    memcpy(&(handle->ctrl_addr), &(handle->connect_addr), sizeof(union socketAddress));
  } else {
    memcpy(&(handle->ctrl_addr), ctrl_addr, sizeof(union socketAddress));
  }
  TCPXCHECK(createListenSocket(&lComm->host_fd, &handle->ctrl_addr, 0));

  *listenComm = lComm;
  return tcpxSuccess;
}

/***** connection V5 (flow steering rule programming) *****/

ConnectionState UpdateFlowSteerRule(int fd, FlowSteerRuleOp op, void* gpu) {
  union socketAddress peer_addr, sock_addr;
  socklen_t peer_len = sizeof(peer_addr.sin);
  if (getpeername(fd, (struct sockaddr *)&peer_addr.sin, &peer_len) != 0) {
    WARN("getpeername %s", strerror(errno));
  }
  socklen_t sock_len = sizeof(sock_addr.sin);
  if (getsockname(fd, (struct sockaddr *)&sock_addr.sin, &sock_len) != 0) {
    WARN("getsockname %s", strerror(errno));
  }
  char buf1[128], buf2[128];
  INFO(TCPX_NET, "update flow steering rule: local %s <- remote %s",
       socketToString(&sock_addr, buf1), socketToString(&peer_addr, buf2));
  char gpu_pci_addr_str[16];
  TCPXCHECKRET(gpu_pci_addr(gpu, gpu_pci_addr_str, 16), tcpxSuccess, CONN_FAILED);
  auto status = UpdateFlowSteerRule(peer_addr, sock_addr, op, gpu_pci_addr_str);
  if (!status.ok()) {
    WARN("update flow steering rule: local %s <- remote %s, failed against receive-datapath-manager: %s", buf1,
         buf2, std::string(status.message()).c_str());
    switch (status.code()) {
      case absl::StatusCode::kResourceExhausted:
        return CONN_FAILED;
        break;
      default:
        return CONN_PENDING;
    }
  }
  return CONN_OK;
}

tcpxResult_t DeleteFlowSteerRule(int fd, void* gpu) {
  return UpdateFlowSteerRule(fd, DELETE, gpu) == CONN_OK ? tcpxSuccess : tcpxInternalError;
}

#define FLOW_TYPE(is_ctrl) (is_ctrl ? "host" : "cuda")

tcpxResult_t tcpxAsyncConnectV5(
    struct tcpxGPUDirectTCPXAsyncConnectArgs* args) {
  int dev = args->dev;
  struct tcpxHandle* handle = args->handle;
  struct tcpxComm* comm = args->comm;

  union socketAddress local_addr;
  TCPXCHECK(GetSocketAddr(dev, &local_addr));

  struct sockCondCtx sc_ctx = {
    .dev = args->dev,
    .gpu = args->gpu,
    .node0 = false,  // set inside of retry
    .even = false,  // set inside of retry
    .stride = args->stride,
    .cnt = 0,
    .fd = -1,  // set inside of retry
    .ctrl = true,
  };

  int ctrl_fd = -1;
  // for (int i = 0; i < comm->num_socks + 1; i++) {
  for (int i = comm->num_socks; i >= 0; i--) {
    usleep(100 * 1000);
    int tmpFd, offset = 0;
    const bool is_ctrl = i == comm->num_socks;
    INFO(TCPX_INIT, "NET/" PRODUCT_NAME ": connecting (%d) through %s", i, FLOW_TYPE(is_ctrl));
    if (is_ctrl) {
      union socketAddress *ctrl_addr;
      if (redirect_control(args->redirect_control_ctx, &ctrl_addr)) {
        TCPXCHECK(ConnectSocketWithRetry(&tmpFd, kConnectionRetry,
                                         &handle->ctrl_addr, ctrl_addr,
                                         // &sockCondDummy, node0));
                                         ctrl_fd, &sockCondCtrl, &sc_ctx));
      } else {
        TCPXCHECK(ConnectSocketWithRetry(&tmpFd, kConnectionRetry,
                                         &handle->ctrl_addr, &local_addr,
                                         // &sockCondDummy, node0));
                                         ctrl_fd, &sockCondCtrl, &sc_ctx));
      }

    } else {
      // no flow steering
      TCPXCHECK(ConnectSocketWithRetryInternal(&tmpFd, kConnectionRetry,
                                       &handle->connect_addr, &local_addr,
                                       // &sockCondDummy, node0));
                                       ctrl_fd, &sockCondDummy, &sc_ctx));
      PRINT_PORTS(tmpFd, "ConnectV5");
    }

    if (!is_ctrl) {
      setSockZcopy(tmpFd);
    }

    char flow_str[FLOW_STR_LEN];
    uint64_t flow_id = initFdFlowInfo(comm, /*passive=*/false, tmpFd, i, ctrl_fd, flow_str);
    TCPXCHECK(socketWait(TCPX_SOCKET_SEND, ctrl_fd, nullptr, &i, sizeof(int), &offset));
    INFO(TCPX_INIT, "NET/" PRODUCT_NAME ": connected  (%d) [%lu:%s] through %s (no flow steering), fd %d cpu %d napi_id %d",
         i, flow_id, flow_str, FLOW_TYPE(is_ctrl), tmpFd, getSoIncomingCpu(tmpFd), getSoIncomingNapiId(tmpFd));
  }
  initCtrlFd(comm, ctrl_fd);

  INFO(TCPX_INIT, "NET/" PRODUCT_NAME ": Connected %d socks", comm->num_socks);
  comm->passive = false;
  comm->conn_state = CONN_OK;

  return tcpxSuccess;
}

void* asyncConnectV5(void* opaque) {
  struct tcpxGPUDirectTCPXAsyncConnectArgs* args =
      static_cast<struct tcpxGPUDirectTCPXAsyncConnectArgs*>(opaque);
  args->ret = tcpxAsyncConnectV5(args);
  return nullptr;
}

tcpxResult_t tcpxConnectV5(void* octx, int dev, void* opaqueHandle, void** sendComm) {
  struct connectionSetupCtx *ctx = (struct connectionSetupCtx *)octx;
  if (ctx == nullptr) return tcpxInternalError;
  if (dev < 0) {  // data transfer socket is based on specified dev
    return tcpxInternalError;
  }

  struct tcpxHandle* handle =
      static_cast<struct tcpxHandle*>(opaqueHandle);
  struct tcpxGPUDirectTCPXAsyncConnectArgs* args =
      static_cast<struct tcpxGPUDirectTCPXAsyncConnectArgs *>(handle->connect_args);
  *sendComm = nullptr;

  if (args == nullptr) {
    struct tcpxComm* comm;
    TCPXCHECK(tcpxCommNew(&comm, dev));
    comm->num_socks = handle->num_socks;
    comm->num_threads = handle->num_threads;
    comm->connect_addr = handle->connect_addr;
    comm->passive = false;
    comm->conn_state = CONN_PENDING;

    struct tcpxHandle* handle_cpy;
    TCPXASSERT(tcpxCalloc(&handle_cpy, 1));
    memcpy(handle_cpy, handle, sizeof(struct tcpxHandle));

    TCPXASSERT(tcpxCalloc(&args, 1));
    args->dev = dev;
    TCPXCHECK(gpu_current_dev(global.gpus, &args->gpu));
    args->handle = handle_cpy;
    args->comm = comm;
    args->redirect_control_ctx = ctx->redirect_control_ctx;

    pthread_mutex_lock(&ctx->tx_stride_mu);
    args->stride = comm->stride = ctx->tx_stride++;
    pthread_mutex_unlock(&ctx->tx_stride_mu);

    args->ret = tcpxInProgress;
    handle->connect_args = reinterpret_cast<void*>(args);

    pthread_t connect_thread;
    pthread_create(&connect_thread, nullptr, asyncConnectV5,
                   reinterpret_cast<void*>(args));
    pthread_detach(connect_thread);
  } else {
    if (args->ret != tcpxInProgress) {
      if (args->ret == tcpxSuccess) {
        *sendComm = args->comm;
        INFO(TCPX_NET, "sendComm %p", *sendComm);
      }

      free(args->handle);
      free(args);
      return args->ret;
    }
  }
  return tcpxSuccess;
}

TCPX_PARAM(ProgramFlowSteeringWaitMicros, "GPUDIRECTTCPX_PROGRAM_FLOW_STEERING_WAIT_MICROS", -2);
tcpxResult_t tcpxAsyncAcceptV5_v5(struct tcpxAsyncAcceptArgs* args) {
  // struct connectionSetupCtx *ctx = (struct connectionSetupCtx *)octx;
  // if (ctx == nullptr) return tcpxInternalError;
  struct tcpxListenComm* lComm = args->lComm;
      // static_cast<struct tcpxListenComm*>(listenComm);
  struct tcpxComm* rComm = args->rComm;

  rComm->num_socks = lComm->num_socks;
  rComm->num_threads = lComm->num_threads;

  INFO(TCPX_NET, "tcpxAccept %p", rComm);

  struct sockCondCtx sc_ctx = {
    .dev = args->dev,
    .gpu = args->gpu,
    .node0 = false, // set inside of retry
    .even = false,  // set inside of retry
    .stride = args->stride,
    .cnt = 0,
    .fd = -1, // set inside of retry
    .ctrl = true,
  };

  int ctrl_fd = -1;
  // for (int i = 0; i < rComm->num_socks + 1; i++) {
  for (int i = rComm->num_socks; i >= 0; i--) {
    usleep(100 * 1000);
    int tmpFd, sendSockIdx, offset = 0;
    const bool is_ctrl = i == rComm->num_socks;
    INFO(TCPX_INIT, "NET/" PRODUCT_NAME ": accepting (%d) through %s", i, FLOW_TYPE(is_ctrl));
    if (is_ctrl) {
      TCPXCHECK(AcceptSocketWithRetry(
          &tmpFd, kConnectionRetry, lComm->host_fd, 
          ctrl_fd, &sockCondCtrl, &sc_ctx));

    } else {
      int fd = lComm->cuda_fd[0];
      TCPXCHECK(AcceptSocketWithRetryInternal(&tmpFd, kConnectionRetry, fd,
                                      ctrl_fd, 
                                      &sockCondProgramFlowSteering, // &sockCondDummy, 
                                      &sc_ctx));
      sc_ctx.cnt++;
    }
    int fd1 = ctrl_fd == -1 ? tmpFd : ctrl_fd;
    TCPXCHECK(socketWait(TCPX_SOCKET_RECV, fd1, nullptr,
                         &sendSockIdx, sizeof(int), &offset));
    if (ctrl_fd == -1 && sendSockIdx != rComm->num_socks) {
      WARN("assume first conn to be ctrl fd failed");
      return tcpxInternalError;
    }

    if (sendSockIdx == rComm->num_socks) {
      ctrl_fd = tmpFd;
      fdToString(tmpFd, /*passive=*/true, rComm->ctrl_flow_str, FLOW_STR_LEN);
      const int one = 1;
      SYSCHECK(setsockopt(ctrl_fd, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(int)),
               "setsockopt");
    } else {
      setSockZcopy(tmpFd);
    }

    char flow_str[FLOW_STR_LEN];
    uint64_t flow_id = initFdFlowInfo(rComm, /*passive=*/true, tmpFd, sendSockIdx, ctrl_fd, flow_str);
    INFO(TCPX_INIT, "NET/" PRODUCT_NAME ": accepted  (%d) [%lu:%s] through %s, fd %d cpu %d napi_id %d",
         i, flow_id, flow_str, FLOW_TYPE(is_ctrl), tmpFd, getSoIncomingCpu(tmpFd), getSoIncomingNapiId(tmpFd));
  }
  initCtrlFd(rComm, ctrl_fd);

  INFO(TCPX_INIT, "NET/" PRODUCT_NAME ": Accepted %d socks", rComm->num_socks);

  unsigned programFlowSteeringWaitMicros = 5 * 1000 * 1000;
  int v = TCPX_GET_PARAM(ProgramFlowSteeringWaitMicros);
  if (v > 0) {
    programFlowSteeringWaitMicros = v;
  }
  usleep(programFlowSteeringWaitMicros);

  rComm->passive = true;
  rComm->conn_state = CONN_OK;

  return tcpxSuccess;
}

void* asyncAcceptV5_v5(void* opaque) {
  struct tcpxAsyncAcceptArgs* args = static_cast<struct tcpxAsyncAcceptArgs*>(opaque);
  args->ret = tcpxAsyncAcceptV5_v5(args);
  return nullptr;
}

tcpxResult_t tcpxAcceptV5_v5(void* octx, void* listenComm, void** recvComm) {
  struct connectionSetupCtx *ctx = (struct connectionSetupCtx *)octx;
  if (ctx == nullptr) return tcpxInternalError;

  struct tcpxListenComm* lComm =
      static_cast<struct tcpxListenComm*>(listenComm);
  struct tcpxAsyncAcceptArgs* args =
      static_cast<struct tcpxAsyncAcceptArgs*>(lComm->accept_args);
  *recvComm = nullptr;

  if (args == nullptr) {
    struct tcpxComm* rComm;
    TCPXCHECK(tcpxCommNew(&rComm, lComm->dev));
    rComm->num_socks = lComm->num_socks;
    rComm->num_threads = lComm->num_threads;
    rComm->conn_state = CONN_PENDING;

    TCPXASSERT(tcpxCalloc(&args, 1));
    args->dev = lComm->dev;
    args->gpu = lComm->gpu;
    args->lComm = lComm;
    args->rComm = rComm;

    pthread_mutex_lock(&ctx->rx_stride_mu);
    args->stride = rComm->stride = ctx->rx_stride++;
    pthread_mutex_unlock(&ctx->rx_stride_mu);

    args->ret = tcpxInProgress;
    lComm->accept_args = args;

    pthread_t accept_thread;
    pthread_create(&accept_thread, nullptr, asyncAcceptV5_v5,
                   reinterpret_cast<void*>(args));

    pthread_detach(accept_thread);
  } else {
    if (args->ret != tcpxInProgress) {
      if (args->ret == tcpxSuccess) {
        *recvComm = args->rComm;
        INFO(TCPX_NET, "recvComm %p", *recvComm);
      }

      free(args);
      return args->ret;
    }
  }

  return tcpxSuccess;
}

/***** external API *****/

TCPX_PARAM(FlowSteeringStrategy, "GPUDIRECTTCPX_FLOW_STEERING_STRATEGY", -2);

int kFlowSteeringStrategy = UNIX_CLIENT;

tcpxResult_t tcpxInitConnectionSetup(void** osetup) {
  int v = TCPX_GET_PARAM(FlowSteeringStrategy);
  if (v >= 0) {
    kFlowSteeringStrategy = v;
  }

  struct tcpxConnectionSetup* setup;
  TCPXCHECK(tcpxCalloc(&setup, 1));
  *osetup = setup;

  struct connectionSetupCtx *ctx;
  TCPXCHECK(tcpxCalloc(&ctx, 1));
  setup->ctx = ctx;

  pthread_mutex_init(&ctx->tx_stride_mu, NULL);
  ctx->tx_stride = 0;
  pthread_mutex_init(&ctx->rx_stride_mu, NULL);
  ctx->rx_stride = 0;

  const char* ctrl_dev_str = TCPX_GET_ENV("CTRL_DEV");
  if (ctrl_dev_str == nullptr || strlen(ctrl_dev_str) == 0) {
    INFO(TCPX_INIT, "NET/" PRODUCT_NAME " : Using default ctrl sockets");
    ctx->redirect_control_ctx = nullptr;
  } else {
    char name[MAX_IF_NAME_SIZE];
    union socketAddress addr;

    int found = findInterfaces(ctrl_dev_str, name, &addr, envSocketFamily(),
                               MAX_IF_NAME_SIZE, 1);
    if (found < 0) {
      WARN("NET/" PRODUCT_NAME " : no ctrl interface found");
    } else {
      char line[2048];
      char addrline[2048];
      line[0] = '\0';
      INFO(TCPX_INIT, "NET/" PRODUCT_NAME " : Using ctrl socket on %s, %s",
           ctrl_dev_str, socketToString(&addr.sa, addrline));

      TCPXCHECK(redirect_control_new(&(ctx->redirect_control_ctx), addr));

      strncpy(kTcpxCtrlDev.dev_name, name, MAX_IF_NAME_SIZE);
      memcpy(&kTcpxCtrlDev.addr, &addr, sizeof(union socketAddress));
      TCPXCHECK(tcpxGetPciPath(kTcpxCtrlDev.dev_name,
                                        &kTcpxCtrlDev.pci_path));
      snprintf(line + strlen(line), 2047 - strlen(line), " [ctrl]%s:%s", name,
               socketToString(&addr.sa, addrline));
      line[2047] = '\0';
      INFO(TCPX_INIT | TCPX_NET, "NET/" PRODUCT_NAME " : Using ctrl%s", line);
    }
  }

  if (kTcpxNetIfs == -1) {
    pthread_mutex_lock(&kTcpxGPUDirectTCPXLock);
    if (kTcpxNetIfs == -1) {
      char names[MAX_IF_NAME_SIZE * MAX_IFS];
      union socketAddress addrs[MAX_IFS];
      kTcpxNetIfs = findInterfaces(names, addrs, MAX_IF_NAME_SIZE, MAX_IFS);
      if (kTcpxNetIfs <= 0) {
        WARN("NET/" PRODUCT_NAME " : no interface found");
        pthread_mutex_unlock(&kTcpxGPUDirectTCPXLock);
        return tcpxInternalError;
      } else {
        char line[2048];
        char addrline[2048];
        line[0] = '\0';
        for (int i = 0; i < kTcpxNetIfs; i++) {
          strncpy(kTcpxSocketDevs[i].dev_name, names + i * MAX_IF_NAME_SIZE,
                  MAX_IF_NAME_SIZE);
          memcpy(&kTcpxSocketDevs[i].addr, addrs + i,
                 sizeof(union socketAddress));
          TCPXCHECK(tcpxGetPciPath(kTcpxSocketDevs[i].dev_name,
                                            &kTcpxSocketDevs[i].pci_path));
          INFO(TCPX_INIT, "set up %d, %s, pci_path %s", i,
               kTcpxSocketDevs[i].dev_name, kTcpxSocketDevs[i].pci_path);
          snprintf(line + strlen(line), 2047 - strlen(line), " [%d]%s:%s", i,
                   names + i * MAX_IF_NAME_SIZE,
                   socketToString(&addrs[i].sa, addrline));
        }
        line[2047] = '\0';
        INFO(TCPX_INIT | TCPX_NET, "NET/" PRODUCT_NAME " : Using%s", line);
      }
    }
    pthread_mutex_unlock(&kTcpxGPUDirectTCPXLock);
  }

  switch (kFlowSteeringStrategy) {
  case OFF:
    WARN("Flow Steering Strategy off, unsupported");
    return tcpxInternalError;
  case FIXED_PORTS:
    WARN("Unsupported Flow Steering Strategy: fixed ports");
    return tcpxInternalError;
  case SIMULATE:
    WARN("Unsupported Flow Steering Strategy: simulate rx 8 gpus");
    return tcpxInternalError;
  case UNIX_CLIENT:
    INFO(TCPX_NET, "Flow Steering Strategy: unix client");
    setup->listen = tcpxListenV3;
    setup->connect = tcpxConnectV5;
    // setup->accept = tcpxAcceptV5;
    setup->accept = tcpxAcceptV5_v5;
    break;
  default:
    WARN("invalid value for TCPX_GPUDIRECTTCPX_FLOW_STEERING_STRATEGY, %d",
         TCPX_GET_PARAM(FlowSteeringStrategy));
    return tcpxInternalError;
  }

  return tcpxSuccess;
}

void setSockZcopy(int fd) {
  int one = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof one) < 0) {
    WARN("Cannot set socket to SO_ZEROCOPY");
  }
}

tcpxResult_t tcpxGetPciPath(char *devName, char **pciPath) {
  char devicePath[PATH_MAX];
  snprintf(devicePath, PATH_MAX, "/sys/class/net/%s/device", devName);
  // May return NULL if the file doesn't exist.
  *pciPath = realpath(devicePath, nullptr);
  return tcpxSuccess;
}

uint64_t initFdFlowInfo(struct tcpxComm* comm, bool passive, int tmpFd,
                        int sockIdx, int& ctrl_fd, char* flow_str) {
  uint64_t flow_id = 0;
  if (sockIdx == comm->num_socks) {
    ctrl_fd = tmpFd;
    fdToString(tmpFd, passive, comm->ctrl_flow_str, FLOW_STR_LEN);
    strncpy(flow_str, comm->ctrl_flow_str, FLOW_STR_LEN);
    flow_id = generateFlowId(comm->ctrl_flow_str);
    comm->ctrl_stats.flow_id = flow_id;
  } else {
    comm->fd_data[sockIdx].fd = tmpFd;
    comm->fd_data[sockIdx].tasks.construct(comm->gpu, sockIdx);
    fdToString(tmpFd, passive, comm->fd_data[sockIdx].flow_str, FLOW_STR_LEN);
    strncpy(flow_str, comm->fd_data[sockIdx].flow_str, FLOW_STR_LEN);
    flow_id = generateFlowId(comm->fd_data[sockIdx].flow_str);
    comm->fd_data[sockIdx].stats.flow_id = flow_id;
  }
  return flow_id;
}
