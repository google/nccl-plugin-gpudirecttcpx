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

#include "tracepoint.h"

#include "../common.h"
#include "monitoring.h"

void tcpxTpSendRecvSlowness(tcpxTaskTp point, struct tcpxTask* t) {
  if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN &&
      errno != ENOBUFS) {
    return;
  } else {
    uint64_t nanos;
    if (tcpxTimeoutDetectionShouldWarn(t->timeout, &nanos)) {
#ifdef TCPX_TRACEPOINT
      switch (point) {
        case TCPX_TASK_TP_SENDMSG:
          t->r->comm->fd_data[t->fd_idx].stats.tx_slow_cnt++;
          break;
        case TCPX_TASK_TP_RECVMSG:
          t->r->comm->fd_data[t->fd_idx].stats.rx_slow_cnt++;
          break;
        default:
          WARN("Wrong TCPX trace point.");
          break;
      }
#endif
      if (kSlownessReport[SENDRECV]) {
        WARN("%p:%p, nic %d, %s, %s %s timeout error %d, %s: [%zu/%zu]/%zu cnt "
             "%lu, nanos %lu",
             t, t->r->comm, t->r->comm->dev,
             kTcpxSocketDevs[t->r->comm->dev].dev_name, t->pipe->flow_str,
             point == TCPX_TASK_TP_SENDMSG ? "send" : "recv", errno,
             strerror(errno), t->offset, t->size, t->r->size,
             t->timeout->same_count, nanos);
      }
    }
  }
}

void tcpxTpSendmsg(tcpxTaskTp point, struct tcpxTask* t, int bytes) {
  //  possible slowness if bytes < 0.
  if (bytes < 0) {
    if (kSlownessSwitch[SENDRECV]) {
      tcpxTpSendRecvSlowness(point, t);
    }
  }
  if (!kExportStatsToFile || !kEnableTaskLevelStats) return;
  if (bytes > 0) {
#ifdef TCPX_TRACEPOINT
    t->r->comm->fd_data[t->fd_idx].stats.tx_cnt++;
    t->r->comm->statsbuf.enqueue(nullptr, t, t->r->comm->passive, TASK_SENDMSG_TS);
#endif
  }
}

void tcpxTpRecvmsg(tcpxTaskTp point, struct tcpxTask* t, int bytes) {
  //  possible slowness if bytes < 0.
  if (bytes < 0) {
    if (kSlownessSwitch[SENDRECV]) {
      tcpxTpSendRecvSlowness(point, t);
    }
  }
  if (!kExportStatsToFile || !kEnableTaskLevelStats) return;
#ifdef TCPX_TRACEPOINT
  t->r->comm->fd_data[t->fd_idx].stats.rx_cnt++;
#endif
}

void tcpxTpCompletion(tcpxTaskTp point, struct tcpxTask* t, uint64_t count) {
  if (!kExportStatsToFile || !kEnableTaskLevelStats) return;
#ifdef TCPX_TRACEPOINT
  t->r->comm->fd_data[t->fd_idx].stats.tx_completion_cnt += count;
  t->r->comm->statsbuf.enqueue(nullptr, t, t->r->comm->passive, TASK_COMPLETION_TS);
#endif
}

void tcpxTpTaskStateCompleting(struct tcpxTask* t) {
  if (!kExportStatsToFile || !kEnableTaskLevelStats) return;
  t->r->comm->statsbuf.enqueue(nullptr, t, t->r->comm->passive, TASK_COMPLETING_TS);
}

void tcpxTpTaskStateInactive(struct tcpxTask* t) {
  if (!kExportStatsToFile || !kEnableTaskLevelStats) return;
  t->r->comm->statsbuf.enqueue(nullptr, t, t->r->comm->passive, TASK_INACTIVE_TS);
}

void tcpxTpTaskStateActive(struct tcpxTask* t) {
  if (!kExportStatsToFile || !kEnableTaskLevelStats) return;
  t->r->comm->statsbuf.enqueue(nullptr, t, t->r->comm->passive, TASK_ACTIVE_TS);
}

void tcpxTpTaskStateFree(struct tcpxTask* t) {
  if (!kExportStatsToFile || !kEnableTaskLevelStats) return;
  t->r->comm->statsbuf.enqueue(nullptr, t, t->r->comm->passive, TASK_FREE_TS);
}

void tcpxTP_TASK(tcpxTaskTp point, struct tcpxTask* t, int bytes,
                 uint64_t count) {
#ifdef TCPX_TRACEPOINT
  switch (point) {
    case TCPX_TASK_TP_SENDMSG:
      tcpxTpSendmsg(point, t, bytes);
      break;
    case TCPX_TASK_TP_RECVMSG:
      tcpxTpRecvmsg(point, t, bytes);
      break;
    case TCPX_TASK_TP_COMPLETION:
      tcpxTpCompletion(point, t, count);
      break;
    case TCPX_TASK_TP_STATE_COMPLETING:
      tcpxTpTaskStateCompleting(t);
      break;
    case TCPX_TASK_TP_STATE_INACTIVE:
      tcpxTpTaskStateInactive(t);
      break;
    case TCPX_TASK_TP_STATE_ACTIVE:
      tcpxTpTaskStateActive(t);
      break;
    case TCPX_TASK_TP_STATE_FREE:
      tcpxTpTaskStateFree(t);
      break;
    default:
      WARN("Wrong TCPX trace point.");
      break;
  }
#endif
  return;
}

void tcpxTpCompletionSlow(struct tcpxComm* comm, int idx) {
  struct tcpxFdData* fd_data = comm->fd_data + idx;
  if (fd_data->tx_upper == fd_data->tx_upper_cache &&
      fd_data->tx_lower == fd_data->tx_lower_cache) {
    uint64_t nanos;
    if (tcpxTimeoutDetectionShouldWarn(&fd_data->timeout, &nanos)) {
#ifdef TCPX_TRACEPOINT
      fd_data->stats.tx_completion_slow_cnt++;
#endif
      if (kSlownessReport[TX_COMP]) {
        WARN(
            "%p nic %d, %s %s tx comp timeout poll upper %u, lower %u, cnt %u, "
            "nanos %lu, range (%lu %lu)",
            comm, comm->dev, kTcpxSocketDevs[comm->dev].dev_name,
            fd_data->flow_str, fd_data->tx_upper, fd_data->tx_lower,
            fd_data->timeout.same_count, nanos, fd_data->stat_lo,
            fd_data->stat_hi);
      }
    }
  } else {
    fd_data->tx_upper_cache = fd_data->tx_upper;
    fd_data->tx_lower_cache = fd_data->tx_lower;
    tcpxTimeoutDetectionReset(&fd_data->timeout);
  }
}

void tcpxTP_TASK(tcpxTaskTp point, struct tcpxComm* comm, int idx) {
#ifdef TCPX_TRACEPOINT
  switch (point) {
    case TCPX_TASK_TP_COMPLETION:
      if (kSlownessSwitch[TX_COMP]) {
        tcpxTpCompletionSlow(comm, idx);
      }
      break;
    default:
      WARN("Wrong TCPX trace point.");
      break;
  }
#endif
  return;
}

void tcpxTpRequestStateTransmitting(struct tcpxRequest* request) {
  if (!kExportStatsToFile || !kEnableRequestLevelStats) return;
  request->comm->statsbuf.enqueue(request, nullptr, request->comm->passive, REQUEST_TRANSMITTING_TS);
}

void tcpxTpRequestStateInactive(struct tcpxRequest* request) {
  if (!kExportStatsToFile || !kEnableRequestLevelStats) return;
  request->comm->statsbuf.enqueue(request, nullptr, request->comm->passive, REQUEST_INACTIVE_TS);
}

void tcpxTpRequestStatePosted(struct tcpxRequest* request) {
  if (!kExportStatsToFile || !kEnableRequestLevelStats) return;
  request->comm->statsbuf.enqueue(request, nullptr, request->comm->passive, REQUEST_POSTED_TS);
}

void tcpxTpRequestStateActive(struct tcpxRequest* request) {
  if (!kExportStatsToFile || !kEnableRequestLevelStats) return;
  request->comm->statsbuf.enqueue(request, nullptr, request->comm->passive, REQUEST_ACTIVE_TS);
}

void tcpxTpRequestStateFree(struct tcpxRequest* request) {
  if (!kExportStatsToFile || !kEnableRequestLevelStats) return;
  request->comm->statsbuf.enqueue(request, nullptr, request->comm->passive, REQUEST_FREE_TS);
}

void tcpxTP_REQUEST(tcpxRequestTp point, struct tcpxRequest* request) {
#ifdef TCPX_TRACEPOINT
  switch (point) {
    case TCPX_REQUEST_TP_STATE_ACTIVE:
      tcpxTpRequestStateActive(request);
      break;
    case TCPX_REQUEST_TP_STATE_POSTED:
      tcpxTpRequestStatePosted(request);
      break;
    case TCPX_REQUEST_TP_STATE_TRANSMITTING:
      tcpxTpRequestStateTransmitting(request);
      break;
    case TCPX_REQUEST_TP_STATE_INACTIVE:
      tcpxTpRequestStateInactive(request);
      break;
    case TCPX_REQUEST_TP_STATE_FREE:
      tcpxTpRequestStateFree(request);
      break;
    default:
      WARN("Wrong TCPX trace point.");
      break;
  }
#endif
}
