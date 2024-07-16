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

#ifndef NET_TCPX_SOCK_TCPX_H_
#define NET_TCPX_SOCK_TCPX_H_

#include <asm-generic/errno.h>
#include <assert.h>
#include <unistd.h>

#include "../devcomm/inline.h"
#include "../work_queue.h"
#include "../macro.h"

#include "datapipe.h"

#ifndef SO_DEVMEM_DONTNEED
#define SO_DEVMEM_DONTNEED 97
#endif

#ifndef SO_DEVMEM_HEADER
#define SO_DEVMEM_HEADER 98
#define SCM_DEVMEM_HEADER SO_DEVMEM_HEADER
#endif

#ifndef SO_DEVMEM_OFFSET
#define SO_DEVMEM_OFFSET 99
#define SCM_DEVMEM_OFFSET SO_DEVMEM_OFFSET
#endif

////
// helpers
////

static inline ssize_t gpudirectTCPXPostSend(int fd, int gpu_mem_fd, int size,
                                        int offset, int page_off,
                                        int gpu_mem_off, void* buf) {
  struct msghdr msg;
  struct iovec iov;
  int v[2];
  v[0] = gpu_mem_fd;
  char ctrl_data[CMSG_SPACE(2 * sizeof(int))];

  memset(&msg, 0, sizeof(msg));

  msg.msg_control = ctrl_data;
  msg.msg_controllen = sizeof(ctrl_data);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_DEVMEM_OFFSET;
  cmsg->cmsg_len = CMSG_LEN(2 * sizeof(int));

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ssize_t ret = 0;

  if (offset < size) {
    // theoretically tx doesn't send from main memory buf
    iov.iov_base = (char*) buf + offset;
    iov.iov_len = size - offset;

    v[1] = gpu_mem_off + page_off + offset;
    // INFO(TCPX_NET, "v[1] %d = gpu_mem_off %d + page_off %d + offset %d", v[1], gpu_mem_off, page_off, offset);
    memcpy((int*)CMSG_DATA(cmsg), v, 2 * sizeof(int));
    ret = sendmsg(fd, &msg, MSG_ZEROCOPY | MSG_DONTWAIT);
    // if (ret < 0) {
      // WARN("sendmsg() error: %s", strerror(errno));
      // exit(1)
    // }
    if (ret == 0) {
      WARN("sendmsg() ret 0, connection closed?");
    }
  }
  return ret;
}

static int readNotification(struct msghdr* msg, uint32_t* lower,
                            uint32_t* upper) {
  struct sock_extended_err* serr;
  struct cmsghdr* cm;
  cm = CMSG_FIRSTHDR(msg);
  if (cm->cmsg_level != SOL_IPV6 && cm->cmsg_type != IP_RECVERR) {
    WARN("Invalid message level %d or type %d from errorqueue!",
         (int)cm->cmsg_level, (int)cm->cmsg_type);
    return -1;
  }
  serr = reinterpret_cast<struct sock_extended_err*>(CMSG_DATA(cm));
  if (serr->ee_errno != 0 || serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY) {
    WARN("Invalid message errno %d or origin %d from errorqueue!",
         (int)serr->ee_errno, (int)serr->ee_origin);
    return -1;
  }
  *lower = serr->ee_info;
  *upper = serr->ee_data + 1;
  return 0;
}

static int readErrqueue(int fd, uint32_t* lower, uint32_t* upper) {
  char control[100];
  struct msghdr msg = {};
  msg.msg_control = control;
  msg.msg_controllen = sizeof control;
  int ret = recvmsg(fd, &msg, MSG_ERRQUEUE);
  if (ret < 0 && errno == EAGAIN) return 0;
  if (ret < 0) {
    WARN("Read error from errqueue: %d", errno);
    return -errno;
  }
  ret = readNotification(&msg, lower, upper);
  if (ret < 0) return ret;
  return *upper - *lower;
}

#include "linux/types.h"
struct devmemvec {
  __u32 frag_offset;
  __u32 frag_size;
  __u32 frag_token;
};

static inline ssize_t process_recv_cmsg(struct msghdr* msg, void* data,
                              struct tcpxDataPipe* p, int offset, uint64_t dst_base_offset,
                              int* user_buffer_count) {
  struct cmsghdr* cm = nullptr;
  struct devmemvec *dmv = nullptr;
  int num_cm = 0;

  size_t host_buf_offset = 0;
  ssize_t dst_offset = 0;

  for (cm = CMSG_FIRSTHDR(msg); cm; cm = CMSG_NXTHDR(msg, cm)) {
    if (cm->cmsg_level != SOL_SOCKET ||
        (cm->cmsg_type != SCM_DEVMEM_OFFSET &&
         cm->cmsg_type != SCM_DEVMEM_HEADER)
    ) {
      INFO(TCPX_NET, "cmsg: unknown %u.%u", cm->cmsg_level, cm->cmsg_type);
      continue;
    }

    num_cm++;

    dmv = (struct devmemvec *)CMSG_DATA(cm);
    const __u32 len = dmv->frag_size;
    if (cm->cmsg_type == SCM_DEVMEM_HEADER) {
      // process data copied from skb's linear buffer
      if (len > 0) {
        TCPXASSERT(gpu_inline_memcpy(p->gpu_inline, ((char*) data) + offset + dst_offset,
                              p->buf + offset + host_buf_offset,
                              len));

        if (host_buf_offset == 0) WARN("%p copied %zu bytes to user buffer, %s", msg, (size_t) len, p->flow_str);

        host_buf_offset += (size_t) len;
        dst_offset += (size_t)len;
        (*user_buffer_count)++;
      }
      continue;
    }

    /* current version returns two cmsgs:
     * - one with offset from start of region
     * - one with raw physaddr */
    p->scatter_list[p->cnt_cache].src_off = (uint32_t)(uint64_t) dmv->frag_offset; 
    p->scatter_list[p->cnt_cache].len = (uint32_t)(uint64_t) len;
    p->scatter_list[p->cnt_cache].dst_off = (uint64_t) dst_offset + offset + dst_base_offset;
    p->cnt_cache++;

    if (p->cnt_cache >= TCPX_UNPACK_MAX_SLICE_PAGES) {
      // WARN("idx = %d, MAX_PAGES = %d", p->cnt_cache, TCPX_UNPACK_MAX_SLICE_PAGES);
      WARN("received %d/%d segs, failstop, %s", p->cnt_cache, TCPX_UNPACK_MAX_SLICE_PAGES, p->flow_str);
      exit(1);
    }
    dst_offset += (size_t)len;

    pgtok_t pgtok = {dmv->frag_token, 1};
    if (*p->pgtok_cnt > 0) {
      pgtok_t *prev = p->pgtoks + (*p->pgtok_cnt - 1);
      if (prev->token_start + prev->token_count == dmv->frag_token) {
        prev->token_count++;
        continue;  // to the next cmsg
      }
    }
    p->pgtoks[*p->pgtok_cnt] = pgtok;
    (*p->pgtok_cnt)++;
  }

  if (num_cm == 0) {
#ifndef EXIT_ON_CMSG_ERRORS
    WARN("%s no cmsg", p->flow_str);
#else
    WARN("fatal, %s no cmsg", p->flow_str);
    exit(1);
#endif
  }
  if (dst_offset == 0) {
#ifndef EXIT_ON_CMSG_ERRORS
    WARN("%s no data", p->flow_str);
#else
    WARN("fatal, %s no data", p->flow_str);
    exit(1);
#endif
  }
  if (host_buf_offset > 0) {
#ifndef EXIT_ON_CMSG_ERRORS
    WARN("%s data landed on host memory %d times", p->flow_str, *user_buffer_count);
#else
    WARN("fatal, %s data landed on host memory %d times", p->flow_str, *user_buffer_count);
    exit(1);
#endif
  }

  return dst_offset;
}

static inline ssize_t gpudirectTCPXRecv(int fd, void* data, int size,
                      int offset, tcpxDataPipe* p, uint64_t dst_base_offset,
                      int* user_buffer_count) {
  ssize_t ret;

  struct msghdr msg;
  char* ctrl_data = p->ctrl_data;
  struct iovec iov;

  memset(&msg, 0, sizeof(msg));
  msg.msg_control = ctrl_data;
  msg.msg_controllen =
      GPUDIRECTTCPX_CTRL_DATA_LEN;  // 10000 * CMSG_SPACE(sizeof(struct iovec));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  iov.iov_base = p->buf + offset;

  iov.iov_len = size - p->bytes_cnt;
  ret = recvmsg(fd, &msg, MSG_SOCK_DEVMEM | MSG_DONTWAIT);
  if (ret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      //
    } else {
      WARN("Error for "
           "fd %d, %s iov_base %p, iov_len %d, size %d, pipe->byte_recv %d: "
           "%d, %x: %s",
           fd, p->flow_str, iov.iov_base, iov.iov_len, size, p->bytes_cnt, ret, errno,
           strerror(errno));
    }
    return ret;
  }

  if (ret == 0) {
    return 0;
  }

  if (msg.msg_flags & MSG_CTRUNC) {
#ifndef EXIT_ON_CMSG_ERRORS
    WARN("cmsg truncated, current msg_controllen %d, %s", GPUDIRECTTCPX_CTRL_DATA_LEN, p->flow_str);
#else
    WARN("fatal, cmsg truncated, current msg_controllen %d", GPUDIRECTTCPX_CTRL_DATA_LEN);
    exit(1);
#endif
  }
  ssize_t cmsg_total_bytes = process_recv_cmsg(&msg, data, p, offset, dst_base_offset, user_buffer_count);
  if (cmsg_total_bytes != ret) {
#ifndef EXIT_ON_CMSG_ERRORS
    WARN("cmsg total bytes %zd, expected %zd, %s", cmsg_total_bytes, ret, p->flow_str);
#else
    WARN("fatal, cmsg total bytes %zd, expected %zd", cmsg_total_bytes, ret);
    exit(1);
#endif
  }

  msg.msg_controllen = sizeof(ctrl_data);
  msg.msg_flags = 0;

  p->bytes_cnt += (ret > 0) ? ret : 0;
  if (p->bytes_cnt >= size) {
    p->bytes_cnt = 0;

    // make sure linear buffer data has been flushed, later?
    gpu_inline_sync(p->gpu_inline);
  }

  return ret;
}

static inline void do_recycle_devmem_batch(int fd, pgtok_t* pgtoks, size_t pgtok_cnt) {
  int ret;
  ret = setsockopt(fd, SOL_SOCKET, SO_DEVMEM_DONTNEED, pgtoks,
                   sizeof(pgtok_t) * pgtok_cnt);
  if (ret != 0) {
    WARN("do_recycle_devmem_batch %d, %p, %zu, (%d %s)", fd, pgtoks, pgtok_cnt, ret, strerror(errno));
  }
  assert(ret == 0);
}


static inline tcpxResult_t recyclePages(tcpxNetDeviceQueue* q, uint64_t q_idx) {
  q_idx %= DEV_UNPACK_MAX_QUEUE_DEPTH;

  size_t fds_cnt = q->record.fds_cnts[q_idx];
  // size_t syscall_cnt = 0;  // debug
  for (size_t i = 0; i < fds_cnt; i++) {
    size_t pgtok_cnt  = q->record.pgtok_cnts[q_idx][i];
    int fd          = q->record.fds[q_idx][i];
    pgtok_t* pgtoks = q->record.pgtoks[q_idx][i];
    // INFO(TCPX_NET, "do_recycle_devmem_bo%do1 %d %p %zu", i, fd, pgtoks, pgtok_cnt);
    if (pgtok_cnt > 0) {
      // syscall_cnt++;
      do_recycle_devmem_batch(fd, pgtoks, pgtok_cnt);
    }
  }
  return tcpxSuccess;
}

#endif  // NET_TCPX_SOCK_TCPX_H_
