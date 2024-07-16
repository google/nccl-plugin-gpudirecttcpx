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

#include "socket_utils.h"
#include "ret.h"

template <unsigned BUF_SIZE>
struct tcpxBufferedSendSocket {
  tcpxBufferedSendSocket() : fd(-1), cur(0) {}
  void setFd(int fileFd) { fd = fileFd; }
  tcpxResult_t sync() {
    if (cur == 0) return tcpxSuccess;
    int off = 0;
    TCPXCHECK(socketSpin(TCPX_SOCKET_SEND, fd, buf, cur, &off));
    cur = 0;
    return tcpxSuccess;
  }
  tcpxResult_t send(void* ptr, unsigned s) {
    if (s > BUF_SIZE) return tcpxInternalError;
    if (cur + s > BUF_SIZE) TCPXCHECK(sync());
    memcpy(buf + cur, ptr, s);
    cur += s;
    return tcpxSuccess;
  }

  int fd;
  int cur;
  char buf[BUF_SIZE];
};

template <unsigned BUF_SIZE>
struct tcpxBufferedRecvSocket {
  tcpxBufferedRecvSocket() : fd(-1), cur(0), end(0) {}
  void setFd(int fileFd) { fd = fileFd; }
  bool empty() { return cur == end; }
  tcpxResult_t refill() {
    if (!empty()) return tcpxSuccess;
    cur = end = 0;
    return socketProgress(TCPX_SOCKET_RECV, fd, buf, BUF_SIZE, &end);
  }
  tcpxResult_t recv(void* ptr, int s) {
    while (s) {
      refill();
      int len = std::min(s, end - cur);
      memcpy(ptr, buf + cur, len);
      cur += len;
      ptr = reinterpret_cast<char*>(ptr) + len;
      s -= len;
    }
    return tcpxSuccess;
  }
  int brecv(void* ptr, int s) {
    int sz = std::min(s, end - cur);
    memcpy(ptr, buf + cur, sz);
    cur += sz;
    return sz;
  }

  int fd;
  int cur;
  int end;
  char buf[BUF_SIZE];
};
